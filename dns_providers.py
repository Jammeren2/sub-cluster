#!/usr/bin/env python3
"""
dns_providers.py — управление DNS-записями (для фейловера доменов).

Абстракция DnsProvider + реализация для reg.ru (REG.API 2.0). При переключении
узел переписывает A-записи поддоменов (admin.<zone> и happ.<zone>) на свой IP.

reg.ru REG.API 2.0:
  base:  https://api.reg.ru/api/regru2/zone/<method>
  auth:  POST-параметры username, password (или отдельный API-пароль)
  формат: input_format=json, output_format=json, input_data=<json>
  методы:
    zone/get_resource_records  {domain_name}
    zone/add_alias             {domain_name, subdomain, ipaddr}   # A-запись
    zone/remove_record         {domain_name, subdomain, record_type}

ВАЖНО: IP сервера должен быть в белом списке API в настройках аккаунта reg.ru,
иначе запросы отклоняются.
"""

import json
import urllib.parse
import urllib.request

REGRU_BASE = "https://api.reg.ru/api/regru2"
HTTP_TIMEOUT = 25


class DnsResult:
    def __init__(self, ok, message="", raw=None):
        self.ok = ok
        self.message = message
        self.raw = raw

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return f"DnsResult(ok={self.ok}, message={self.message!r})"


class DnsProvider:
    name = "base"

    def set_a_record(self, zone, subdomain, ip):
        """Сделать так, чтобы subdomain.zone указывал A-записью на ip."""
        raise NotImplementedError

    def get_records(self, zone):
        """→ список записей зоны (для отображения), либо []."""
        return []


class MockProvider(DnsProvider):
    """Для тестов и режима без настроенного провайдера: только запоминает вызовы."""
    name = "mock"

    def __init__(self, fail=False):
        self.calls = []
        self.state = {}  # (zone,subdomain) -> ip
        self.fail = fail

    def set_a_record(self, zone, subdomain, ip):
        self.calls.append((zone, subdomain, ip))
        if self.fail:
            return DnsResult(False, "mock failure")
        self.state[(zone, subdomain)] = ip
        return DnsResult(True, "ok")

    def get_records(self, zone):
        return [{"subdomain": sd, "type": "A", "ip": ip}
                for (z, sd), ip in self.state.items() if z == zone]


class RegRuProvider(DnsProvider):
    name = "regru"

    def __init__(self, username, password, base=REGRU_BASE, timeout=HTTP_TIMEOUT):
        self.username = username
        self.password = password
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _call(self, method, input_data):
        url = f"{self.base}/{method}"
        form = {
            "username": self.username,
            "password": self.password,
            "io_encoding": "utf8",
            "input_format": "json",
            "output_format": "json",
            "input_data": json.dumps(input_data, ensure_ascii=False),
        }
        body = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"result": "error", "error_text": raw[:300]}

    @staticmethod
    def _domain_ok(parsed):
        """Проверяет результат уровня домена внутри ответа regru2."""
        if not isinstance(parsed, dict):
            return False, "пустой ответ"
        if parsed.get("result") != "success":
            return False, parsed.get("error_text") or parsed.get("error_code") or "ошибка API"
        answer = parsed.get("answer") or {}
        domains = answer.get("domains") or []
        for d in domains:
            if d.get("result") not in (None, "success"):
                return False, d.get("error_text") or d.get("error_code") or "ошибка домена"
        return True, "ok"

    def set_a_record(self, zone, subdomain, ip):
        # 1) убрать старую A-запись поддомена (если её нет — reg.ru вернёт ошибку,
        #    которую мы трактуем как «нечего удалять»).
        try:
            self._call("zone/remove_record", {
                "domain_name": zone, "subdomain": subdomain, "record_type": "A",
            })
        except Exception as e:
            # удаление не критично; продолжаем к добавлению
            print(f"[dns] remove_record {subdomain}.{zone}: {e}", flush=True)
        # 2) добавить новую A-запись.
        try:
            parsed = self._call("zone/add_alias", {
                "domain_name": zone, "subdomain": subdomain, "ipaddr": ip,
            })
        except Exception as e:
            return DnsResult(False, f"сеть/API: {e}")
        ok, msg = self._domain_ok(parsed)
        return DnsResult(ok, msg, parsed)

    def get_records(self, zone):
        try:
            parsed = self._call("zone/get_resource_records", {"domain_name": zone})
        except Exception as e:
            return []
        out = []
        answer = (parsed or {}).get("answer") or {}
        for d in answer.get("domains", []):
            for rr in d.get("rrs", []) or []:
                out.append(rr)
        return out


def provider_from_settings(settings, decrypt_fn):
    """Строит DnsProvider из settings['dns']. → (provider, error_or_None)."""
    dns = (settings or {}).get("dns") or {}
    prov = dns.get("provider", "regru")
    if prov == "mock":
        return MockProvider(), None
    if prov == "regru":
        user = dns.get("regru_username") or ""
        pwd = decrypt_fn(dns.get("regru_password_enc") or "")
        if not user or not pwd:
            return None, "reg.ru: не заданы логин/пароль"
        return RegRuProvider(user, pwd), None
    return None, f"неизвестный DNS-провайдер: {prov}"
