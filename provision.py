#!/usr/bin/env python3
"""
provision.py — РАНТАЙМ-доустановка бинарников (nfqws/xray) в контейнер, если их нет
в образе.

Зачем: при сборке через Coolify/Nixpacks (а не наш Dockerfile) zapret/xray в образ не
попадают — и build-arg тут не помогает. Это запускается на СТАРТЕ приложения (под
Coolify обычно root), качает release с GitHub, СВЕРЯЕТ sha256 (пин надёжнее TLS-CA,
который в Nixpacks-образе может отсутствовать), ставит в /opt (или /data, если нет прав),
best-effort setcap. Идемпотентно: если бинарник уже есть — ничего не делает.

Скачивание гейтится ZAPRET=true (ZAPRET_ENABLE_APPLY) — без явного согласия ничего не
тянем из сети.
"""

import os
import io
import ssl
import sys
import hashlib
import tarfile
import zipfile
import subprocess
import urllib.request

# Пины версий и sha256 (совпадают с Dockerfile). Сверены по реальным release-файлам.
ZAPRET_VERSION = os.environ.get("ZAPRET_VERSION", "v72.12")
XRAY_VERSION = os.environ.get("XRAY_VERSION", "v26.3.27")
_SHA = {
    "v72.12": "5a461c4cddb87bb8a9f1de5e222e3423f8f0d656a7520f529cf1f66d8d585a68",
    "v26.3.27": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
}


def _download(url, timeout=180):
    try:
        return urllib.request.urlopen(url, timeout=timeout, context=ssl.create_default_context()).read()
    except Exception:
        # CA может отсутствовать в Nixpacks-образе → берём без проверки TLS; целостность
        # гарантируем pin'ом sha256 ниже (это надёжнее, чем доверять цепочке сертификатов).
        return urllib.request.urlopen(url, timeout=timeout, context=ssl._create_unverified_context()).read()


def _writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        t = os.path.join(path, ".wtest")
        open(t, "w").close()
        os.remove(t)
        return True
    except Exception:
        return False


def _try_setcap(binpath, log):
    try:
        r = subprocess.run(["setcap", "cap_net_admin,cap_net_raw+ep", binpath],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            log(f"  setcap {os.path.basename(binpath)}: {(r.stderr or '').strip()[:120]} "
                f"(нужен root — без caps реальное применение обхода может не работать)")
    except Exception as e:
        log(f"  setcap не выполнен: {e}")


def _safe_tar_members(tf, strip):
    """Члены tar со срезанным верхним каталогом (strip-components) и защитой от path-traversal."""
    for m in tf.getmembers():
        parts = [p for p in m.name.split("/") if p not in ("", ".")]
        if len(parts) <= strip:
            continue
        rel = parts[strip:]
        if ".." in rel:
            continue
        m.name = "/".join(rel)
        yield m


def ensure_zapret(log=print):
    """Если nfqws нет — скачать zapret-релиз. → путь к nfqws | None."""
    import zapret
    p = zapret.nfqws_path()
    if p or not sys.platform.startswith("linux"):
        return p
    url = f"https://github.com/bol-van/zapret/releases/download/{ZAPRET_VERSION}/zapret-{ZAPRET_VERSION}.tar.gz"
    target = "/opt/zapret" if _writable("/opt") else "/data/zapret"
    try:
        log(f"[provision] nfqws нет в образе — качаю zapret {ZAPRET_VERSION} → {target} …")
        data = _download(url)
        want = _SHA.get(ZAPRET_VERSION)
        if want and hashlib.sha256(data).hexdigest() != want:
            log("[provision] sha256 zapret не совпал — отмена (версия/файл не те)")
            return None
        os.makedirs(target, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(target, members=list(_safe_tar_members(tf, 1)))
        nf = os.path.join(target, "binaries/linux-x86_64/nfqws")
        if not os.path.exists(nf):
            log("[provision] nfqws не найден в архиве")
            return None
        os.chmod(nf, 0o755)
        _try_setcap(nf, log)
        for b in ("/usr/sbin/xtables-nft-multi", "/usr/sbin/xtables-legacy-multi"):
            if os.path.exists(b):
                _try_setcap(b, log)
        os.environ["ZAPRET_NFQWS"] = nf
        os.environ["ZAPRET_FAKE_DIR"] = os.path.join(target, "files/fake")
        zapret.refresh_defaults()      # стратегии должны ссылаться на актуальный fake-каталог
        log(f"[provision] nfqws готов: {nf}")
        return nf
    except Exception as e:
        log(f"[provision] zapret: {e}")
        return None


def ensure_xray(log=print):
    """Если xray нет — скачать release (xray + geoip/geosite). → путь к xray | None."""
    import gateway
    p = gateway.xray_path()
    if p or not sys.platform.startswith("linux"):
        return p
    url = f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/Xray-linux-64.zip"
    target = "/opt/xray" if _writable("/opt") else "/data/xray"
    try:
        log(f"[provision] xray нет в образе — качаю xray {XRAY_VERSION} → {target} …")
        data = _download(url)
        want = _SHA.get(XRAY_VERSION)
        if want and hashlib.sha256(data).hexdigest() != want:
            log("[provision] sha256 xray не совпал — отмена")
            return None
        os.makedirs(target, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist())
            for name in ("xray", "geoip.dat", "geosite.dat"):
                if name in names:
                    with z.open(name) as src, open(os.path.join(target, name), "wb") as dst:
                        dst.write(src.read())
        xb = os.path.join(target, "xray")
        if not os.path.exists(xb):
            log("[provision] xray не найден в архиве")
            return None
        os.chmod(xb, 0o755)
        _try_setcap(xb, log)
        os.environ["XRAY_BIN"] = xb
        os.environ.setdefault("XRAY_LOCATION_ASSET", target)
        log(f"[provision] xray готов: {xb}")
        return xb
    except Exception as e:
        log(f"[provision] xray: {e}")
        return None


def ensure_all(log=print):
    """Доустановить nfqws и xray, если их нет (на старте, при ZAPRET=true)."""
    ensure_zapret(log)
    ensure_xray(log)
