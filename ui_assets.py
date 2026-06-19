# -*- coding: utf-8 -*-
"""ui_assets.py — статика панели. EDITOR_JS/EDITOR_CSS читаются из editor.js/editor.css
(удобно править как обычные файлы); PAGE_CSS — для не-редакторных страниц."""

import os

_DIR = os.path.dirname(os.path.abspath(__file__))


def _read(name):
    try:
        with open(os.path.join(_DIR, name), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


EDITOR_CSS = _read("editor.css")
EDITOR_JS = _read("editor.js")

# Палитра без синего: графитовые кнопки + тёплый бирюзовый акцент (под ноды).
PAGE_CSS = """
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       background:#0f1115; color:#e6e6e6; margin:0; padding:0; }
.wrap { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color:#8a93a2; font-size: 13px; margin-bottom: 24px; }
a { color:#6fd3c3; }
.card { background:#171a21; border:1px solid #232833; border-radius:12px;
        padding:18px; margin-bottom:16px; }
.route-head { display:flex; justify-content:space-between; align-items:center; gap:12px; }
.route-title { font-size:16px; font-weight:600; }
.path { font-family: ui-monospace, Menlo, Consolas, monospace; color:#7ee787; font-size:13px; }
label { display:block; font-size:12px; color:#8a93a2; margin:10px 0 4px; }
input, textarea, select { width:100%; background:#0f1115; border:1px solid #2b313d;
        color:#e6e6e6; border-radius:8px; padding:9px 10px; font-size:14px; font-family:inherit; }
input:focus, textarea:focus, select:focus { outline:none; border-color:#3f9d8f; }
textarea { min-height:84px; resize:vertical; font-family: ui-monospace, Menlo, Consolas, monospace; }
.btn { display:inline-block; border:1px solid #43454e; border-radius:8px; padding:9px 14px; font-size:14px;
       cursor:pointer; background:#33343b; color:#e8e8ea; text-decoration:none; }
.btn:hover { background:#3c3d45; border-color:#52545e; }
.btn.primary { background:#2f8f86; border-color:#2f8f86; color:#fff; }
.btn.primary:hover { background:#36a399; border-color:#36a399; }
.btn.gray { background:#2b313d; border-color:#333a47; }
.btn.red { background:#8f3636; border-color:#8f3636; color:#fff; }
.btn.red:hover { background:#a23f3f; border-color:#a23f3f; }
.btn.ghost { background:transparent; border-color:#45464f; color:#cfd2d8; }
.btn.small { padding:6px 10px; font-size:13px; }
.row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.muted { color:#8a93a2; font-size:12px; }
.tag { font-size:11px; padding:2px 8px; border-radius:999px; background:#22272f; color:#8a93a2; }
.tag.on { background:#16321f; color:#7ee787; }
.tag.off { background:#3a1d1d; color:#ff8585; }
.flash { background:#16321f; border:1px solid #25502f; color:#9fe6ad;
         padding:10px 12px; border-radius:8px; margin-bottom:16px; font-size:14px; }
.flash.err { background:#3a1d1d; border-color:#5a2a2a; color:#ffb0b0; }
hr { border:0; border-top:1px solid #232833; margin:16px 0; }
.login-box { max-width:360px; margin:80px auto; }
form.inline { display:inline; }
.upstreams { font-family: ui-monospace, Menlo, Consolas, monospace; font-size:12px;
             color:#9aa4b2; white-space:pre-wrap; word-break:break-all; }
/* размытие чувствительных значений до клика (классич. вид) */
.blur { filter: blur(5px); cursor:pointer; transition: filter .12s; }
.blur:focus { filter:none; cursor:text; }
.blur.show { filter:none; }
body.unblur .blur { filter:none; cursor:auto; }
"""
