"""
UrlScout - malicious URL detector (backend)

Two layers:
  1. Static analysis  - looks only at the URL text (safe, instant, offline)
  2. Deep scan        - optional: DNS, TLS certificate, redirect chain
Every signal carries points + a plain-English reason, so the verdict is explainable.
"""
import ipaddress, math, re, socket, sqlite3, ssl, time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, unquote

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)  # lets the frontend call the API even if hosted on another origin
DB = "scans.db"

# ---------- reference data ----------
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
          "netflix", "whatsapp", "paytm", "flipkart", "hdfc", "icici", "dropbox", "linkedin", "github"]
TRUSTED = {"google.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com", "amazon.in",
           "facebook.com", "instagram.com", "paypal.com", "netflix.com", "github.com", "linkedin.com",
           "whatsapp.com", "dropbox.com", "wikipedia.org", "paytm.com", "flipkart.com",
           "hdfcbank.com", "icicibank.com", "sbi.co.in", "onlinesbi.sbi"}
BAD_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "support", "icu"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at"}
MULTI_TLD = {"co.uk", "co.in", "org.in", "net.in", "gov.in", "ac.in", "com.au", "com.br"}
KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "bank", "confirm",
            "wallet", "password", "suspend", "invoice", "otp", "kyc", "reward", "free"]
RISKY_EXT = (".exe", ".apk", ".scr", ".msi", ".bat", ".jar", ".js", ".vbs", ".iso")
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"})


# ---------- helpers ----------
def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def split_host(host):
    parts = host.split(".")
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLD else 2
    return ".".join(parts[-n:]), parts[:-n]  # registered domain, subdomain labels


def normalise(raw):
    raw = raw.strip()
    if len(raw) > 2048:
        raise ValueError("URL is too long (max 2048 characters).")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Only valid http/https URLs can be analysed.")
    return raw


def is_public(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None  # does not resolve
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


# ---------- layer 1: static analysis ----------
def static_signals(url):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path_q = unquote(p.path + "?" + p.query).lower()
    out = []

    def add(key, pts, why):
        out.append({"key": key, "points": pts, "why": why})

    try:
        ipaddress.ip_address(host)
        add("ip_host", 35, "Uses a raw IP address instead of a domain name.")
    except ValueError:
        pass

    reg, sub = split_host(host)
    tld = host.rsplit(".", 1)[-1]

    if "@" in p.netloc:
        add("at_symbol", 30, "Contains '@' - everything before it is ignored by browsers, a classic disguise.")
    if p.scheme == "http":
        add("no_https", 10, "Connection is not encrypted (http).")
    if len(url) > 120:
        add("very_long", 12, f"Very long URL ({len(url)} characters).")
    elif len(url) > 75:
        add("long", 6, f"Long URL ({len(url)} characters).")
    if len(sub) >= 4:
        add("deep_subdomain", 12, f"{len(sub)} subdomain levels - used to bury the real domain.")
    if host.count("-") >= 3:
        add("hyphens", 10, "Many hyphens in the domain, common in throw-away phishing domains.")
    if host and sum(c.isdigit() for c in host) / len(host) > 0.3:
        add("digits", 8, "Domain is full of digits.")
    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", 25, "Punycode domain - may visually imitate another site.")
    elif any(ord(c) > 127 for c in host):
        add("unicode", 25, "Non-ASCII characters in the domain (look-alike letters).")
    if tld in BAD_TLDS:
        add("bad_tld", 15, f".{tld} is a TLD heavily abused for phishing and spam.")
    if reg in SHORTENERS:
        add("shortener", 20, "Link shortener - the real destination is hidden.")
    if p.port and p.port not in (80, 443):
        add("odd_port", 8, f"Unusual port {p.port}.")
    if path_q.count("http") >= 1:
        add("embedded_url", 15, "Another URL is hidden inside this one (redirect trick).")
    if p.path.lower().endswith(RISKY_EXT):
        add("risky_file", 20, "Points straight at an executable or script file.")

    hits = [k for k in KEYWORDS if k in host + path_q]
    if len(hits) >= 2:
        add("keywords", 15, "Pressure words in URL: " + ", ".join(hits[:4]) + ".")
    elif hits:
        add("keywords", 6, f"Contains the word '{hits[0]}'.")

    label = reg.split(".")[0]
    if len(label) > 12 and entropy(label) > 3.6:
        add("random_name", 10, "Domain looks randomly generated.")

    # brand impersonation
    if reg in TRUSTED:
        add("known_good", -25, f"{reg} is a well-known legitimate domain.")
    else:
        flat = label.translate(LEET)
        found = False
        for part in flat.split("-"):
            for b in BRANDS:
                if 0 < levenshtein(part, b) <= 2 and len(b) >= 5 and part != b:
                    add("typosquat", 30, f"'{label}' is almost '{b}' - possible typo-squatting.")
                    found = True
                    break
            if found:
                break
        if not found:
            for b in BRANDS:
                if b in flat.replace("-", ""):
                    add("brand_in_domain", 28, f"Domain mentions '{b}' but is not the real {b} site.")
                    found = True
                    break
                if any(b in s.translate(LEET) for s in sub):
                    add("brand_in_subdomain", 25, f"'{b}' appears as a subdomain of an unrelated domain ({reg}).")
                    found = True
                    break
    return out


# ---------- layer 2: deep scan ----------
def deep_signals(url):
    p = urlparse(url)
    host = p.hostname
    out, info = [], {}

    def add(key, pts, why):
        out.append({"key": key, "points": pts, "why": why})

    pub = is_public(host)
    if pub is None:
        add("no_dns", 20, "Domain does not resolve in DNS.")
        return out, info
    if pub is False:
        info["note"] = "Resolves to a private address - deep scan skipped for safety."
        return out, info

    # TLS certificate
    if p.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, p.port or 443), timeout=4) as s:
                with ctx.wrap_socket(s, server_hostname=host) as t:
                    cert = t.getpeercert()
            age = (time.time() - ssl.cert_time_to_seconds(cert["notBefore"])) / 86400
            issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "unknown")
            info["cert"] = {"issuer": issuer, "age_days": int(age)}
            if age < 14:
                add("new_cert", 15, f"Certificate issued only {int(age)} days ago.")
        except ssl.SSLError as e:
            add("bad_cert", 25, "TLS certificate failed validation.")
            info["cert_error"] = e.reason or "invalid"
        except OSError:
            info["cert_error"] = "could not connect on 443"

    # redirect chain (every hop re-checked so we never touch private hosts)
    hops, cur = [url], url
    try:
        for _ in range(5):
            h = urlparse(cur).hostname
            if is_public(h) is not True:
                break
            r = requests.get(cur, allow_redirects=False, timeout=4, stream=True,
                             headers={"User-Agent": "UrlScout/1.0"})
            r.close()
            loc = r.headers.get("Location")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                cur = urljoin(cur, loc)
                hops.append(cur)
            else:
                break
    except requests.RequestException:
        info["fetch_error"] = "site did not respond"
    info["redirects"] = hops
    if len(hops) >= 4:
        add("many_redirects", 10, f"Follows {len(hops) - 1} redirects before landing.")
    if split_host(urlparse(hops[0]).hostname)[0] != split_host(urlparse(hops[-1]).hostname)[0]:
        add("redirect_away", 12, "Ends up on a different domain than the one you pasted.")
    return out, info


# ---------- scoring ----------
def verdict_for(score):
    if score >= 60:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "safe"


def analyse(raw, deep=False):
    url = normalise(raw)
    signals = static_signals(url)
    info = {}
    if deep:
        extra, info = deep_signals(url)
        signals += extra
    score = max(0, min(100, sum(s["points"] for s in signals)))
    signals.sort(key=lambda s: -abs(s["points"]))
    return {"url": url, "host": urlparse(url).hostname, "score": score, "verdict": verdict_for(score),
            "signals": signals, "deep": info if deep else None,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


# ---------- storage + rate limit ----------
def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, url TEXT, score INT, verdict TEXT, ts TEXT)")
    return c


HITS = {}


def too_many(ip):
    now = time.time()
    recent = [t for t in HITS.get(ip, []) if now - t < 60] + [now]
    HITS[ip] = recent
    return len(recent) > 30


# ---------- routes ----------
@app.get("/")
def home():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.post("/api/analyze")
def api_analyze():
    if too_many(request.remote_addr):
        return jsonify(error="Too many requests. Wait a minute and try again."), 429
    body = request.get_json(silent=True) or {}
    try:
        res = analyse(body.get("url", ""), bool(body.get("deep")))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    with db() as c:
        c.execute("INSERT INTO scans(url,score,verdict,ts) VALUES(?,?,?,?)",
                  (res["url"][:300], res["score"], res["verdict"], res["scanned_at"]))
    return jsonify(res)


@app.get("/api/history")
def history():
    with db() as c:
        rows = c.execute("SELECT url,score,verdict,ts FROM scans ORDER BY id DESC LIMIT 8").fetchall()
    return jsonify([dict(zip(("url", "score", "verdict", "ts"), r)) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)