#!/usr/bin/env python3
"""
Proxy Farm manager — turns a VPN account (HMA certificate, WireGuard, OpenVPN or IKEv2
username/password, from any provider) into many per-location SOCKS5/HTTP proxy ports,
each a Docker container running one tunnel + gost (see ../node). Host-side: shells out
to `docker`. Provider presets and server-list importers live in providers.py.

  python3 farm.py serve                  # web UI on :8090 (default)
  python3 farm.py up <KEY|CC> ...        # start tunnels for locations/countries
  python3 farm.py down [KEY ...]         # stop (all if none given)
  python3 farm.py ls                     # list running proxies + exit IPs
  python3 farm.py rotate <KEY>           # reconnect (new gateway IP)
  python3 farm.py presets                # providers Proxy Farm knows, and how to add them
  python3 farm.py import <PRESET> [openvpn|wireguard|ikev2] [per-city]
                                         # fetch a provider's server list (asks for the account)
  python3 farm.py auth <PROVIDER> [USER]  # store OpenVPN username/password for a provider
  python3 farm.py add <FILE...>          # import .ovpn/.conf/.zip files (ca.crt etc. alongside)

State: farm-state.json (chosen locations -> assigned port). Ports from BASE_PORT.
"""
import json, os, re, base64, subprocess, sys, time, threading, http.server, urllib.parse, socket
import providers as P

HERE = os.path.dirname(os.path.abspath(__file__))
LOCS = json.load(open(os.path.join(HERE, "locations.json")))
STATE_FILE = os.environ.get("PF_STATE", os.path.join(HERE, "farm-state.json"))
IMAGE = os.environ.get("PF_IMAGE", "proxy-farm-node")
SECRETS = os.environ.get("PF_SECRETS", os.path.expanduser("~/proxy-farm/secrets"))  # host path for -v
# Where the manager itself reads/writes the certificate. Same as SECRETS when it runs with
# host networking and no mount indirection; a published container must mount it.
COMPOSE_PROJECT = os.environ.get("PF_COMPOSE_PROJECT", "")
SECRETS_DIR = os.environ.get("PF_SECRETS_DIR", SECRETS)
BASE_PORT = int(os.environ.get("PF_BASE_PORT", "29001"))
FLAGS_DIR = os.environ.get("PF_FLAGS", os.path.join(HERE, "flags"))
STATUS_DIR = os.environ.get("PF_STATUS_DIR", os.path.join(HERE, "status"))   # in-container path
STATUS_DIR_HOST = os.environ.get("PF_STATUS_HOST", STATUS_DIR)               # host path for -v mounts
os.makedirs(STATUS_DIR, exist_ok=True)
BIND = os.environ.get("PF_BIND", "127.0.0.1")          # host iface proxies listen on
UI_PORT = int(os.environ.get("PF_UI_PORT", "8090"))
# Where the UI socket itself binds. Same as BIND when the manager runs with host
# networking; when it runs as a published container it must bind 0.0.0.0 inside the
# container and let `-p 127.0.0.1:...` do the restricting.
UI_BIND = os.environ.get("PF_UI_BIND", BIND)

# Drop zone on disk: anything left here is imported automatically. run.sh seeds it with
# the HMA device token when the app is installed on this machine.
INBOX = os.environ.get("PF_INBOX", "")
# Read-only directories scanned for VPN configs. Findings are only ever *suggested*;
# nothing outside INBOX is imported without the user asking.
SCAN_DIR = os.environ.get("PF_SCAN", "")

CONFIG_DIR = os.environ.get("PF_CONFIG_DIR", os.path.join(HERE, "configs"))
CONFIG_DIR_HOST = os.environ.get("PF_CONFIG_HOST", CONFIG_DIR)
os.makedirs(CONFIG_DIR, exist_ok=True)

# ---- targets -----------------------------------------------------------------
# A "target" is anything that can become a proxy port. Two sources:
#   catalog  — a provider with a server list we ship (HMA/SurfEasy), auth by certificate
#   config   — a .conf/.ovpn the user uploaded; one file = one location
CATALOG = []
for l in LOCS["locations"]:
    CATALOG.append({**l, "provider": "hma", "protocol": "ikev2-cert",
                    "label": l["countryName"] + " " + l["city"]})

detect_protocol = P.detect_protocol

_CC = {f[:-4].upper() for f in os.listdir(FLAGS_DIR) if f.endswith(".png")} \
      if os.path.isdir(FLAGS_DIR) else set()
CC_NAME = {l["country"]: l["countryName"] for l in CATALOG}

_NOT_PROVIDER = {"udp", "tcp", "ovpn", "conf", "openvpn", "wireguard", "config", "vpn",
                 "server", "prod", "com", "net", "default", "client", "free", "secure"}

def guess_provider(name, content=""):
    """Best-effort provider. The servers a config points at say it best
    ('uk765.nordvpn.com' -> nordvpn); otherwise the first word of the filename
    ('mullvad-se-got.conf' -> 'mullvad')."""
    hosts = [h for h, _, _ in P.parse_remotes(content)] if content else []
    m = re.search(r"^[ \t]*Endpoint[ \t]*=[ \t]*\[?([^\]\s:]+)", content or "", re.M)
    if m: hosts.append(m.group(1))
    by_host = P.provider_from_hosts(hosts)
    if by_host: return by_host
    toks = [t for t in re.split(r"[^A-Za-z]+", os.path.basename(name).lower()) if t]
    for t in toks:                    # a known provider anywhere in the name wins
        if t in P.PRESET_BY_ID: return t
    for tok in toks:
        if tok.upper() in _CC or P.cc_from_token(tok) or P._norm(tok) in P._NAME_TO_CC:
            break                     # 'nl-amsterdam.ovpn': what follows a country is a city
        if len(tok) > 2 and tok not in _NOT_PROVIDER:
            return tok
    # Unknown provider but a real hostname: 'nl1.myvpn.net' -> 'myvpn'
    for h in hosts:
        parts = h.lower().rstrip(".").split(".")
        if len(parts) >= 2 and not parts[-1].isdigit() and re.fullmatch(r"[a-z0-9-]{3,}", parts[-2]):
            return parts[-2]
    return "custom"

def guess_country(name, content=""):
    """Best-effort 2-letter country from a filename ('mullvad-se-got.conf',
    'TorGuard.USA-NEW-YORK.ovpn', 'us_new_york.ovpn') or the server name in it."""
    hosts = [h for h, _, _ in P.parse_remotes(content)] if content else []
    return P.guess_location(name, hosts)[0]

def config_targets():
    out = []
    for fn in sorted(os.listdir(CONFIG_DIR)):
        if not fn.endswith((".conf", ".ovpn")): continue
        meta_p = os.path.join(CONFIG_DIR, fn + ".meta.json")
        try: meta = json.load(open(meta_p))
        except Exception: meta = {}
        stem = re.sub(r"[^A-Za-z0-9]+", "-", fn.rsplit(".", 1)[0]).strip("-").upper()
        cc = meta.get("country") or guess_country(fn)
        out.append({
            "key": "CFG-" + stem,
            "provider": meta.get("provider") or "custom",
            "protocol": meta.get("protocol") or ("wireguard" if fn.endswith(".conf") else "openvpn"),
            "config": fn,
            "country": cc,
            "city": meta.get("city") or fn.rsplit(".", 1)[0],
            "countryName": meta.get("countryName") or CC_NAME.get(cc) or P.country_name(cc) or "Tự nạp",
            "needs_auth": bool(meta.get("needs_auth")),
            "label": fn,
        })
    return out

# ---- providers ---------------------------------------------------------------
PROVIDERS_FILE = os.path.join(os.path.dirname(STATE_FILE), "providers.json")

def load_providers():
    try: return json.load(open(PROVIDERS_FILE))
    except Exception: return {"eap": []}
def save_providers(p):
    json.dump(p, open(PROVIDERS_FILE, "w"), indent=1)
    os.chmod(PROVIDERS_FILE, 0o600)

def slug(t): return re.sub(r"[^A-Za-z0-9]+", "-", t).strip("-").upper() or "X"

# ---- OpenVPN accounts ------------------------------------------------------------
# One username/password per provider, shared by every config of that provider. Kept in
# SECRETS_DIR/auth/<provider>.txt (0600) and bind-mounted read-only into exactly the ports
# that need it, so the password never sits in `docker inspect` or another port's view.
def _pid(p): return re.sub(r"[^a-z0-9_-]+", "-", (p or "custom").lower()).strip("-") or "custom"

def auth_file(provider, host=False):
    return os.path.join(SECRETS if host else SECRETS_DIR, "auth", _pid(provider) + ".txt")

def has_account(provider):
    return os.path.exists(auth_file(provider))

def set_account(provider, user, password):
    user = (user or "").strip()
    if not user or not password:
        raise ValueError("Cần đủ tên đăng nhập và mật khẩu")
    if "\n" in user or "\n" in password:
        raise ValueError("Tên/mật khẩu không được chứa xuống dòng")
    d = os.path.dirname(auth_file(provider))
    os.makedirs(d, exist_ok=True); os.chmod(d, 0o700)
    path = auth_file(provider)
    with open(path, "w") as f: f.write(f"{user}\n{password}\n")
    os.chmod(path, 0o600)
    prov = load_providers()
    prov.setdefault("accounts", {})[_pid(provider)] = {"user": user, "set": int(time.time())}
    save_providers(prov)
    return {"provider": _pid(provider), "user": user}

def delete_account(provider):
    try: os.remove(auth_file(provider))
    except OSError: pass
    prov = load_providers()
    if prov.get("accounts", {}).pop(_pid(provider), None) is not None: save_providers(prov)

def hma_status():
    """What the UI shows for the HMA/SurfEasy card: is the device certificate present,
    whose is it, and when does it expire."""
    pem = os.path.join(SECRETS_DIR, "client.pem")
    if not os.path.exists(pem): return {"ready": False}
    out = {"ready": True, "locations": len(CATALOG)}
    try:
        r = subprocess.run(["openssl", "x509", "-in", pem, "-noout", "-subject",
                            "-enddate", "-nameopt", "multiline"],
                           text=True, capture_output=True, timeout=10)
        cn = re.search(r"commonName\s*=\s*(.+)", r.stdout)
        end = re.search(r"notAfter=(.+)", r.stdout)
        if cn: out["udid"] = cn.group(1).strip()
        if end: out["expires"] = end.group(1).strip()
    except Exception as e:
        out["error"] = str(e)
    return out

_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
_PEM_KEY = re.compile(r"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----.*?"
                      r"-----END (?:ENCRYPTED )?PRIVATE KEY-----|"
                      r"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----", re.S)

def _openssl_p12(p12_path, password, *args):
    """Run openssl pkcs12, retrying with -legacy: the app's bundle uses RC2/SHA1, which
    OpenSSL 3 only reads through the legacy provider."""
    base = ["openssl", "pkcs12", "-in", p12_path, "-passin", f"pass:{password}"]
    for extra in ([], ["-legacy"]):
        r = subprocess.run(base + list(args) + extra, text=True, capture_output=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip(): return r.stdout
    raise ValueError("Không mở được chứng chỉ — sai mật khẩu hoặc file hỏng"
                     + (f" ({r.stderr.strip().splitlines()[-1]})" if r.stderr.strip() else ""))

def import_hma(token_text=None, p12_b64=None, password=None):
    """Install the HMA device certificate. Accepts either the macOS app's
    tokenCoreSE.json (which carries the PKCS#12 *and* its password) or a raw .p12."""
    meta = {}
    if token_text:
        try:
            outer = json.loads(token_text)
            dev = json.loads(base64.b64decode(outer["DeviceManager.device"]))
            p12_b64 = dev["credentials"]["certificate"]
            password = dev["credentials"]["certificatePassword"]
            meta = {"udid": dev.get("udid", ""),
                    "dns_format": (dev.get("dnsFormat") or [""])[0]}
        except Exception as e:
            raise ValueError(f"Không đọc được tokenCoreSE.json: {e}")
    if not p12_b64:
        raise ValueError("Thiếu chứng chỉ")
    try: raw = base64.b64decode(p12_b64)
    except Exception: raise ValueError("Chứng chỉ không phải base64 hợp lệ")

    os.makedirs(SECRETS_DIR, exist_ok=True)
    tmp = os.path.join(SECRETS_DIR, ".import.p12")
    with open(tmp, "wb") as f: f.write(raw)
    os.chmod(tmp, 0o600)
    try:
        leaf = _PEM_CERT.search(_openssl_p12(tmp, password or "", "-nokeys", "-clcerts"))
        key = _PEM_KEY.search(_openssl_p12(tmp, password or "", "-nocerts", "-nodes"))
        chain = _PEM_CERT.findall(_openssl_p12(tmp, password or "", "-nokeys", "-cacerts"))
        if not leaf or not key:
            raise ValueError("Chứng chỉ thiếu phần client hoặc khoá riêng")
        # Write only after every part parsed, so a bad import can't half-replace a
        # working certificate and take the whole farm down.
        for name, body in (("client.pem", leaf.group(0) + "\n"),
                           ("client.key", key.group(0) + "\n"),
                           ("ca-int.pem", "\n".join(chain) + "\n" if chain else "")):
            if not body.strip(): continue
            path = os.path.join(SECRETS_DIR, name)
            with open(path, "w") as f: f.write(body)
            os.chmod(path, 0o600)
    finally:
        try: os.remove(tmp)
        except OSError: pass

    prov = load_providers()
    prov["hma"] = {**meta, "imported": int(time.time())}
    save_providers(prov)
    return hma_status()

# ---- automatic discovery ------------------------------------------------------
def _cert_mtime():
    try: return os.path.getmtime(os.path.join(SECRETS_DIR, "client.pem"))
    except OSError: return 0

def ingest_inbox():
    """Import whatever is sitting in INBOX. Config files are consumed; the HMA token is
    left in place (run.sh refreshes it) and re-imported only when it is newer than the
    certificate we already installed."""
    if not INBOX or not os.path.isdir(INBOX): return []
    done = []
    for fn in sorted(os.listdir(INBOX)):
        path = os.path.join(INBOX, fn)
        if not os.path.isfile(path): continue
        try:
            if fn == "tokenCoreSE.json":
                if os.path.getmtime(path) <= _cert_mtime(): continue
                import_hma(token_text=open(path, encoding="utf-8").read())
                done.append(("hma", fn))
            elif fn.endswith((".conf", ".ovpn")):
                save_config(fn, open(path, encoding="utf-8").read(), assets=INBOX)
                os.remove(path)
                done.append(("config", fn))
            elif fn.lower().endswith(".zip"):
                save_bundle(fn, open(path, "rb").read())
                os.remove(path)
                done.append(("bundle", fn))
        except Exception as e:
            print(f"inbox: bỏ qua {fn}: {e}", flush=True)
    if done: print("inbox: đã nạp " + ", ".join(f for _, f in done), flush=True)
    return done

def inbox_loop():
    while True:
        try: ingest_inbox()
        except Exception as e: print("inbox:", e, flush=True)
        time.sleep(60)

def discover():
    """Config files lying around on the machine that are not imported yet."""
    if not SCAN_DIR or not os.path.isdir(SCAN_DIR): return []
    have = {t["config"] for t in config_targets()}
    out = []
    for root, dirs, files in os.walk(SCAN_DIR):
        dirs[:] = [d for d in dirs if not d.startswith(".")][:20]
        if root.count(os.sep) - SCAN_DIR.count(os.sep) > 2: dirs[:] = []
        for fn in files:
            if not fn.endswith((".conf", ".ovpn")) or fn in have: continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > 200_000: continue
                proto = detect_protocol(open(fp, encoding="utf-8", errors="ignore").read(4000))
            except OSError: continue
            if not proto: continue
            out.append({"name": fn, "path": fp, "protocol": proto,
                        "where": os.path.relpath(root, SCAN_DIR),
                        "provider": guess_provider(fn), "country": guess_country(fn)})
            if len(out) >= 40: return out
    return out

def import_found(paths):
    ok = []
    for fp in paths:
        # Only ever read back inside the scanned tree: a path from the client is input.
        rp = os.path.realpath(fp)
        if not SCAN_DIR or not rp.startswith(os.path.realpath(SCAN_DIR) + os.sep): continue
        try:
            # ca.crt / ta.key next to the .ovpn get inlined; nothing else is read.
            save_config(os.path.basename(rp), open(rp, encoding="utf-8").read(),
                        assets=os.path.dirname(rp))
            ok.append(os.path.basename(rp))
        except Exception as e:
            print(f"import: {rp}: {e}", flush=True)
    return ok

def eap_targets():
    out = []
    for e in load_providers().get("eap", []):
        out.append({"key": "EAP-" + e["id"], "provider": e.get("name") or "ikev2",
                    "protocol": "ikev2-eap", "fqdn": e["server"],
                    "eap_user": e.get("user"), "eap_pass": e.get("pass"),
                    "server_id": e.get("server_id"), "ca": e.get("ca"),
                    "country": e.get("country") or "XX",
                    "city": e.get("city") or e["server"],
                    "countryName": CC_NAME.get(e.get("country") or "") or
                                   P.country_name(e.get("country")) or "Tự nạp",
                    "label": e["server"]})
    return out

def save_ca(name, data):
    """Store a provider's CA (PEM or DER bytes) as SECRETS_DIR/ca-eap-<name>.pem; returns
    the file name. IKEv2 ports that reference it trust only this CA for the gateway."""
    pem = P.ca_to_pem(data)
    r = subprocess.run(["openssl", "x509", "-noout", "-subject"], input=pem, text=True,
                       capture_output=True, timeout=10)
    if r.returncode != 0:
        raise ValueError("File CA không phải chứng chỉ X.509 hợp lệ")
    os.makedirs(SECRETS_DIR, exist_ok=True)
    fn = "ca-eap-" + _pid(name) + ".pem"
    path = os.path.join(SECRETS_DIR, fn)
    with open(path, "w") as f: f.write(pem)
    os.chmod(path, 0o600)
    return fn

def add_eap(d, save=True):
    for f in ("server", "user", "pass"):
        if not (d.get(f) or "").strip():
            raise ValueError("Cần đủ máy chủ, tên đăng nhập và mật khẩu")
    prov = load_providers()
    name = (d.get("name") or d["server"].split(".")[0]).strip()
    ca = d.get("ca_file") or None
    if d.get("ca"):          # uploaded from the UI as base64 (PEM or DER)
        try: raw = base64.b64decode(d["ca"])
        except Exception: raise ValueError("File CA hỏng")
        ca = save_ca(name, raw)
    e = {"id": slug(name + "-" + d["server"]), "name": name,
         "server": d["server"].strip(), "user": d["user"].strip(), "pass": d["pass"],
         "server_id": (d.get("server_id") or "").strip() or None,
         "country": (d.get("country") or "").strip().upper()[:2] or None,
         "city": (d.get("city") or "").strip() or None, "ca": ca}
    prov.setdefault("eap", [])
    prov["eap"] = [x for x in prov["eap"] if x["id"] != e["id"]] + [e]
    save_providers(prov)
    return next(t for t in eap_targets() if t["key"] == "EAP-" + e["id"])

def delete_provider(pid):
    """Remove a provider and every port it owns. HMA also drops its certificate."""
    prov = load_providers()
    if pid == "hma":
        down([k for k, v in load_state().items() if v.get("provider") == "hma"])
        for f in os.listdir(SECRETS_DIR) if os.path.isdir(SECRETS_DIR) else []:
            if f.startswith(("client.", "ca-")): os.remove(os.path.join(SECRETS_DIR, f))
        prov.pop("hma", None)
    else:
        gone = [e for e in prov.get("eap", []) if slug(e["name"]) == pid]
        if gone:
            down(["EAP-" + e["id"] for e in gone])
            prov["eap"] = [e for e in prov["eap"] if slug(e["name"]) != pid]
            for ca in {e.get("ca") for e in gone if e.get("ca")}:
                if not any(e.get("ca") == ca for e in prov["eap"]):
                    try: os.remove(os.path.join(SECRETS_DIR, ca))
                    except OSError: pass
        else:   # a file-based provider: every config tagged with this name
            for t in config_targets():
                if t["provider"] == pid: delete_config(t["key"])
            save_providers(prov)
            delete_account(pid)
            return
    save_providers(prov)

def presets_list():
    """The registry as the UI needs it: what each provider supports, whether Proxy Farm
    can fetch its servers, and whether an account is already stored."""
    out = []
    for pre in P.PRESETS:
        protos = []
        for k, v in pre.get("protocols", {}).items():
            protos.append({"protocol": k, "how": v.get("how"), "note": v.get("note", ""),
                           "importable": v.get("how") in ("import", "template"),
                           "template": v.get("how") == "template",
                           "list_checked": bool(v.get("list_checked")),
                           "connect_verified": bool(v.get("connect_verified")),
                           "default_address": v.get("default_address", "")})
        out.append({"id": pre["id"], "name": pre["name"], "protocols": protos,
                    "credentials": pre.get("credentials", ""),
                    "account_url": pre.get("account_url", ""),
                    "unsupported": pre.get("unsupported", ""),
                    "max_connections": pre.get("max_connections", 0),
                    "has_account": has_account(pre["id"])})
    return out

def upload_batch(files, provider=None):
    """Files dropped together: ca.crt / ta.key / client.key are kept in memory and inlined
    into the .ovpn files of the same batch; .zip bundles are expanded."""
    assets, configs, zips, errors, done = {}, [], [], [], []
    for f in files:
        name = os.path.basename(f.get("name") or "file")
        try:
            raw = base64.b64decode(f["b64"]) if f.get("b64") else (f.get("content") or "").encode()
        except Exception:
            errors.append(f"{name}: hỏng"); continue
        if name.lower().endswith(".zip"): zips.append((name, raw))
        elif name.lower().endswith((".ovpn", ".conf")) or \
                detect_protocol(raw.decode("utf-8", "ignore")): configs.append((name, raw))
        else: assets[name] = raw
    for name, raw in zips:
        try: done += [it["name"] for it in save_bundle(name, raw, provider)]
        except Exception as e: errors.append(f"{name}: {e}")
    for name, raw in configs:
        try:
            save_config(name, raw.decode("utf-8", "replace"), provider, assets=assets)
            done.append(name)
        except Exception as e: errors.append(f"{name}: {e}")
    return {"imported": done, "errors": errors}

# ---- per-provider port limits --------------------------------------------------
# Most providers cap simultaneous connections per account, so the farm refuses to start
# more than the cap rather than let the provider kick sessions. 0 = no limit.
# HMA: no limit — 20+ concurrent ran stable; what broke big farms was stuck reconnects,
# not the count. HMA ends every session after ~4.5 h; the watchdog reconnects in seconds.
DEFAULT_LIMITS = {**P.default_limits(), "hma": 0, "proton": 10, "custom": 0}

def limit_key(t):
    return "hma" if t.get("protocol") == "ikev2-cert" else (t.get("provider") or "custom").lower()

def get_limits():
    return load_providers().get("limits", {})

def limit_for(key):
    lim = get_limits()
    return int(lim[key]) if key in lim else DEFAULT_LIMITS.get(key, 0)

def set_limit(key, n):
    prov = load_providers()
    prov.setdefault("limits", {})[key] = max(0, int(n))
    save_providers(prov)

def usage(run=None):
    """Ports currently holding a connection, per provider (stopped ones don't count)."""
    run = run if run is not None else running_containers()
    idx = targets_index(); out = {}
    for k, v in load_state().items():
        if (run.get(k) or {}).get("state") in ("running", "restarting"):
            lk = limit_key(idx.get(k, v))
            out[lk] = out.get(lk, 0) + 1
    return out

def over_quota(targets):
    """Split targets into those allowed to start now and those the cap refuses."""
    run = running_containers(); used = usage(run)
    ok, refused = [], []
    for t in targets:
        if (run.get(t["key"]) or {}).get("state") in ("running", "restarting"):
            ok.append(t); continue                    # already counted; recreating is free
        lk = limit_key(t); lim = limit_for(lk)
        if lim and used.get(lk, 0) >= lim:
            refused.append({"key": t["key"], "provider": lk, "limit": lim})
        else:
            used[lk] = used.get(lk, 0) + 1; ok.append(t)
    return ok, refused

def providers_list():
    out = [{"id": "hma", "kind": "ikev2-cert", "name": "HMA / SurfEasy",
            "note": "Chứng chỉ thiết bị từ app", **hma_status()}]
    by_file = {}
    for t in config_targets():
        pre = P.preset(t["provider"])
        p = by_file.setdefault(t["provider"], {"id": t["provider"], "kind": t["protocol"],
                                               "name": t["provider"],
                                               "title": pre["name"] if pre else t["provider"],
                                               "ready": True, "note": "File cấu hình",
                                               "locations": 0, "needs_auth": False})
        p["locations"] += 1
        if t["protocol"] != p["kind"]: p["kind"] = "mixed"
        if t.get("needs_auth"): p["needs_auth"] = True
    for p in by_file.values():
        if p["needs_auth"]:
            p["has_auth"] = has_account(p["id"])
            acct = load_providers().get("accounts", {}).get(_pid(p["id"]))
            p["auth_user"] = (acct or {}).get("user")
    out += sorted(by_file.values(), key=lambda p: p["name"])
    by_acct = {}
    for e in load_providers().get("eap", []):
        p = by_acct.setdefault(slug(e["name"]), {"id": slug(e["name"]), "kind": "ikev2-eap",
                                                 "name": e["name"], "ready": True,
                                                 "title": (P.preset(e["name"]) or {}).get("name"),
                                                 "note": e["user"], "locations": 0})
        p["locations"] += 1
    out += sorted(by_acct.values(), key=lambda p: p["name"])
    used = usage()
    for p in out:
        lk = "hma" if p["kind"] == "ikev2-cert" else p["name"].lower()
        p["limit_key"] = lk
        p["limit"] = limit_for(lk)
        p["limit_default"] = DEFAULT_LIMITS.get(lk, 0)
        p["used"] = used.get(lk, 0)
    return out

def all_targets():
    # No certificate installed = no HMA locations, so a fresh install shows an honest
    # empty farm instead of 115 ports that would all fail to start.
    hma = CATALOG if os.path.exists(os.path.join(SECRETS_DIR, "client.pem")) else []
    return hma + config_targets() + eap_targets()

def targets_index():
    return {t["key"]: t for t in all_targets()}

BY_CC = {}
for l in CATALOG:
    BY_CC.setdefault(l["country"], []).append(l)

def load_state():
    try: return json.load(open(STATE_FILE))
    except Exception: return {}
def save_state(s): json.dump(s, open(STATE_FILE, "w"), indent=1)

SETTINGS_FILE = os.path.join(os.path.dirname(STATE_FILE), "settings.json")
CREDS_FILE = os.path.join(os.path.dirname(STATE_FILE), "creds.json")   # pre-settings layout

# Environment gives the defaults; settings.json (written by the UI) overrides them, so a
# user who never opens Settings behaves exactly as the docker run flags say.
DEFAULTS = {
    "proxy_user": os.environ.get("PF_PROXY_USER", "proxy"),
    "proxy_pass": os.environ.get("PF_PROXY_PASS", ""),
    "rotate_key": "",
    "bind": BIND,
    "base_port": BASE_PORT,
    "mtu": int(os.environ.get("PF_MTU", "1400")),
    "watchdog_interval": int(os.environ.get("PF_WATCHDOG_INTERVAL", "15")),
    "watchdog_fails": int(os.environ.get("PF_WATCHDOG_FAILS", "3")),
    # Nodes already back off to one attempt per 30 min, which is cheap and self-heals
    # when a gateway lifts its block. Giving up for good is therefore opt-in.
    "give_up_after": int(os.environ.get("PF_GIVE_UP_AFTER", "0")),
    "dns": os.environ.get("PF_TUNNEL_DNS", "1.1.1.1 8.8.8.8"),
}
SETTABLE = [k for k in DEFAULTS if k != "rotate_key"]

def save_settings(s):
    json.dump(s, open(SETTINGS_FILE, "w"), indent=1)
    os.chmod(SETTINGS_FILE, 0o600)

def load_settings():
    st = dict(DEFAULTS)
    try:
        st.update(json.load(open(SETTINGS_FILE)))
    except Exception:
        try:                                   # migrate the older creds-only file
            c = json.load(open(CREDS_FILE))
            st.update(proxy_user=c.get("user") or st["proxy_user"],
                      proxy_pass=c.get("pass") or "", rotate_key=c.get("rotate_key") or "")
        except Exception: pass
    import secrets as _s
    missing = not st["proxy_pass"] or not st["rotate_key"]
    st["proxy_pass"] = st["proxy_pass"] or _s.token_urlsafe(12)
    st["rotate_key"] = st["rotate_key"] or _s.token_urlsafe(16)
    if missing or not os.path.exists(SETTINGS_FILE): save_settings(st)
    return st

def load_creds():
    st = load_settings()
    return {"user": st["proxy_user"], "pass": st["proxy_pass"], "rotate_key": st["rotate_key"]}

def rotate_key(): return load_settings()["rotate_key"]

def docker(*a, check=True, capture=True):
    return subprocess.run(["docker", *a], text=True, check=check,
                          capture_output=capture)
def cname(key): return "pf-" + key.lower()

def used_ports(state):
    return {v["port"] for v in state.values()}
def next_port(state):
    used = used_ports(state)
    p = load_settings()["base_port"]
    while p in used: p += 1
    return p

def resolve_targets(args):
    """Expand KEY / country-code / 'all' into a list of target dicts."""
    idx = targets_index()
    out, seen = [], set()
    for a in args:
        if a == "all": picks = list(idx.values())
        elif a in idx: picks = [idx[a]]
        elif a.upper() in BY_CC: picks = BY_CC[a.upper()]
        else:
            print(f"unknown location/country: {a}", file=sys.stderr); continue
        for l in picks:
            if l["key"] not in seen: seen.add(l["key"]); out.append(l)
    return out

def up(keys):
    targets, refused = over_quota(resolve_targets(keys))
    for r in refused:
        print(f"skip {r['key']}: {r['provider']} đã đủ {r['limit']} cổng", flush=True)
    clear_failed([l["key"] for l in targets])
    stop_gracefully([cname(l["key"]) for l in targets])
    state = load_state()
    st = load_settings()
    cr = load_creds()
    for l in targets:                 # only what the cap allowed, never the raw request
        k = l["key"]
        proto = l.get("protocol", "ikev2-cert")
        port = state.get(k, {}).get("port") or next_port(state)
        state[k] = {"port": port, "country": l["country"], "city": l["city"],
                    "name": l.get("countryName", l.get("provider", "")),
                    "provider": l.get("provider", "hma"), "protocol": proto,
                    "fqdn": l.get("fqdn"), "config": l.get("config"),
                    **{x: state.get(k, {})[x] for x in ("rotate_minutes", "last_rotate")
                       if x in state.get(k, {})}}
        args = ["run", "-d", "--name", cname(k), "--restart", "unless-stopped",
                "--cap-add", "NET_ADMIN",
                "-e", f"PROTOCOL={proto}", "-e", f"STATUS_KEY={k}",
                "-e", f"PROXY_USER={cr['user']}", "-e", f"PROXY_PASS={cr['pass']}",
                "-e", f"MTU={st['mtu']}", "-e", f"TUNNEL_DNS={st['dns']}",
                "-e", f"WATCHDOG_INTERVAL={st['watchdog_interval']}",
                "-e", f"WATCHDOG_FAILS={st['watchdog_fails']}",
                "-v", f"{STATUS_DIR_HOST}:/status",
                "-p", f"{st['bind']}:{port}:1080",
                "--label", "proxy-farm.port=1", "--label", f"proxy-farm.key={k}"]
        if COMPOSE_PROJECT:   # group the ports under the compose project in Docker Desktop
            args += ["--label", f"com.docker.compose.project={COMPOSE_PROJECT}",
                     "--label", "com.docker.compose.service=port",
                     "--label", "com.docker.compose.oneoff=False"]
        if proto in ("wireguard", "openvpn"):
            args += ["-e", f"CONFIG=/config/{l['config']}",
                     "-v", f"{CONFIG_DIR_HOST}:/config:ro"]
            if proto == "openvpn" and has_account(l.get("provider")):
                args += ["-v", f"{auth_file(l.get('provider'), host=True)}:/auth/ovpn.auth:ro",
                         "-e", "OVPN_AUTH_FILE=/auth/ovpn.auth"]
            else:
                for env in ("OVPN_USER", "OVPN_PASS"):
                    if os.environ.get(env): args += ["-e", f"{env}={os.environ[env]}"]
        else:  # ikev2-cert / ikev2-eap
            args += ["-e", f"SERVER={l['fqdn']}", "-v", f"{SECRETS}:/secrets:ro"]
            for env, field in (("EAP_USER", "eap_user"), ("EAP_PASS", "eap_pass"),
                               ("SERVER_ID", "server_id")):
                v = l.get(field) or os.environ.get(env)
                if v: args += ["-e", f"{env}={v}"]
            if l.get("ca"): args += ["-e", f"EAP_CA=/secrets/{l['ca']}"]
        docker("rm", "-f", cname(k), check=False)   # already stopped gracefully above
        docker(*args, IMAGE)
        save_state(state)
        print(f"up  {k:28} :{port}  ({proto}  {l['country']} / {l['city']})")
    return {"started": [l["key"] for l in targets], "refused": refused}

def _asset_lookup(assets):
    """assets: a directory to read siblings from, or {filename: bytes}. Only plain file
    names are honoured — a config cannot make us read /etc/shadow via `ca ../../x`."""
    def lookup(name):
        base = os.path.basename(name.replace("\\", "/"))
        if not base or base.startswith("."): return None
        if isinstance(assets, dict):
            return assets.get(base)
        if assets and os.path.isdir(assets):
            fp = os.path.join(assets, base)
            if os.path.isfile(fp) and os.path.getsize(fp) < 1_000_000:
                return open(fp, "rb").read()
        return None
    return lookup

def save_config(filename, content, provider=None, assets=None, meta=None):
    """Store an uploaded VPN config + a sidecar describing it. Returns the new target.
    OpenVPN files that point at ca.crt / ta.key / client.key get those inlined (from
    `assets`), because the port container only ever sees this one file."""
    fn = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(filename))
    content = content.replace("\r\n", "\n")
    proto = detect_protocol(content)
    if not proto:
        raise ValueError("Không nhận ra định dạng — cần file WireGuard (.conf) hoặc OpenVPN (.ovpn)")
    if proto == "openvpn" and P.referenced_files(content):
        content, missing = P.inline_files(content, _asset_lookup(assets))
        if missing:
            raise ValueError(f"{fn} cần thêm file: {', '.join(missing)} — kéo thả chúng cùng lúc "
                             "với file .ovpn, hoặc kéo thả cả gói .zip của nhà cung cấp")
    if not fn.endswith((".conf", ".ovpn")):
        fn += ".conf" if proto == "wireguard" else ".ovpn"
    path = os.path.join(CONFIG_DIR, fn)
    with open(path, "w") as f: f.write(content)
    os.chmod(path, 0o600)
    hosts = [h for h, _, _ in P.parse_remotes(content)]
    cc, city = P.guess_location(fn, hosts)
    m = {"provider": provider or guess_provider(fn, content), "protocol": proto,
         "country": cc, "needs_auth": proto == "openvpn" and P.needs_auth(content)}
    if city: m["city"] = city
    m.update(meta or {})
    json.dump(m, open(path + ".meta.json", "w"))
    return next(t for t in config_targets() if t["config"] == fn)

def write_items(items, replace_provider=None, replace_protocol=None):
    """Write importer output as ordinary configs. Re-importing a provider replaces its old
    generated files, except ones a port still uses (their key must keep working)."""
    keep = {v.get("config") for v in load_state().values()}
    names = set()
    for it in items:
        save_config(it["name"], it["content"], meta=it["meta"])
        names.add(re.sub(r"[^A-Za-z0-9._-]", "_", it["name"]))
    if replace_provider:
        for t in config_targets():
            if t["provider"] == replace_provider and t["config"] not in names and \
               t["config"] not in keep and (not replace_protocol or t["protocol"] == replace_protocol):
                meta_p = os.path.join(CONFIG_DIR, t["config"] + ".meta.json")
                try: generated = json.load(open(meta_p)).get("preset")
                except Exception: generated = None
                if generated:              # never touch files the user dropped in by hand
                    for f in (t["config"], t["config"] + ".meta.json"):
                        try: os.remove(os.path.join(CONFIG_DIR, f))
                        except OSError: pass
    return len(items)

def save_bundle(filename, data, provider=None):
    """A provider's zip of .ovpn files (+ ca.crt/ta.key): one location per city."""
    items = P.import_zip_bundle(data, provider)
    if not items: raise ValueError("Không có cấu hình nào trong zip")
    for it in items: it["meta"].pop("preset", None)     # user-supplied: never auto-pruned
    write_items(items)
    return items

def import_preset(pid, proto=None, data=None):
    """Fetch a provider's public server list and create its locations. data carries the
    account: user/pass (OpenVPN, IKEv2), wg_key/wg_address or wg_conf (WireGuard),
    template (Windscribe), per_city."""
    data = data or {}
    pre = P.preset(pid)
    if not pre: raise ValueError(f"Không biết nhà cung cấp '{pid}'")
    protos = [k for k, v in pre["protocols"].items() if v.get("how") in ("import", "template")]
    proto = proto or (protos[0] if protos else None)
    name, s = P.importer_for(pid, proto)
    if not name:
        raise ValueError(f"{pre['name']} / {proto}: không tự nạp được — "
                         + ((s or {}).get("note") or "tải file cấu hình từ trang tài khoản rồi kéo thả"))
    acct = {"pid": pre["id"], "template": data.get("template"), "wg_key": data.get("wg_key"),
            "wg_address": data.get("wg_address"), "wg_dns": data.get("wg_dns")}
    if data.get("wg_conf"):           # one downloaded .conf carries key + address
        ident = P.wg_identity(data["wg_conf"])
        acct.update(wg_key=acct["wg_key"] or ident["private_key"],
                    wg_address=acct["wg_address"] or ident["address"])
    user, pw = (data.get("user") or "").strip(), data.get("pass") or ""
    if proto in ("openvpn", "ikev2") and not (user and pw) and not has_account(pre["id"]):
        raise ValueError("Cần tên đăng nhập và mật khẩu dịch vụ — " + pre.get("credentials", ""))
    items, eaps, ca_pem = P.run_importer(name, s, acct, data.get("per_city") or 1)
    if proto == "openvpn" and user and pw:
        set_account(pre["id"], user, pw)
    if items:
        write_items(items, replace_provider=pre["id"], replace_protocol=proto)
    if eaps:
        if not (user and pw):          # reuse the stored OpenVPN account for IKEv2
            u, pw = open(auth_file(pre["id"])).read().split("\n")[:2]
            user = u
        ca = save_ca(pre["id"], ca_pem.encode()) if ca_pem else None
        prov = load_providers(); keep = set(load_state())
        prov["eap"] = [e for e in prov.get("eap", []) if e.get("name") != pre["id"]
                       or "EAP-" + e["id"] in keep]
        save_providers(prov)
        for e in eaps:
            add_eap({**e, "name": pre["id"], "user": user, "pass": pw, "ca_file": ca})
    return {"provider": pre["id"], "protocol": proto, "locations": len(items) + len(eaps)}

def delete_config(key):
    t = targets_index().get(key)
    if not t or not t.get("config"): return
    down([key])
    for p in (os.path.join(CONFIG_DIR, t["config"]),
              os.path.join(CONFIG_DIR, t["config"] + ".meta.json")):
        try: os.remove(p)
        except OSError: pass

def down(keys):
    """Delete: remove the container and drop the port assignment."""
    state = load_state()
    # No keys = every port in state. Fall back to the stored record for a target whose
    # source is gone (config deleted), so its container still gets removed.
    idx = targets_index()
    targets = (resolve_targets(keys) if keys else
               [idx.get(k, {**v, "key": k}) for k, v in list(state.items())])
    stop_gracefully([cname(l["key"]) for l in targets])   # send IKE DELETE first
    for l in targets:
        k = l["key"]
        docker("rm", "-f", cname(k), check=False)
        state.pop(k, None); save_state(state)
        try: os.remove(os.path.join(STATUS_DIR, k + ".json"))
        except OSError: pass
        print("down", k)

def stop(keys):
    """Switch off: close the session, remove the container, keep the port number.
    Start builds a fresh container from the current image, so a stopped port never
    lingers as a stale container running yesterday's code."""
    targets = resolve_targets(keys) or []
    names = [cname(l["key"]) for l in targets]
    for n in names: docker("update", "--restart", "no", n, check=False)
    stop_gracefully(names)
    for l in targets:
        k = l["key"]
        docker("rm", "-f", cname(k), check=False)
        for suffix in (".json", ".wait.json"):
            try: os.remove(os.path.join(STATUS_DIR, k + suffix))
            except OSError: pass
        print("stop", k)

def start(keys):
    allowed, refused = over_quota(resolve_targets(keys) or [])
    clear_failed([l["key"] for l in allowed])
    run = running_containers()
    # Stopped ports have no container any more: build them fresh, in one batch.
    todo = [l["key"] for l in allowed
            if (run.get(l["key"]) or {}).get("state") not in ("running", "restarting")]
    for k in todo: reset_backoff(k)
    if todo: up(todo)
    return {"started": [l["key"] for l in allowed], "refused": refused}

def rotate(keys):
    clear_failed([l["key"] for l in resolve_targets(keys)])
    state = load_state()
    for l in resolve_targets(keys):
        k = l["key"]
        reset_backoff(k)
        docker("restart", "-t", "6", cname(k), check=False)
        if k in state:
            state[k]["last_rotate"] = time.time(); save_state(state)
        try: os.remove(os.path.join(STATUS_DIR, k + ".json"))
        except OSError: pass
        print("rotate", k)

def set_autorotate(keys, minutes):
    """0 disables. Rotation happens in autorotate_loop()."""
    state = load_state()
    for l in resolve_targets(keys):
        k = l["key"]
        if k in state:
            state[k]["rotate_minutes"] = int(minutes)
            state[k].setdefault("last_rotate", time.time())
    save_state(state)
    print(f"auto-rotate = {minutes} min for {len(resolve_targets(keys))} port(s)")

def autorotate_loop():
    while True:
        try:
            state = load_state(); now = time.time()
            due = [k for k, v in state.items()
                   if v.get("rotate_minutes") and
                   now - v.get("last_rotate", 0) >= v["rotate_minutes"] * 60]
            if due:
                log_line(f"auto-rotate: {', '.join(due)}")
                rotate(due)
        except Exception:
            pass
        time.sleep(20)

def log_line(m): print(m, flush=True)

def container_logs(key, n=200):
    r = docker("logs", "--tail", str(n), cname(key), check=False)
    return (r.stdout or "") + (r.stderr or "")

def check_now(key):
    """Run the health probe inside the container right now (same path the watchdog uses)."""
    cr = load_creds()
    auth = f"{cr['user']}:{cr['pass']}@" if cr.get("user") else ""
    r = docker("exec", cname(key), "sh", "-c",
               f"curl -s -m 12 -x socks5h://{auth}127.0.0.1:1080 https://ipinfo.io/json",
               check=False)
    try:
        return {"ok": True, "info": json.loads(r.stdout)}
    except Exception:
        return {"ok": False, "error": (r.stderr or r.stdout or "no response")[:200]}

def test_port(key, speed=False):
    """What a user wants to know about a proxy: does it work, where does it come out,
    how fast. Runs inside the node so it measures the tunnel, not docker's port mapping."""
    cr = load_creds()
    px = f"socks5h://{cr['user']}:{cr['pass']}@127.0.0.1:1080"
    script = (f'P="{px}"; '
              'curl -s -m 20 -o /tmp/t.json -w "%{http_code} %{time_connect} %{time_appconnect} %{time_total}" '
              '-x "$P" https://ipinfo.io/json; echo; cat /tmp/t.json 2>/dev/null | tr -d "\n"; echo')
    if speed:
        script += ('; curl -s -m 30 -o /dev/null -w "%{http_code} %{speed_download} %{size_download}" '
                   '-x "$P" "https://speed.cloudflare.com/__down?bytes=5000000"; echo')
    r = docker("exec", cname(key), "sh", "-c", script, check=False)
    lines = (r.stdout or "").splitlines()
    out = {"key": key, "ok": False}
    try:
        code, tc, ta, tt = lines[0].split()
        out.update(http=int(code), connect_ms=int(float(tc)*1000),
                   tls_ms=int(float(ta)*1000), total_ms=int(float(tt)*1000))
        if code == "200":
            info = json.loads(lines[1])
            out.update(ok=True, ip=info.get("ip"), city=info.get("city"),
                       region=info.get("region"), country=info.get("country"),
                       org=info.get("org"), timezone=info.get("timezone"))
    except Exception:
        out["error"] = ((r.stderr or r.stdout or "không có phản hồi").strip().splitlines() or [""])[-1][:160]
    if speed and len(lines) >= 3:
        try:
            code, sp, size = lines[2].split()
            if code == "200" and int(float(size)) > 0:
                out["mbps"] = round(float(sp) * 8 / 1e6, 1)
        except Exception: pass
    t = targets_index().get(key) or {}
    out["expected_country"] = t.get("country")
    out["geo_match"] = bool(out.get("country")) and out.get("country") == t.get("country")
    return out

# --- live status ------------------------------------------------------------
def read_wait(key):
    try:
        d = json.load(open(os.path.join(STATUS_DIR, key + ".wait.json")))
        return d if d.get("until", 0) > time.time() else None
    except Exception:
        return None

def read_phase(key):
    """Which step a port that is still connecting is in (written by the node)."""
    try: return json.load(open(os.path.join(STATUS_DIR, key + ".phase.json")))
    except Exception: return None

def read_status(key):
    # Each tunnel container writes /status/<key>.json from inside its own netns (the reliable
    # path). We just read + freshness-check it; no cross-container network probing.
    try:
        d = json.load(open(os.path.join(STATUS_DIR, key + ".json")))
        if time.time() - d.get("ts", 0) > 60:
            return {"ip": None, "ok": False, "latency": None}
        info = d.get("info", {})
        return {"ip": info.get("ip"), "country": info.get("country"),
                "city": info.get("city"), "ok": True, "latency": d.get("latency")}
    except Exception:
        return {"ip": None, "ok": False, "latency": None}

FAIL_REASONS = (
    ("không gửi dữ liệu về",          "gateway bắt tay xong nhưng không gửi dữ liệu về"),
    ("IKE_SA_INIT_I: retransmission", "gateway không trả lời (IKE_SA_INIT)"),
    ("authentication failed",          "gateway từ chối chứng chỉ"),
    ("no connection is known",         "cấu hình tunnel sai"),
    ("FATAL:",                         "container không khởi động được"),
    ("Handshake did not complete",     "WireGuard không bắt tay được"),
    ("AUTH_FAILED",                    "sai tài khoản"),
    ("AUTH_MISSING",                   "chưa nhập tài khoản OpenVPN cho nhà cung cấp này"),
    ("EAP_FAILURE",                    "sai tài khoản IKEv2"),
    ("constraint check failed",        "không tin được chứng chỉ máy chủ (CA / ID máy chủ)"),
    ("no trusted RSA public key",      "không tin được chứng chỉ máy chủ (CA / ID máy chủ)"),
    ("Options error",                  "file .ovpn có tuỳ chọn OpenVPN không hỗ trợ"),
    ("TLS key negotiation failed",     "máy chủ OpenVPN không trả lời"),
)

def fail_reason(key):
    """A short, human reason pulled from the container's own log."""
    log = container_logs(key, 2000)
    for needle, why in FAIL_REASONS:
        if needle in log: return why
    return "tunnel không lên được"

def give_up(key, state=None):
    """Stop a port that keeps restarting without ever coming up. Docker would otherwise
    retry for ever, which burns CPU and shows a permanent 'connecting' that never ends."""
    state = state if state is not None else load_state()
    if key not in state: return
    why = fail_reason(key)
    docker("update", "--restart", "no", cname(key), check=False)
    docker("stop", "-t", "3", cname(key), check=False)
    try: os.remove(os.path.join(STATUS_DIR, key + ".json"))
    except OSError: pass
    state[key]["failed"] = {"at": int(time.time()), "why": why}
    save_state(state)
    print(f"give-up {key}: {why}", flush=True)

def reset_backoff(key):
    """A user asking for a retry means *now*, not after the node's back-off timer. The
    marker goes through the shared status dir because the node's own /run is out of
    reach while it is stopped; the node consumes it on its next start."""
    open(os.path.join(STATUS_DIR, key + ".now"), "w").close()
    try: os.remove(os.path.join(STATUS_DIR, key + ".wait.json"))
    except OSError: pass

def stop_gracefully(names, timeout=6):
    """SIGTERM so the node sends IKE DELETE; in parallel, because doing fifty in a row
    with a per-container grace period would take minutes."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(lambda n: docker("stop", "-t", str(timeout), n, check=False), names))

def clear_failed(keys):
    state = load_state(); touched = False
    for k in keys:
        if state.get(k, {}).pop("failed", None): touched = True
    if touched: save_state(state)

def supervisor_loop():
    while True:
        time.sleep(30)
        try:
            limit = load_settings()["give_up_after"]
            if limit <= 0: continue
            state = load_state(); run = running_containers()
            for k, v in list(state.items()):
                if v.get("failed"): continue
                info = run.get(k) or {}
                if info.get("state") != "running": continue
                try: n = int(info.get("restarts") or 0)
                except ValueError: continue
                # Restarting that often while never writing a status file means it has
                # never once carried traffic — not a blip.
                if n >= limit and not read_status(k).get("ok"):
                    give_up(k, state)
        except Exception as e:
            print("supervisor:", e, flush=True)

def running_containers():
    out = docker("ps", "-a", "--filter", "label=proxy-farm.port=1",
                 "--format", "{{.Label \"proxy-farm.key\"}}\t{{.State}}\t{{.Names}}",
                 check=False)
    r = {}
    for line in out.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            rc = docker("inspect", "-f", "{{.RestartCount}}", parts[2],
                        check=False).stdout.strip()
            r[parts[0]] = {"state": parts[1], "restarts": rc or "?"}
    return r

def ls(as_json=False):
    state = load_state(); run = running_containers(); idx = targets_index()
    rows = []
    for k, v in sorted(state.items()):
        st = run.get(k, {}).get("state", "gone")
        s = read_status(k) if st == "running" else {}
        # Display fields come from the live target, not the port's frozen state: editing a
        # config's metadata should re-label the row without having to recreate the port.
        t = idx.get(k, v)
        rows.append({"key": k, "port": v["port"],
                     "name": t.get("countryName") or v["name"],
                     "city": t.get("city") or v["city"],
                     "country": t.get("country") or v["country"],
                     "state": st, "ip": s.get("ip"), "ok": s.get("ok"),
                     "latency": s.get("latency"),
                     "rotate_minutes": v.get("rotate_minutes", 0),
                     "provider": t.get("provider", v.get("provider", "hma")),
                     "protocol": t.get("protocol", v.get("protocol", "ikev2-cert")),
                     "failed": v.get("failed"),
                     "wait": read_wait(k) if st == "running" and not s.get("ok") else None,
                     "phase": read_phase(k) if st == "running" and not s.get("ok") else None,
                     "restarts": run.get(k, {}).get("restarts")})
    if as_json: return rows
    for r in rows:
        print(f"{r['key']:26} :{r['port']}  {r['state']:8} "
              f"{(r['ip'] or '-'):16} {r['country']} / {r['city']}")
    return rows

# --- web UI -----------------------------------------------------------------
UI_FILE = os.path.join(HERE, "ui.html")
_ui_cache = {"mtime": 0, "html": ""}
def ui_html():
    """Re-read when the file changes, so editing ui.html needs no restart."""
    m = os.path.getmtime(UI_FILE)
    if m != _ui_cache["mtime"]:
        with open(UI_FILE, encoding="utf-8") as f:
            _ui_cache.update(mtime=m, html=f.read())
    return _ui_cache["html"]

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        # Everything here is live state; a cached page shows a stale farm (and, after an
        # upgrade, a UI missing the features the user just installed).
        if not ctype.startswith("image/"):
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b))); self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p in ("/", "/index.html"): return self._send(200, ui_html(), "text/html; charset=utf-8")
        if p == "/api/locations":
            return self._send(200, json.dumps({"locations": all_targets()}))
        if p == "/api/status":
            c = load_creds()
            return self._send(200, json.dumps({
                "rows": ls(as_json=True), "bind": load_settings()["bind"],
                "auth": {"user": c["user"], "pass": c["pass"]},
                "rotate_key": rotate_key()}))
        if p == "/api/discover":
            return self._send(200, json.dumps(
                {"found": discover(), "scan": os.environ.get("PF_SCAN_HOST", SCAN_DIR),
                 "inbox": os.environ.get("PF_INBOX_HOST", INBOX)}))
        if p == "/api/providers":
            return self._send(200, json.dumps({"providers": providers_list()}))
        if p == "/api/presets":
            return self._send(200, json.dumps({"presets": presets_list()}))
        if p == "/api/settings":
            st = load_settings()
            return self._send(200, json.dumps({
                "settings": {k: st[k] for k in SETTABLE},
                "rotate_key": st["rotate_key"],
                "paths": {"secrets": SECRETS, "configs": CONFIG_DIR_HOST,
                          "status": STATUS_DIR_HOST, "state": STATE_FILE},
                "running": len(load_state())}))
        if p == "/api/logs":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            k = q.get("key", [""])[0]
            if k not in load_state(): return self._send(404, json.dumps({"error": "unknown port"}))
            return self._send(200, json.dumps({"key": k, "log": container_logs(k, int(q.get("n", ["300"])[0]))}))
        # Webhook: GET /api/rotate?key=<rotate_key>&port=29001  (or &all=1) — for automation
        if p == "/api/rotate":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("key", [""])[0] != rotate_key():
                return self._send(403, json.dumps({"error": "bad key"}))
            state = load_state()
            if q.get("all", [""])[0] in ("1", "true", "yes"):
                targets = list(state)
            else:
                port = q.get("port", [""])[0]
                targets = [k for k, v in state.items() if str(v["port"]) == str(port)]
            if not targets: return self._send(404, json.dumps({"error": "no matching port"}))
            rotate(targets)
            return self._send(200, json.dumps({"rotated": targets}))
        if p.startswith("/flags/"):
            fn = os.path.basename(p)
            fp = os.path.join(FLAGS_DIR, fn)
            if fn.endswith(".png") and os.path.isfile(fp):
                self.send_response(200); self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "max-age=86400")
                b = open(fp, "rb").read(); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b); return
            return self._send(404, "{}")
        return self._send(404, "{}")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n) or "{}")
        p = urllib.parse.urlparse(self.path).path
        keys = data.get("keys", [])
        if keys == "*": keys = list(load_state().keys())
        if p == "/api/up":
            return self._send(200, json.dumps({"ok": True, **up(keys)}))
        elif p == "/api/down": down(keys if keys else [])
        elif p == "/api/rotate": rotate(keys)
        elif p == "/api/stop": stop(keys)
        elif p == "/api/start":
            return self._send(200, json.dumps({"ok": True, **start(keys)}))
        elif p == "/api/autorotate": set_autorotate(keys, data.get("minutes", 0))
        elif p == "/api/upload":
            if "files" in data:          # a batch: configs, zips and the ca/key files they use
                return self._send(200, json.dumps({"ok": True, **upload_batch(data["files"],
                                                                             data.get("provider"))}))
            try:
                t = save_config(data.get("name", "config"), data.get("content", ""),
                                data.get("provider"))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
            return self._send(200, json.dumps({"ok": True, "target": t}))
        elif p == "/api/preset/import":
            try: r = import_preset(data.get("id"), data.get("protocol"), data)
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
            return self._send(200, json.dumps({"ok": True, **r}))
        elif p == "/api/provider/auth":
            try:
                if data.get("delete"): delete_account(data.get("provider"))
                else: set_account(data.get("provider"), data.get("user"), data.get("pass"))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
        elif p == "/api/delete-config":
            for k in keys: delete_config(k)
        elif p == "/api/settings":
            st = load_settings()
            changed = {k: v for k, v in (data.get("settings") or {}).items()
                       if k in SETTABLE and v not in ("", None) and v != st[k]}
            for k in ("base_port", "mtu", "watchdog_interval", "watchdog_fails"):
                if k in changed:
                    try: changed[k] = int(changed[k])
                    except ValueError: return self._send(400, json.dumps(
                        {"error": f"{k} phải là số"}))
            if data.get("new_rotate_key"):
                import secrets as _s
                changed["rotate_key"] = _s.token_urlsafe(16)
            st.update(changed); save_settings(st)
            # bind/creds/mtu/watchdog live in each container's `docker run` flags, so they
            # only take effect once the ports are recreated. Say so rather than lying.
            # base_port only affects ports created later; rotate_key lives in the manager
            # alone. Neither is baked into a running container, so neither needs a restart.
            needs = [k for k in changed if k not in
                     ("base_port", "rotate_key", "give_up_after")]
            restarted = []
            if needs and data.get("restart"):
                # Only ports that are on: recreating a stopped one would switch it on
                # behind the user's back (and could push a provider over its cap).
                run = running_containers()
                restarted = [k for k in load_state()
                             if (run.get(k) or {}).get("state") in ("running", "restarting")]
                up(restarted)
            return self._send(200, json.dumps(
                {"ok": True, "changed": sorted(changed), "restarted": len(restarted),
                 "needs_restart": bool(needs) and not data.get("restart")}))
        elif p == "/api/provider/hma":
            try:
                st = import_hma(token_text=data.get("token"), p12_b64=data.get("p12"),
                                password=data.get("password"))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
            return self._send(200, json.dumps({"ok": True, "status": st}))
        elif p == "/api/discover":
            names = import_found(data.get("paths", []))
            return self._send(200, json.dumps({"ok": True, "imported": names}))
        elif p == "/api/provider/eap":
            try: t = add_eap(data)
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
            return self._send(200, json.dumps({"ok": True, "target": t}))
        elif p == "/api/provider/delete":
            try: delete_provider(data.get("id", ""))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
        elif p == "/api/limit":
            try: set_limit(str(data.get("provider", "")).lower(), data.get("limit", 0))
            except (TypeError, ValueError):
                return self._send(400, json.dumps({"error": "giới hạn phải là số"}))
        elif p == "/api/test":
            from concurrent.futures import ThreadPoolExecutor
            ks = [k for k in keys if k in load_state()][:20]
            with ThreadPoolExecutor(max_workers=6) as ex:
                res = list(ex.map(lambda k: test_port(k, bool(data.get("speed"))), ks))
            return self._send(200, json.dumps({"results": res}))
        elif p == "/api/check":
            return self._send(200, json.dumps({k: check_now(k) for k in keys[:8]}))
        else: return self._send(404, "{}")
        return self._send(200, json.dumps({"ok": True}))

def serve():
    ingest_inbox()
    threading.Thread(target=inbox_loop, daemon=True).start()
    threading.Thread(target=autorotate_loop, daemon=True).start()
    threading.Thread(target=supervisor_loop, daemon=True).start()
    httpd = http.server.ThreadingHTTPServer((UI_BIND, UI_PORT), H)
    print(f"Proxy farm UI on http://{UI_BIND}:{UI_PORT}  (proxies bind {BIND}, image {IMAGE})", flush=True)
    httpd.serve_forever()

# --- CLI helpers -------------------------------------------------------------
def _ask(prompt, secret=False, env=None):
    """Value from the environment (PF_USER, PF_PASS, …) or an interactive prompt, so the
    same commands work in scripts and in `docker exec -it`."""
    if env and os.environ.get(env): return os.environ[env]
    if secret:
        import getpass
        return getpass.getpass(prompt)
    return input(prompt)

def cli_presets():
    for p in presets_list():
        protos = ", ".join(f"{x['protocol']}:{x['how']}" for x in p["protocols"]) or "-"
        acct = " [đã có tài khoản]" if p["has_account"] else ""
        print(f"{p['id']:14} {p['name']:26} {protos}{acct}")
        if p["unsupported"]: print(f"{'':14} không hỗ trợ: {p['unsupported']}")
    print("\nimport: farm.py import <id> [openvpn|wireguard|ikev2] [số máy chủ mỗi thành phố]")

def cli_import(a):
    if not a: return print("import <PRESET> [openvpn|wireguard|ikev2] [per-city]")
    pre = P.preset(a[0])
    if not pre: return print(f"không biết '{a[0]}' — xem: farm.py presets")
    proto = a[1] if len(a) > 1 and not a[1].isdigit() else None
    per_city = next((int(x) for x in a[1:] if x.isdigit()), 1)
    name, s = P.importer_for(pre["id"], proto or next(
        (k for k, v in pre["protocols"].items() if v.get("how") in ("import", "template")), ""))
    proto = proto or next((k for k, v in pre["protocols"].items()
                           if v.get("how") in ("import", "template")), None)
    if not name:
        return print(f"{pre['name']}{(' / ' + proto) if proto else ''}: không tự nạp được — "
                     f"{(s or {}).get('note') or pre.get('unsupported') or 'tải file cấu hình từ trang tài khoản rồi dùng: farm.py add <file…>'}\n"
                     f"{pre.get('credentials', '')}")
    print(pre.get("credentials", ""))
    d = {"per_city": per_city}
    if proto in ("openvpn", "ikev2") and not has_account(pre["id"]):
        d["user"] = _ask("Tên đăng nhập dịch vụ: ", env="PF_USER")
        d["pass"] = _ask("Mật khẩu dịch vụ: ", True, env="PF_PASS")
    if proto == "wireguard":
        d["wg_key"] = _ask("WireGuard private key: ", True, env="PF_WG_KEY")
        dflt = s.get("default_address", "")
        d["wg_address"] = _ask(f"Địa chỉ (Address) [{dflt}]: ", env="PF_WG_ADDRESS") or dflt
    if name == "windscribe":
        d["template"] = open(_ask("Đường dẫn file .ovpn mẫu: ", env="PF_TEMPLATE")).read()
    r = import_preset(pre["id"], proto, d)
    print(f"đã nạp {r['locations']} vị trí {pre['name']} ({proto}). Bật bằng: farm.py up <KEY|mã nước>")

def cli_auth(a):
    if not a: return print("auth <PROVIDER> [USER]   (mật khẩu hỏi riêng, hoặc PF_PASS)")
    user = a[1] if len(a) > 1 else _ask("Tên đăng nhập: ", env="PF_USER")
    r = set_account(a[0], user, _ask("Mật khẩu: ", True, env="PF_PASS"))
    print(f"đã lưu tài khoản OpenVPN cho {r['provider']} ({r['user']})")

def cli_add(paths):
    files = []
    for fp in paths:
        files.append({"name": os.path.basename(fp), "b64": base64.b64encode(open(fp, "rb").read()).decode()})
        # ca.crt / ta.key next to a config come along automatically
        d = os.path.dirname(os.path.abspath(fp))
        for fn in os.listdir(d):
            if fn.lower().endswith((".crt", ".key", ".pem")) and fn not in [f["name"] for f in files]:
                files.append({"name": fn, "b64": base64.b64encode(open(os.path.join(d, fn), "rb").read()).decode()})
    r = upload_batch(files)
    for n in r["imported"]: print("nạp", n)
    for e in r["errors"]: print("lỗi", e)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    a = sys.argv[2:]
    {"serve": lambda: serve(), "up": lambda: up(a), "down": lambda: down(a),
     "ls": lambda: ls(), "rotate": lambda: rotate(a),
     "stop": lambda: stop(a), "start": lambda: start(a),
     "logs": lambda: print(container_logs(a[0])) if a else print("logs <KEY>"),
     "autorotate": lambda: set_autorotate(a[:-1], a[-1]) if len(a) > 1 else print("autorotate <KEY..> <minutes>"),
     "presets": cli_presets, "import": lambda: cli_import(a), "auth": lambda: cli_auth(a),
     "add": lambda: cli_add(a),
     }.get(cmd, lambda: print(__doc__))()
