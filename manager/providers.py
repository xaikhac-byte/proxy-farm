"""
Provider layer for the Proxy Farm manager: everything that turns "a VPN account" into
config files, independent of Docker.

  * presets.json — the registry: which protocols each provider offers, where the user gets
    manual credentials, and which importer (if any) can fetch its server list.
  * OpenVPN helpers — parse remotes, inline referenced ca/cert/key/tls-auth files, merge
    many per-server files into one per-city file.
  * Importers — fetch a provider's PUBLIC server list (no login) and produce
    [{"name", "content", "meta"}] items; farm.py writes them as ordinary configs.

Only stdlib, so the manager image stays python:alpine + nothing.
"""
import base64, io, json, os, re, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "proxy-farm (+https://github.com/huuhoa143/proxy-farm)"

# ---- registry ------------------------------------------------------------------
def load_presets(path=None):
    with open(path or os.path.join(HERE, "presets.json"), encoding="utf-8") as f:
        return json.load(f)["presets"]

PRESETS = load_presets()
PRESET_BY_ID = {p["id"]: p for p in PRESETS}

def preset(pid):
    return PRESET_BY_ID.get((pid or "").lower())

def default_limits():
    return {p["id"]: int(p.get("max_connections") or 0) for p in PRESETS}

def importer_for(pid, proto):
    """(importer name, protocol settings) when Proxy Farm can fetch this provider's
    servers itself, else (None, settings-or-None)."""
    p = preset(pid)
    s = (p or {}).get("protocols", {}).get(proto)
    if not s: return None, None
    return (s.get("importer") if s.get("how") in ("import", "template") else None), s

def provider_from_hosts(hosts):
    """Provider id from the servers a config points at: 'uk765.nordvpn.com' -> nordvpn.
    Far more reliable than the filename, which users rename."""
    for h in hosts:
        h = h.lower().rstrip(".")
        for p in PRESETS:
            for d in p.get("domains", []):
                if h == d or h.endswith("." + d):
                    return p["id"]
    return None

# ---- countries -----------------------------------------------------------------
with open(os.path.join(HERE, "countries.json"), encoding="utf-8") as f:
    COUNTRIES = json.load(f)                                   # "VN" -> "Vietnam"

def _norm(s): return re.sub(r"[^a-z]", "", s.lower())

_NAME_TO_CC = {_norm(v): k for k, v in COUNTRIES.items()}
_NAME_TO_CC.update({
    "uk": "GB", "england": "GB", "scotland": "GB", "britain": "GB", "greatbritain": "GB",
    "usa": "US", "unitedstatesofamerica": "US", "america": "US", "uae": "AE",
    "korea": "KR", "southkorea": "KR", "czech": "CZ", "czechia": "CZ", "holland": "NL",
    "bosnia": "BA", "macedonia": "MK", "northmacedonia": "MK", "russianfederation": "RU",
    "vietnam": "VN", "hongkong": "HK", "turkiye": "TR", "ivorycoast": "CI",
    "capeverde": "CV", "srilanka": "LK", "newzealand": "NZ", "southafrica": "ZA",
    "costarica": "CR", "saudiarabia": "SA", "isleofman": "IM", "taiwan": "TW",
    "elsalvador": "SV", "macao": "MO", "puertorico": "PR", "dominicanrepublic": "DO",
})
# Two-letter tokens that are ISO codes in filenames. "uk" is not ISO but every provider
# uses it for Great Britain.
_CC_ALIAS = {"UK": "GB", "EL": "GR"}
# Tokens that never name a place.
_NOISE = {"udp", "tcp", "ovpn", "conf", "openvpn", "wireguard", "wg", "vpn", "prod", "com",
          "net", "org", "server", "servers", "config", "default", "stream", "streaming",
          "optimized", "virtual", "p2p", "secure", "core", "free", "st", "pf", "gw",
          "client", "the"}

def country_name(cc):
    return COUNTRIES.get((cc or "").upper(), "")

def cc_from_token(tok):
    t = tok.upper()
    t = _CC_ALIAS.get(t, t)
    return t if len(t) == 2 and t in COUNTRIES else None

def guess_location(name, hosts=(), providers=()):
    """(country code, city) from a filename such as 'mullvad-se-got.conf',
    'TorGuard.USA-NEW-YORK.ovpn', 'us_new_york.ovpn', 'United_Kingdom-London.ovpn', or
    failing that from a server name like 'us-nyc.prod.surfshark.com'. ('XX', '') if
    nothing matches."""
    stem = os.path.basename(name)
    stem = re.sub(r"\.(ovpn|conf|txt)$", "", stem, flags=re.I)
    skip = {_norm(p) for p in providers} | {p["id"] for p in PRESETS} | \
           {_norm(p["name"]) for p in PRESETS} | \
           {re.sub(r"vpn$", "", p["id"]) for p in PRESETS if len(p["id"]) > 5}
    toks = [t for t in re.split(r"[^A-Za-z]+", stem) if t]
    toks = [t for t in toks if t.lower() not in _NOISE and _norm(t) not in skip]
    cc, used = None, set()
    # 1. an explicit upper-case code: 'ipvanish-AD-Andorra-la-Vella', 'TorGuard.UK.London'
    for i, t in enumerate(toks):
        if len(t) == 2 and t.isupper() and cc_from_token(t):
            cc, used = cc_from_token(t), {i}; break
    # 2. the longest run of tokens spelling a country: 'United_Kingdom', 'USA-NEW-YORK'
    if not cc:
        for size in (4, 3, 2, 1):
            for i in range(len(toks) - size + 1):
                joined = _norm("".join(toks[i:i + size]))
                if len(joined) > 2 and joined in _NAME_TO_CC:
                    cc, used = _NAME_TO_CC[joined], set(range(i, i + size)); break
            if cc: break
    # 3. any two-letter code: 'mullvad-se-got', 'us_new_york'
    if not cc:
        for i, t in enumerate(toks):
            if len(t) == 2 and cc_from_token(t):
                cc, used = cc_from_token(t), {i}; break
    # 4. the server name: 'us-nyc.prod.surfshark.com', 'uk765.nordvpn.com'
    if not cc:
        for h in hosts:
            first = re.split(r"[^A-Za-z0-9]+", h.lower())[0] if h else ""
            m = re.match(r"([a-z]{2})(?:\d|$)", first)
            if m and cc_from_token(m.group(1)):
                cc = cc_from_token(m.group(1)); break
    rest = [(i, t) for i, t in enumerate(toks)
            if i not in used and len(t) >= 2 and not (len(t) == 2 and t.isupper())]
    # In a mixed-case name, lower-case tokens after the last capitalised word are server
    # codes ('UK-London-lon-b23'); 'Andorra-la-Vella' keeps its 'la'.
    if any(t[:1].isupper() and not t.isupper() for t in toks):
        last = max((i for i, t in rest if t[:1].isupper()), default=-1)
        rest = [(i, t) for i, t in rest if not (t.islower() and i > last)]
    city = " ".join(t.capitalize() if t.isupper() or t.islower() else t for _, t in rest)
    if not city and cc: city = country_name(cc)
    return (cc or "XX"), city

# ---- OpenVPN -------------------------------------------------------------------
_REMOTE = re.compile(r"^[ \t]*remote[ \t]+(\S+)(?:[ \t]+(\d+))?(?:[ \t]+(\S+))?", re.M)
_FILE_DIRECTIVES = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2",
                    "extra-certs", "dh", "secret", "crl-verify", "pkcs12")

def parse_remotes(text):
    """[(host, port, proto)] for every `remote` line; port/proto default from the
    file's own `port`/`proto` lines."""
    t = text.replace("\r", "")
    dport = (re.search(r"^[ \t]*r?port[ \t]+(\d+)", t, re.M) or [None, "1194"])[1]
    dproto = (re.search(r"^[ \t]*proto[ \t]+(\S+)", t, re.M) or [None, "udp"])[1]
    out = []
    for host, port, proto in _REMOTE.findall(t):
        out.append((host, int(port or dport), (proto or dproto).lower()))
    return out

def detect_protocol(text):
    if "[Interface]" in text and "PrivateKey" in text: return "wireguard"
    if re.search(r"^\s*remote\s+\S+", text, re.M): return "openvpn"
    return None

def needs_auth(text):
    """True when the config asks for a username/password at connect time. A filled
    inline <auth-user-pass> block brings its own."""
    t = text.replace("\r", "")
    inline = re.search(r"<auth-user-pass>\s*\S.*?</auth-user-pass>", t, re.S)
    return bool(re.search(r"^[ \t]*auth-user-pass\b", t, re.M)) and not inline

def referenced_files(text):
    """{directive: filename} for directives that point at a file instead of inlining."""
    out = {}
    for line in text.replace("\r", "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] in _FILE_DIRECTIVES and parts[1] != "[inline]":
            out.setdefault(parts[0], parts[1].strip('"\''))
    return out

def inline_files(text, lookup):
    """Replace `ca ca.crt` style references with inline <ca>…</ca> blocks so the config is
    self-contained (the container only sees the one file). lookup(filename) -> bytes|None.
    Returns (text, [missing filenames])."""
    missing, out = [], []
    for line in text.replace("\r", "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] in _FILE_DIRECTIVES and parts[1] != "[inline]":
            fn = parts[1].strip('"\'')
            data = lookup(fn)
            if data is None:
                missing.append(fn); out.append(line); continue
            if parts[0] == "pkcs12":       # binary; OpenVPN takes it inline as base64
                body = base64.encodebytes(data).decode().strip()
            else:
                body = data.decode("utf-8", "replace").replace("\r", "").strip()
            if parts[0] == "tls-auth" and len(parts) >= 3:
                out.append(f"key-direction {parts[2]}")
            out.append(f"<{parts[0]}>\n{body}\n</{parts[0]}>")
        else:
            out.append(line)
    return "\n".join(out) + "\n", missing

def _x509_name(text):
    m = re.search(r"^[ \t]*verify-x509-name[ \t]+(\S+)(?:[ \t]+(\S+))?", text, re.M)
    if not m: return None
    name = m.group(1).strip("'\"")
    if (m.group(2) or "subject") == "subject":
        cn = re.search(r"CN=([^,/]+)", name)
        name = cn.group(1) if cn else name
    return name

def crypto_signature(text):
    """What must be identical for two server files to be merged into one config."""
    t = text.replace("\r", "")
    blocks = re.findall(r"<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2|pkcs12)>(.*?)</\1>", t, re.S)
    lines = re.findall(r"^[ \t]*(?:cipher|auth|proto|dev|key-direction|tls-cipher|comp-lzo|compress)\b.*$", t, re.M)
    return hash((tuple((k, v.strip()) for k, v in blocks), tuple(sorted(l.strip() for l in lines))))

def merge_configs(texts, max_remotes=8):
    """One config for many servers of the same provider/city: the first file is the
    template, every file contributes its remotes. Per-server verify-x509-name lines become
    one `name-prefix` check on what the names share ('dal-c38.ipvanish.com' +
    'dal-a12.ipvanish.com' -> 'dal-'), so the certificate is still pinned to that pool."""
    texts = [t.replace("\r", "") for t in texts if t]
    if len(texts) == 1: return texts[0]
    remotes, seen = [], set()
    for t in texts:
        for line in re.findall(r"^[ \t]*remote[ \t]+\S+.*$", t, re.M):
            k = " ".join(line.split()[1:3])
            if k not in seen:
                seen.add(k); remotes.append(line.strip())
    remotes = remotes[:max_remotes]
    names = [_x509_name(t) for t in texts]
    tpl = re.sub(r"^[ \t]*(remote|verify-x509-name)[ \t]+.*\n?", "", texts[0], flags=re.M)
    head = "\n".join(remotes) + "\n"
    if all(names):
        pre = os.path.commonprefix(names)
        if len(pre) >= 2:
            head += f"verify-x509-name {pre} name-prefix\n"
    if not re.search(r"^[ \t]*remote-cert-tls", tpl, re.M):
        head += "remote-cert-tls server\n"
    # remotes go right after "client"/"dev" so the file still reads naturally
    m = re.search(r"^[ \t]*dev[ \t]+\S+.*\n", tpl, re.M)
    i = m.end() if m else 0
    return tpl[:i] + head + tpl[i:]

# ---- WireGuard -----------------------------------------------------------------
_B64KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")

def valid_wg_key(k):
    return bool(_B64KEY.match((k or "").strip()))

def valid_cidr4(a):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$", (a or "").strip())
    return bool(m) and all(int(x) <= 255 for x in m.groups()[:4]) and int(m.group(5)) <= 32

def wg_identity(text):
    """PrivateKey / Address / DNS / PresharedKey out of a provider's WireGuard .conf, so the
    user can drop ONE downloaded file and get every server."""
    def field(k):
        m = re.search(rf"^[ \t]*{k}[ \t]*=[ \t]*(.+?)[ \t]*$", text, re.M | re.I)
        return m.group(1) if m else ""
    addr = [a.strip() for a in field("Address").split(",") if a.strip() and ":" not in a]
    return {"private_key": field("PrivateKey"), "address": addr[0] if addr else "",
            "dns": field("DNS"), "psk": field("PresharedKey")}

def wg_conf(private_key, address, pubkey, endpoint, dns="", psk=""):
    lines = ["[Interface]", f"PrivateKey = {private_key}", f"Address = {address}"]
    if dns: lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {pubkey}"]
    if psk: lines.append(f"PresharedKey = {psk}")
    lines += ["AllowedIPs = 0.0.0.0/0", f"Endpoint = {endpoint}", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)

# ---- network -------------------------------------------------------------------
def http_get(url, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def http_json(url, timeout=90):
    return json.loads(http_get(url, timeout).decode("utf-8").split("\n\n")[0].strip()
                      if "piaservers" in url else http_get(url, timeout))

# ---- importers -----------------------------------------------------------------
# Every importer returns a list of items:
#   {"name": "nordvpn-us-new-york.ovpn", "content": "...",
#    "meta": {"provider", "protocol", "country", "city", "countryName", "needs_auth"}}
# farm.py writes them to the configs folder; from there on they are ordinary configs.

def slugify(t):
    return re.sub(r"[^a-z0-9]+", "-", (t or "").lower()).strip("-") or "x"

def _item(pid, proto, cc, city, content, suffix=""):
    # The location key comes from the file stem, so a provider's WireGuard and OpenVPN
    # files for the same city must not share one.
    ext = "-wg.conf" if proto == "wireguard" else ".ovpn"
    name = f"{pid}-{cc.lower()}-{slugify(city)}{('-' + suffix) if suffix else ''}{ext}"
    return {"name": name, "content": content,
            "meta": {"provider": pid, "protocol": proto, "country": cc, "city": city,
                     "countryName": country_name(cc) or cc,
                     "needs_auth": proto == "openvpn" and needs_auth(content),
                     "preset": pid}}

def _group(rows, per_city):
    """rows: [(cc, city, load, payload)] -> {(cc, city): [payload…]} keeping the
    `per_city` least loaded."""
    g = {}
    for cc, city, load, payload in rows:
        g.setdefault((cc, city), []).append((load if load is not None else 999, payload))
    return {k: [p for _, p in sorted(v, key=lambda x: x[0])[:max(1, per_city)]]
            for k, v in g.items()}

# --- OpenVPN bundles (zip) ---
def _enrich_map(kind):
    """host -> (cc, city) from the provider's public server list, used to name the
    locations in a zip bundle properly. Missing data just falls back to the filename."""
    out = {}
    try:
        if kind == "surfshark":
            for c in http_json("https://api.surfshark.com/v4/server/clusters/generic"):
                out[c["connectionName"].lower()] = (c["countryCode"].upper(), c.get("location", ""))
        elif kind == "pia":
            d = http_json("https://serverlist.piaservers.net/vpninfo/servers/v6")
            for r in d["regions"]:
                name = re.sub(r"^[A-Z]{2}\s+", "", r["name"])
                out[r["dns"].lower()] = (r["country"].upper(), name)
        elif kind == "ivpn":
            d = http_json("https://api.ivpn.net/v5/servers.json")
            for s in d.get("openvpn", []):
                out[s["gateway"].lower()] = (s["country_code"].upper(), s.get("city", ""))
    except Exception as e:                     # names are cosmetic; never fail the import
        print(f"enrich {kind}: {e}", flush=True)
    return out

def import_zip_bundle(data, pid=None, enrich=None, prefer="udp", max_remotes=8):
    """Every OpenVPN file in a provider's zip, with referenced ca/cert/key files inlined
    and per-server files merged into one location per (country, city)."""
    z = zipfile.ZipFile(io.BytesIO(data))
    files = {n: z.read(n) for n in z.namelist() if not n.endswith("/") and z.getinfo(n).file_size < 2_000_000}
    by_base = {}
    for n, b in files.items(): by_base.setdefault(os.path.basename(n), b)
    ovpn = [n for n in files if n.lower().endswith((".ovpn", ".conf")) and
            detect_protocol(files[n].decode("utf-8", "replace")) == "openvpn"]
    if not ovpn: raise ValueError("Không có file OpenVPN nào trong zip")
    # Prefer one transport when the bundle ships both (…_udp.ovpn / …-tcp.ovpn).
    def proto_of(n, text):
        rs = parse_remotes(text)
        return rs[0][2][:3] if rs else "udp"
    texts = {n: files[n].decode("utf-8", "replace") for n in ovpn}
    protos = {n: proto_of(n, texts[n]) for n in ovpn}
    if prefer and any(p == prefer for p in protos.values()):
        ovpn = [n for n in ovpn if protos[n] == prefer]
    enrich_map = _enrich_map(enrich) if enrich else {}
    groups, missing_all = {}, set()
    for n in sorted(ovpn):
        d = os.path.dirname(n)
        def lookup(fn, d=d):
            for k in (os.path.normpath(os.path.join(d, fn)), fn, os.path.basename(fn)):
                if k in files: return files[k]
            return by_base.get(os.path.basename(fn))
        text, missing = inline_files(texts[n], lookup)
        missing_all.update(missing)
        hosts = [h for h, _, _ in parse_remotes(text)]
        prov = pid or provider_from_hosts(hosts) or "custom"
        loc = next((enrich_map[h.lower()] for h in hosts if h.lower() in enrich_map), None)
        cc, city = loc if loc and loc[1] else guess_location(n, hosts, [prov])
        if loc and not loc[1]: cc = loc[0]
        groups.setdefault((prov, cc, city or country_name(cc) or cc), []).append(text)
    items = []
    for (prov, cc, city), texts_ in sorted(groups.items()):
        # Only files that share their keys can share one config: split on the crypto.
        by_sig = {}
        for t in texts_: by_sig.setdefault(crypto_signature(t), []).append(t)
        for i, same in enumerate(by_sig.values()):
            items.append(_item(prov, "openvpn", cc, city, merge_configs(same, max_remotes),
                               suffix=str(i + 1) if i else ""))
    if missing_all:
        print("zip: thiếu file " + ", ".join(sorted(missing_all)), flush=True)
    return items

# --- NordVPN ---
NORD_API = ("https://api.nordvpn.com/v1/servers?limit=20000"
            "&filters[servers_technologies][identifier]={tech}"
            "&fields[servers.hostname]&fields[servers.station]&fields[servers.load]"
            "&fields[servers.status]&fields[servers.locations.country.code]"
            "&fields[servers.locations.country.city.name]&fields[servers.groups.identifier]"
            "&fields[servers.technologies.identifier]&fields[servers.technologies.metadata]")
NORD_OVPN = "https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/{host}.udp.ovpn"
# Only the plain pool; obfuscated, double-VPN, onion and dedicated-IP servers need
# configs or accounts of their own.
_NORD_SKIP = {"legacy_obfuscated_servers", "legacy_double_vpn", "legacy_onion_over_vpn",
              "legacy_dedicated_ip", "anti_ddos"}

def _nord_servers(tech, servers=None):
    rows = []
    for s in servers if servers is not None else http_json(NORD_API.format(tech=tech)):
        if s.get("status") != "online": continue
        groups = {g.get("identifier") for g in s.get("groups", [])}
        if groups & _NORD_SKIP: continue
        loc = (s.get("locations") or [{}])[0].get("country", {})
        cc = (loc.get("code") or "XX").upper()
        city = (loc.get("city") or {}).get("name") or cc
        rows.append((cc, city, s.get("load"), s))
    return rows

def import_nordvpn(per_city=3, servers=None, template=None):
    rows = _nord_servers("openvpn_udp", servers)
    if not rows: raise ValueError("NordVPN không trả về máy chủ nào")
    groups = _group(rows, per_city)
    if template is None:
        first = next(iter(groups.values()))[0]["hostname"]
        template = http_get(NORD_OVPN.format(host=first)).decode()
    if "<ca>" not in template: raise ValueError("Không tải được file mẫu OpenVPN của NordVPN")
    port = (re.search(r"^remote\s+\S+\s+(\d+)", template, re.M) or [None, "1194"])[1]
    items = []
    for (cc, city), servers_ in sorted(groups.items()):
        texts = []
        for s in servers_:
            t = re.sub(r"^[ \t]*remote[ \t]+.*\n?", "", template, flags=re.M)
            t = re.sub(r"^[ \t]*verify-x509-name[ \t]+.*$", f"verify-x509-name CN={s['hostname']}", t, flags=re.M)
            texts.append(f"remote {s['station']} {port}\n" + t)
        items.append(_item("nordvpn", "openvpn", cc, city, merge_configs(texts)))
    return items

def _nord_pubkey(s):
    for t in s.get("technologies", []):
        if t.get("identifier") == "wireguard_udp":
            for m in t.get("metadata", []):
                if m.get("name") == "public_key": return m.get("value")
    return None

def import_nordvpn_wg(private_key, address="10.5.0.2/32", per_city=1, servers=None, dns=""):
    rows = [r for r in _nord_servers("wireguard_udp", servers) if _nord_pubkey(r[3])]
    items = []
    for (cc, city), servers_ in sorted(_group(rows, per_city).items()):
        for i, s in enumerate(servers_):
            items.append(_item("nordvpn", "wireguard", cc, city if i == 0 else f"{city} {i + 1}",
                               wg_conf(private_key, address, _nord_pubkey(s), f"{s['station']}:51820", dns)))
    return items

def import_nordvpn_ikev2(per_city=1, servers=None):
    """One IKEv2 entry per city (least loaded server); the farm stores them as EAP
    targets that share the account's credentials."""
    rows = _nord_servers("ikev2", servers)
    out = []
    for (cc, city), servers_ in sorted(_group(rows, per_city).items()):
        for i, s in enumerate(servers_):
            out.append({"server": s["hostname"], "server_id": s["hostname"], "country": cc,
                        "city": city if i == 0 else f"{city} {i + 1}"})
    return out

# --- Surfshark / Mullvad / IVPN WireGuard ---
def import_surfshark_wg(private_key, address="10.14.0.2/16", per_city=1, clusters=None, dns=""):
    clusters = clusters if clusters is not None else \
        http_json("https://api.surfshark.com/v4/server/clusters/generic")
    rows = [(c["countryCode"].upper(), c.get("location") or c["countryCode"], c.get("load"), c)
            for c in clusters if c.get("pubKey") and c.get("connectionName")]
    items = []
    for (cc, city), cs in sorted(_group(rows, per_city).items()):
        for i, c in enumerate(cs):
            items.append(_item("surfshark", "wireguard", cc, city if i == 0 else f"{city} {i + 1}",
                               wg_conf(private_key, address, c["pubKey"], f"{c['connectionName']}:51820", dns)))
    return items

def import_mullvad_wg(private_key, address, per_city=1, relays=None, dns=""):
    relays = relays if relays is not None else http_json("https://api.mullvad.net/www/relays/all/")
    rows = [(r["country_code"].upper(), r.get("city_name") or r["country_code"], None, r)
            for r in relays if r.get("type") == "wireguard" and r.get("active") and r.get("pubkey")]
    items = []
    for (cc, city), rs in sorted(_group(rows, per_city).items()):
        for i, r in enumerate(rs):
            items.append(_item("mullvad", "wireguard", cc, city if i == 0 else f"{city} {i + 1}",
                               wg_conf(private_key, address, r["pubkey"], f"{r['ipv4_addr_in']}:51820", dns)))
    return items

def import_ivpn_wg(private_key, address, per_city=1, data=None, dns=""):
    data = data if data is not None else http_json("https://api.ivpn.net/v5/servers.json")
    rows = []
    for g in data.get("wireguard", []):
        for h in g.get("hosts", []):
            if h.get("public_key") and h.get("host"):
                rows.append((g["country_code"].upper(), g.get("city") or g["country_code"], h.get("load"), h))
    items = []
    for (cc, city), hs in sorted(_group(rows, per_city).items()):
        for i, h in enumerate(hs):
            items.append(_item("ivpn", "wireguard", cc, city if i == 0 else f"{city} {i + 1}",
                               wg_conf(private_key, address, h["public_key"], f"{h['host']}:2049", dns)))
    return items

# --- Windscribe (template) ---
def import_windscribe(template, data=None):
    """Windscribe's CA/TLS key only come with a config from its (logged-in) generator, so the
    user gives us one; the public region list fans it out to every region."""
    if detect_protocol(template) != "openvpn":
        raise ValueError("Cần một file .ovpn tải từ Windscribe Config Generator làm mẫu")
    rs = parse_remotes(template)
    port, proto = (rs[0][1], rs[0][2]) if rs else (443, "udp")
    data = data if data is not None else http_json("https://assets.windscribe.com/serverlist/openvpn/0/ef")
    body = re.sub(r"^[ \t]*remote[ \t]+.*\n?", "", template.replace("\r", ""), flags=re.M)
    items = []
    for r in data.get("data", []):
        if not r.get("dns_hostname") or r.get("status") != 1: continue
        cc = (r.get("country_code") or "XX").upper()
        cc = _CC_ALIAS.get(cc, cc)
        items.append(_item("windscribe", "openvpn", cc, r.get("name") or cc,
                           f"remote {r['dns_hostname']} {port} {proto}\n" + body))
    return items

def ca_to_pem(data):
    """A CA certificate as PEM text, from PEM or DER bytes."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        return re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S).group(0).decode() + "\n"
    b64 = base64.encodebytes(data).decode().replace("\n", "")
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + \
           "\n-----END CERTIFICATE-----\n"

# name -> callable(account dict, per_city) for farm.py
def run_importer(name, s, acct, per_city=1):
    """Dispatch one importer. acct: {"user","pass","wg_key","wg_address","wg_dns",
    "template"}. Returns (items, eap_entries, ca_pem)."""
    per_city = max(1, min(int(per_city or 1), 10))
    if name == "zip":
        return import_zip_bundle(http_get(s["zip_url"], 180), acct.get("pid"), s.get("enrich")), [], None
    if name == "nordvpn":
        return import_nordvpn(max(per_city, 3)), [], None
    if name == "nordvpn_ikev2":
        return [], import_nordvpn_ikev2(per_city), ca_to_pem(http_get(s["ca_url"]))
    if name == "windscribe":
        return import_windscribe(acct.get("template") or ""), [], None
    if name in ("nordvpn_wg", "surfshark_wg", "mullvad_wg", "ivpn_wg"):
        key, addr = (acct.get("wg_key") or "").strip(), (acct.get("wg_address") or "").strip()
        addr = addr or s.get("default_address", "")
        if not valid_wg_key(key): raise ValueError("Private key WireGuard không hợp lệ (base64, 44 ký tự)")
        if not valid_cidr4(addr): raise ValueError("Địa chỉ WireGuard phải dạng 10.x.x.x/nn")
        fn = {"nordvpn_wg": import_nordvpn_wg, "surfshark_wg": import_surfshark_wg,
              "mullvad_wg": import_mullvad_wg, "ivpn_wg": import_ivpn_wg}[name]
        return fn(key, addr, per_city=per_city, dns=acct.get("wg_dns") or ""), [], None
    raise ValueError(f"Không có trình nạp '{name}'")
