"""Offline tests for manager/providers.py and the provider guessing in farm.py.

Run: python3 -m unittest discover -s tests -v
No network: every importer is fed fixture data through its servers=/clusters=/relays=/
data= parameter. Fixtures are inline strings because *.ovpn/*.conf are gitignored."""
import base64, io, json, os, sys, tempfile, unittest, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "manager"))
_tmp = tempfile.mkdtemp(prefix="pf-test-")
for k, sub in (("PF_STATE", "farm-state.json"), ("PF_CONFIG_DIR", "configs"),
               ("PF_SECRETS_DIR", "secrets"), ("PF_SECRETS", "secrets"),
               ("PF_STATUS_DIR", "status"), ("PF_FLAGS", "flags")):
    os.environ[k] = os.path.join(_tmp, sub)     # never touch a real farm
for d in ("configs", "secrets", "status", "flags"):
    os.makedirs(os.path.join(_tmp, d), exist_ok=True)

import providers as P   # noqa: E402

KEY = base64.b64encode(bytes(range(32))).decode()          # a valid-looking WG key
PUB = base64.b64encode(bytes(range(1, 33))).decode()
CA = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----"
TA = "-----BEGIN OpenVPN Static key V1-----\n00ff\n-----END OpenVPN Static key V1-----"

def ovpn(remote, extra=""):
    return (f"client\ndev tun\nproto udp\nremote {remote}\nresolv-retry infinite\n"
            f"nobind\nauth-user-pass\ncipher AES-256-CBC\n<ca>\n{CA}\n</ca>\n{extra}")


class Registry(unittest.TestCase):
    def test_presets_consistent(self):
        ids = [p["id"] for p in P.PRESETS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate preset id")
        known = {"zip", "nordvpn", "nordvpn_wg", "nordvpn_ikev2", "surfshark_wg",
                 "mullvad_wg", "ivpn_wg", "windscribe"}
        for p in P.PRESETS:
            for f in ("id", "name", "protocols"):
                self.assertIn(f, p, p.get("id"))
            for proto, s in p["protocols"].items():
                self.assertIn(s.get("how"), {"import", "template", "manual", "unsupported", "builtin"},
                              f"{p['id']}/{proto}")
                if s["how"] in ("import", "template"):
                    self.assertIn(s.get("importer"), known, f"{p['id']}/{proto}")
                    if s["importer"] == "zip":
                        self.assertTrue(s.get("zip_url", "").startswith("https://"))
                # honesty: nothing but HMA claims a verified real connection
                if p["id"] != "hma":
                    self.assertFalse(s.get("connect_verified"), f"{p['id']}/{proto}")

    def test_importer_for(self):
        self.assertEqual(P.importer_for("nordvpn", "openvpn")[0], "nordvpn")
        self.assertEqual(P.importer_for("mullvad", "wireguard")[0], "mullvad_wg")
        self.assertIsNone(P.importer_for("expressvpn", "openvpn")[0])
        self.assertIsNone(P.importer_for("nope", "openvpn")[0])

    def test_provider_from_hosts(self):
        self.assertEqual(P.provider_from_hosts(["uk765.nordvpn.com"]), "nordvpn")
        self.assertEqual(P.provider_from_hosts(["de-fra.prod.surfshark.com"]), "surfshark")
        self.assertIsNone(P.provider_from_hosts(["1.2.3.4", "vpn.example.org"]))

    def test_default_limits(self):
        lim = P.default_limits()
        self.assertEqual(lim.get("nordvpn"), 10)


class Location(unittest.TestCase):
    CASES = [
        ("mullvad-se-got.conf", (), "SE"),
        ("TorGuard.USA-NEW-YORK.ovpn", (), "US"),
        ("us_new_york.ovpn", (), "US"),
        ("uk765.nordvpn.com.udp.ovpn", (), "GB"),
        ("de-fra.prod.surfshark.com_udp.ovpn", (), "DE"),
        ("Netherlands.ovpn", (), "NL"),
        ("x.ovpn", ("jp12.nordvpn.com",), "JP"),
    ]
    def test_guess_location(self):
        for name, hosts, cc in self.CASES:
            with self.subTest(name=name):
                self.assertEqual(P.guess_location(name, hosts)[0], cc)


class OpenVPN(unittest.TestCase):
    def test_parse_remotes_defaults(self):
        t = "client\nport 443\nproto tcp\nremote a.example 1194 udp\nremote b.example\r\n"
        self.assertEqual(P.parse_remotes(t), [("a.example", 1194, "udp"), ("b.example", 443, "tcp")])

    def test_detect_protocol(self):
        self.assertEqual(P.detect_protocol(ovpn("a 1194")), "openvpn")
        self.assertEqual(P.detect_protocol("[Interface]\nPrivateKey = x\n"), "wireguard")
        self.assertIsNone(P.detect_protocol("hello"))

    def test_needs_auth(self):
        self.assertTrue(P.needs_auth("remote a\nauth-user-pass\n"))
        self.assertTrue(P.needs_auth("remote a\nauth-user-pass login.txt\n"))
        self.assertFalse(P.needs_auth("remote a\n"))
        self.assertFalse(P.needs_auth("remote a\nauth-user-pass\n<auth-user-pass>\nu\np\n</auth-user-pass>\n"))

    def test_inline_files(self):
        t = "client\nremote a 1194\nca ca.crt\ntls-auth \"ta.key\" 1\ncert missing.crt\n"
        files = {"ca.crt": CA.encode(), "ta.key": TA.encode()}
        out, missing = P.inline_files(t, files.get)
        self.assertIn("<ca>\n" + CA + "\n</ca>", out)
        self.assertIn("key-direction 1\n<tls-auth>", out)
        self.assertEqual(missing, ["missing.crt"])
        self.assertEqual(P.referenced_files(out), {"cert": "missing.crt"})

    def test_merge_configs(self):
        a = ovpn("1.1.1.1 1194", "verify-x509-name dal-c38.ipvanish.com name\n")
        b = ovpn("2.2.2.2 1194", "verify-x509-name dal-a12.ipvanish.com name\n")
        m = P.merge_configs([a, b])
        self.assertEqual([r[0] for r in P.parse_remotes(m)], ["1.1.1.1", "2.2.2.2"])
        self.assertIn("verify-x509-name dal- name-prefix", m)
        self.assertIn("remote-cert-tls server", m)
        self.assertEqual(m.count("<ca>"), 1)
        self.assertEqual(P.crypto_signature(a), P.crypto_signature(b))
        self.assertNotEqual(P.crypto_signature(a), P.crypto_signature(a.replace("MIIBfake", "MIIBother")))

    def test_zip_bundle(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("cfg/ca.crt", CA)
            z.writestr("cfg/de-fra.prod.surfshark.com_udp.ovpn",
                       "client\ndev tun\nproto udp\nremote de-fra.prod.surfshark.com 1194\nca ca.crt\nauth-user-pass\n")
            z.writestr("cfg/de-fra.prod.surfshark.com_tcp.ovpn",
                       "client\ndev tun\nproto tcp\nremote de-fra.prod.surfshark.com 1443\nca ca.crt\nauth-user-pass\n")
            z.writestr("cfg/us-nyc.prod.surfshark.com_udp.ovpn",
                       "client\ndev tun\nproto udp\nremote us-nyc.prod.surfshark.com 1194\nca ca.crt\nauth-user-pass\n")
        items = P.import_zip_bundle(buf.getvalue())
        self.assertEqual(len(items), 2)              # udp preferred, one per city
        names = sorted(i["name"] for i in items)
        self.assertTrue(all(n.startswith("surfshark-") and n.endswith(".ovpn") for n in names), names)
        for it in items:
            self.assertIn("<ca>", it["content"])
            self.assertTrue(it["meta"]["needs_auth"])
        self.assertEqual(sorted(i["meta"]["country"] for i in items), ["DE", "US"])


class WireGuard(unittest.TestCase):
    def test_key_and_cidr(self):
        self.assertTrue(P.valid_wg_key(KEY))
        self.assertFalse(P.valid_wg_key("short="))
        self.assertTrue(P.valid_cidr4("10.5.0.2/32"))
        self.assertFalse(P.valid_cidr4("10.5.0.300/32"))
        self.assertFalse(P.valid_cidr4("10.5.0.2"))

    def test_identity_roundtrip(self):
        c = P.wg_conf(KEY, "10.66.1.2/32", PUB, "1.2.3.4:51820", dns="10.64.0.1")
        ident = P.wg_identity(c + "\n")
        self.assertEqual(ident["private_key"], KEY)
        self.assertEqual(ident["address"], "10.66.1.2/32")
        self.assertEqual(P.detect_protocol(c), "wireguard")
        self.assertEqual(P.wg_identity("[Interface]\nAddress = 10.1.2.3/32, fc00::1/128\n")["address"], "10.1.2.3/32")


NORD = [
    {"hostname": "nl1.nordvpn.com", "station": "10.0.0.1", "load": 30, "status": "online",
     "locations": [{"country": {"code": "NL", "city": {"name": "Amsterdam"}}}], "groups": [],
     "technologies": [{"identifier": "wireguard_udp", "metadata": [{"name": "public_key", "value": PUB}]}]},
    {"hostname": "nl2.nordvpn.com", "station": "10.0.0.2", "load": 10, "status": "online",
     "locations": [{"country": {"code": "NL", "city": {"name": "Amsterdam"}}}], "groups": [],
     "technologies": [{"identifier": "wireguard_udp", "metadata": [{"name": "public_key", "value": PUB}]}]},
    {"hostname": "nl3.nordvpn.com", "station": "10.0.0.3", "load": 1, "status": "online",
     "locations": [{"country": {"code": "NL", "city": {"name": "Amsterdam"}}}],
     "groups": [{"identifier": "legacy_obfuscated_servers"}], "technologies": []},
    {"hostname": "jp1.nordvpn.com", "station": "10.0.1.1", "load": 5, "status": "offline",
     "locations": [{"country": {"code": "JP", "city": {"name": "Tokyo"}}}], "groups": [], "technologies": []},
]
NORD_TPL = ("client\ndev tun\nproto udp\nremote 1.1.1.1 1194\nverify-x509-name CN=nl9.nordvpn.com\n"
            "auth-user-pass\n<ca>\n" + CA + "\n</ca>\n")


class Importers(unittest.TestCase):
    def test_nordvpn_openvpn(self):
        items = P.import_nordvpn(per_city=3, servers=NORD, template=NORD_TPL)
        self.assertEqual(len(items), 1)                       # offline + obfuscated skipped
        it = items[0]
        self.assertEqual(it["name"], "nordvpn-nl-amsterdam.ovpn")
        self.assertEqual([r[0] for r in P.parse_remotes(it["content"])], ["10.0.0.2", "10.0.0.1"])
        # the CN of nl1/nl2.nordvpn.com still has to start with "nl"
        self.assertIn("verify-x509-name nl name-prefix", it["content"])
        self.assertTrue(it["meta"]["needs_auth"])

    def test_nordvpn_wg_and_ikev2(self):
        wg = P.import_nordvpn_wg(KEY, servers=NORD)
        self.assertEqual([i["name"] for i in wg], ["nordvpn-nl-amsterdam-wg.conf"])
        self.assertIn("Endpoint = 10.0.0.2:51820", wg[0]["content"])
        ike = P.import_nordvpn_ikev2(servers=NORD)
        self.assertEqual(ike, [{"server": "nl2.nordvpn.com", "server_id": "nl2.nordvpn.com",
                                "country": "NL", "city": "Amsterdam"}])

    def test_surfshark_wg(self):
        cl = [{"countryCode": "de", "location": "Frankfurt", "load": 9, "pubKey": PUB,
               "connectionName": "de-fra.prod.surfshark.com"},
              {"countryCode": "de", "location": "Frankfurt", "load": 3, "pubKey": PUB,
               "connectionName": "de-fra2.prod.surfshark.com"},
              {"countryCode": "us", "location": "Dallas", "pubKey": None, "connectionName": "x"}]
        items = P.import_surfshark_wg(KEY, clusters=cl)
        self.assertEqual(len(items), 1)
        self.assertIn("de-fra2.prod.surfshark.com:51820", items[0]["content"])
        self.assertEqual(len(P.import_surfshark_wg(KEY, per_city=2, clusters=cl)), 2)

    def test_mullvad_wg(self):
        relays = [{"type": "wireguard", "active": True, "pubkey": PUB, "country_code": "se",
                   "city_name": "Gothenburg", "ipv4_addr_in": "185.1.1.1"},
                  {"type": "bridge", "active": True, "pubkey": PUB, "country_code": "se",
                   "city_name": "Gothenburg", "ipv4_addr_in": "185.1.1.2"},
                  {"type": "wireguard", "active": False, "pubkey": PUB, "country_code": "de",
                   "city_name": "Berlin", "ipv4_addr_in": "185.1.1.3"}]
        items = P.import_mullvad_wg(KEY, "10.66.1.2/32", relays=relays)
        self.assertEqual([i["name"] for i in items], ["mullvad-se-gothenburg-wg.conf"])
        self.assertIn("Endpoint = 185.1.1.1:51820", items[0]["content"])

    def test_ivpn_wg(self):
        data = {"wireguard": [{"country_code": "NL", "city": "Amsterdam",
                               "hosts": [{"host": "1.2.3.4", "public_key": PUB, "load": 5}]}]}
        items = P.import_ivpn_wg(KEY, "172.20.0.2/32", data=data)
        self.assertIn("Endpoint = 1.2.3.4:2049", items[0]["content"])

    def test_windscribe_template(self):
        data = {"data": [{"dns_hostname": "ca.windscribe.com", "status": 1, "country_code": "CA", "name": "Canada East"},
                         {"dns_hostname": "uk.windscribe.com", "status": 1, "country_code": "UK", "name": "United Kingdom"},
                         {"dns_hostname": "x.windscribe.com", "status": 0, "country_code": "FR", "name": "France"}]}
        items = P.import_windscribe(ovpn("us-central.windscribe.com 443"), data=data)
        self.assertEqual(sorted(i["meta"]["country"] for i in items), ["CA", "GB"])
        self.assertEqual(P.parse_remotes(items[0]["content"])[0][0], "ca.windscribe.com")
        with self.assertRaises(ValueError):
            P.import_windscribe("not a config", data=data)

    def test_ca_to_pem(self):
        der = bytes(range(100))
        pem = P.ca_to_pem(der)
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----\n"))
        body = "".join(pem.strip().splitlines()[1:-1])
        self.assertEqual(base64.b64decode(body), der)
        self.assertEqual(P.ca_to_pem(("junk\n" + CA + "\n").encode()), CA + "\n")


class FarmGuessing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import farm
        cls.farm = farm

    def test_guess_provider(self):
        g = self.farm.guess_provider
        self.assertEqual(g("x.ovpn", "remote uk765.nordvpn.com 1194"), "nordvpn")
        self.assertEqual(g("mullvad-se-got.conf", "Endpoint = 1.2.3.4:51820"), "mullvad")
        self.assertEqual(g("TorGuard.USA-NEW-YORK.ovpn"), "torguard")
        self.assertEqual(g("nl-amsterdam.ovpn", "remote nl1.myvpn.net 1194"), "myvpn")
        self.assertEqual(g("us_new_york.ovpn", "remote 1.2.3.4"), "custom")

    def test_save_config_inlines_and_accounts(self):
        f = self.farm
        t = f.save_config("myvpn-de-berlin.ovpn",
                          "client\ndev tun\nremote de1.myvpn.net 1194\nca ca.crt\nauth-user-pass\n",
                          assets={"ca.crt": CA.encode()})
        with open(os.path.join(f.CONFIG_DIR, "myvpn-de-berlin.ovpn")) as fh: body = fh.read()
        self.assertIn("<ca>", body)
        self.assertTrue(t.get("needs_auth"))
        with self.assertRaises(Exception):
            f.save_config("myvpn-de-x.ovpn", "client\nremote a 1194\nca nothere.crt\n")
        f.set_account("myvpn", "user", 'p@ss "x"')
        self.assertTrue(f.has_account("myvpn"))
        path = f.auth_file("myvpn")
        with open(path) as fh: self.assertEqual(fh.read(), 'user\np@ss "x"\n')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            f.set_account("myvpn", "u", "a\nb")
        f.delete_account("myvpn")
        self.assertFalse(f.has_account("myvpn"))


class LowResource(unittest.TestCase):
    """The farm-wide cap on ports switched on at once (low-resource mode)."""
    @classmethod
    def setUpClass(cls):
        import farm
        cls.farm = farm

    def _quota(self, running, cap, wanted):
        f = self.farm
        saved = (f.running_containers, f.usage, f.load_settings, f.limit_for)
        st = dict(f.load_settings(), max_active=cap)
        try:
            f.running_containers = lambda: {k: {"state": "running"} for k in running}
            f.usage = lambda run=None: {"nordvpn": len(running)}
            f.load_settings = lambda: st
            f.limit_for = lambda key: 0
            return f.over_quota([{"key": k, "provider": "nordvpn", "protocol": "openvpn"} for k in wanted])
        finally:
            f.running_containers, f.usage, f.load_settings, f.limit_for = saved

    def test_cap_refuses_extra_ports(self):
        ok, refused = self._quota(["A"], 3, ["A", "B", "C", "D"])
        self.assertEqual([t["key"] for t in ok], ["A", "B", "C"])       # A was already on
        self.assertEqual([(r["key"], r["provider"], r["limit"]) for r in refused], [("D", "_all", 3)])

    def test_no_cap(self):
        ok, refused = self._quota([], 0, ["A", "B", "C", "D"])
        self.assertEqual(len(ok), 4); self.assertEqual(refused, [])

    def test_defaults(self):
        self.assertIn("low_resource", self.farm.DEFAULTS)
        self.assertIn("max_active", self.farm.SETTABLE)
        self.assertGreaterEqual(self.farm.DEFAULTS["port_mem_mb"], 32)


if __name__ == "__main__":
    unittest.main()
