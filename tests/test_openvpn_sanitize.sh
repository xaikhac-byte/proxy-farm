#!/bin/sh
# Offline test of node/drivers/openvpn.sh: ovpn_sanitize, _ovpn_remotes, ovpn_needs_auth.
# Run: sh tests/test_openvpn_sanitize.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../node/drivers/openvpn.sh"      # only defines functions
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
ok()  { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; fail=1; }
has()    { grep -qxF -- "$2" "$1" && ok "has '$2'" || bad "missing '$2'"; }
hasnt()  { grep -qE -- "$2" "$1" && bad "still has /$2/" || ok "dropped /$2/"; }

printf '%s\r\n' \
  'client' 'dev tun' 'proto udp' 'port 1197' \
  'remote a.example.com 1194' 'remote b.example.com' 'remote c.example.com 443 tcp' \
  'remote-random' 'resolv-retry infinite' 'nobind' 'persist-key' \
  'auth-user-pass' 'ns-cert-type server' 'cipher aes-128-cbc' 'comp-lzo' \
  'keysize 256' 'ncp-disable' 'route-method exe' 'block-outside-dns' \
  'redirect-gateway def1' 'dhcp-option DNS 10.0.0.1' 'up /etc/openvpn/update-resolv-conf' \
  'script-security 2' 'keepalive 10 60' 'verb 3' '; comment' '# comment' \
  '<connection>' 'remote d.example.com 1194' '</connection>' \
  '<ca>' '-----BEGIN CERTIFICATE-----' 'remote not-a-directive-inside-a-block' '-----END CERTIFICATE-----' '</ca>' \
  > "$T/in.ovpn"

_ovpn_remotes "$T/in.ovpn" > "$T/remotes"
has "$T/remotes" "a.example.com 1194 udp"
has "$T/remotes" "b.example.com 1197 udp"
has "$T/remotes" "c.example.com 443 tcp-client"
has "$T/remotes" "d.example.com 1194 udp"
ovpn_needs_auth "$T/in.ovpn" && ok "needs auth" || bad "needs auth"

ovpn_sanitize "$T/in.ovpn" 1 > "$T/out1"
for re in '^remote [a-d]\.' '^remote-random' '^auth-user-pass' '^keysize' '^ncp-disable' '^route-method' \
          '^block-outside-dns' '^redirect-gateway' '^dhcp-option' '^up ' '^script-security' \
          '^keepalive' '^verb' '^[;#]' '<connection>' 'd\.example' '^ns-cert-type' "$(printf '\r')"; do
  hasnt "$T/out1" "$re"
done
has "$T/out1" "remote-cert-tls server"
has "$T/out1" "cipher aes-128-cbc"
has "$T/out1" "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC"
has "$T/out1" "data-ciphers-fallback AES-128-CBC"
has "$T/out1" "allow-compression asym"
has "$T/out1" "remote not-a-directive-inside-a-block"   # inline blocks untouched
has "$T/out1" "persist-key"

ovpn_sanitize "$T/in.ovpn" 0 > "$T/out0"
has "$T/out0" "auth-user-pass"

printf 'client\nremote x 1194\n' > "$T/noauth.ovpn"
ovpn_needs_auth "$T/noauth.ovpn" && bad "no auth expected" || ok "no auth"

[ $fail = 0 ] && echo "all passed" || { echo "FAILED"; exit 1; }
