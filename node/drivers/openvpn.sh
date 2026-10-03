#!/bin/sh
# OpenVPN from a standard .ovpn — NordVPN, Surfshark, PIA, IPVanish, TorGuard, IVPN,
# ExpressVPN/CyberGhost/PureVPN manual configs, or your own server.
#
# The file is never run as-is. ovpn_sanitize writes a copy that keeps the crypto and
# drops whatever would fight this container: the server list (we pin one IP the
# kill-switch routes), route/DNS/redirect directives, scripts, Windows-only options and
# options OpenVPN 2.6 removed. A config written for a desktop client therefore works
# unchanged.
#
# Env: CONFIG (path to the .ovpn)
#      OVPN_AUTH_FILE  file with "username\npassword" (the manager mounts one per provider)
#      OVPN_USER / OVPN_PASS  fallback when there is no auth file

# Every remote in the file as "host port proto". `port`/`proto` lines give the defaults;
# remotes inside <connection> blocks count too.
_ovpn_remotes() {
  awk '
    function norm(p) { p = tolower(p)
      if (p ~ /^tcp/) return "tcp-client"
      if (p ~ /^udp/) return "udp"
      return "" }
    { sub(/\r$/, "") }
    NR == FNR {
      if ($1 == "port" && $2 ~ /^[0-9]+$/) dport = $2
      if ($1 == "rport" && $2 ~ /^[0-9]+$/) dport = $2
      if ($1 == "proto" && norm($2) != "") dproto = norm($2)
      next }
    $1 == "remote" && $2 != "" {
      port = ($3 ~ /^[0-9]+$/) ? $3 : (dport ? dport : 1194)
      pr = norm($4); if (pr == "") pr = norm($3); if (pr == "") pr = (dproto ? dproto : "udp")
      print $2, port, pr }
  ' "$1" "$1"
}

# 0 when the config wants a username/password (a bare auth-user-pass, or one pointing at a
# file). An inline <auth-user-pass> block with content carries its own.
ovpn_needs_auth() { grep -qE '^[[:space:]]*auth-user-pass([[:space:]]|$)' "$1"; }

# ovpn_sanitize <in> <have_auth 0|1>  -> stdout
ovpn_sanitize() {
  awk -v have_auth="$2" '
    BEGIN {
      split("remote remote-random up down route-up route-pre-down ipchange client-connect " \
            "client-disconnect learn-address tls-verify auth-user-pass-verify script-security " \
            "plugin route route-ipv6 redirect-gateway redirect-private dhcp-option " \
            "block-outside-dns register-dns ip-win32 route-method win-sys dhcp-renew " \
            "dhcp-release tap-sleep show-net-up service log log-append daemon syslog status " \
            "writepid cd chroot user group keysize ncp-disable tun-ipv6 tls-remote auth-retry " \
            "askpass http-proxy http-proxy-option http-proxy-user-pass socks-proxy dev-node " \
            "lladdr management management-hold management-query-passwords " \
            "management-client-auth management-signal verb mute route-delay " \
            "route-nopull ping ping-restart ping-exit keepalive ping-timer-rem hand-window " \
            "connect-retry connect-retry-max connect-timeout server-poll-timeout", a, " ")
      for (i in a) drop[a[i]] = 1 }
    { sub(/\r$/, "") }
    # Inline blocks (<ca>…</ca>) pass through untouched, except <connection> (it carries
    # its own remote list) and an inline <auth-user-pass> we are replacing.
    inblk != "" { if ($0 ~ "^[ \t]*</" inblk ">") { if (!skipblk) print; inblk = ""; skipblk = 0; next }
                  if (!skipblk) print; next }
    /^[ \t]*<[A-Za-z0-9-]+>[ \t]*$/ {
      inblk = $0; gsub(/[ \t<>]/, "", inblk)
      skipblk = (inblk == "connection" || (inblk == "auth-user-pass" && have_auth == 1))
      if (!skipblk) print; next }
    /^[ \t]*([#;]|$)/ { next }
    { d = $1 }
    d ~ /^management/ { next }
    d in drop { next }
    d == "auth-user-pass" { if (have_auth != 1) print; next }
    d == "ns-cert-type" { print "remote-cert-tls server"; next }
    d == "cipher" { cipher = $2 }
    d == "data-ciphers" { has_dc = 1 }
    d == "data-ciphers-fallback" { has_dcf = 1 }
    d == "comp-lzo" || d == "compress" { comp = 1 }
    d == "allow-compression" { has_ac = 1 }
    d == "tun-mtu" { has_mtu = 1 }
    { print }
    END {
      # OpenVPN 2.6 negotiates data ciphers. Servers that predate negotiation only speak
      # the cipher the config names, so keep it in the list and as the fallback.
      if (cipher != "" && !has_dc)
        print "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:" toupper(cipher)
      if (cipher != "" && !has_dcf) print "data-ciphers-fallback " toupper(cipher)
      # 2.6 refuses compression by default; asym still decompresses what the server
      # sends while never compressing our own packets (VORACLE).
      if (comp && !has_ac) print "allow-compression asym"
      if (has_mtu) print "# pf: tun-mtu from config"
    }
  ' "$1"
}

driver_resolve() {
  : "${CONFIG:?CONFIG required for openvpn}"
  [ -f "$CONFIG" ] || { echo "config not found: $CONFIG" >&2; return 1; }
  TUNNEL_LABEL=$(basename "$CONFIG" | sed 's/\.[^.]*$//')
  _ovpn_remotes "$CONFIG" > /run/ovpn.remotes
  [ -s /run/ovpn.remotes ] || { echo "no 'remote' line in $CONFIG" >&2; return 1; }
  # ip -> port/proto, so driver_up can dial whichever IP the entrypoint picked.
  : > /run/ovpn.map
  while read -r host port proto; do
    if echo "$host" | grep -qE '^[0-9.]+$'; then ips=$host
    else ips=$(dig +short "$host" A | grep -E '^[0-9.]+$')
    fi
    for ip in $ips; do echo "$ip $port $proto" >> /run/ovpn.map; done
  done < /run/ovpn.remotes
  cut -d' ' -f1 /run/ovpn.map | awk '!seen[$0]++'
}

driver_up() {
  EPIP=$(cat /run/server_ip)
  # shellcheck disable=SC2046
  set -- $(awk -v ip="$EPIP" '$1 == ip { print; exit }' /run/ovpn.map)
  PORT=${2:-1194}; PROTO=${3:-udp}

  rm -f /run/ovpn.auth
  if [ -n "$OVPN_AUTH_FILE" ] && [ -s "$OVPN_AUTH_FILE" ]; then
    cp "$OVPN_AUTH_FILE" /run/ovpn.auth
  elif [ -n "$OVPN_USER" ]; then
    printf '%s\n%s\n' "$OVPN_USER" "$OVPN_PASS" > /run/ovpn.auth
  fi
  HAVE_AUTH=0
  [ -s /run/ovpn.auth ] && { chmod 600 /run/ovpn.auth; HAVE_AUTH=1; }

  AUTH=""
  if ovpn_needs_auth "$CONFIG"; then
    if [ "$HAVE_AUTH" = 1 ]; then
      AUTH="--auth-user-pass /run/ovpn.auth"
    else
      # Retrying cannot fix a missing password; back off like any failed attempt.
      echo "FATAL: AUTH_MISSING — file cần tài khoản OpenVPN (auth-user-pass) nhưng chưa nhập"
      echo auth > /run/why; echo $(( ${FAILS:-0} + 1 )) > /run/fails
      exit 1
    fi
  fi
  ovpn_sanitize "$CONFIG" "$HAVE_AUTH" > /run/client.ovpn
  MTUOPT="--tun-mtu $MTU"
  grep -q '^# pf: tun-mtu from config' /run/client.ovpn && MTUOPT=""

  # OpenVPN needs the tun device; Docker's default device rules allow creating it.
  [ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun; }

  # Split default so it beats any leftover default without needing to delete it.
  cat > /run/ovpn-up.sh <<'EOS'
#!/bin/sh
ip route replace 0.0.0.0/1 dev "$dev"
ip route replace 128.0.0.0/1 dev "$dev"
EOS
  chmod +x /run/ovpn-up.sh

  # --remote is the only server: the sanitized copy has none, so OpenVPN cannot wander
  # off to an IP the kill-switch does not route. --route-nopull keeps the server from
  # installing routes around the kill-switch; our own split default goes in route-up.
  : > /run/ovpn.log
  # shellcheck disable=SC2086
  { openvpn --config /run/client.ovpn \
      --remote "$EPIP" "$PORT" "$PROTO" \
      --nobind --route-nopull \
      $MTUOPT --mssfix \
      --script-security 2 --route-up /run/ovpn-up.sh \
      --persist-tun --persist-key \
      --ping 10 --ping-restart 60 --hand-window 25 --connect-retry-max 1 \
      --auth-retry none --auth-nocache \
      --writepid /run/openvpn.pid --verb 3 \
      $AUTH 2>&1; } | tee -a /run/ovpn.log >&2 &
}

driver_established() { grep -q "Initialization Sequence Completed" /run/ovpn.log 2>/dev/null; }

driver_stuck() {
  if grep -q "AUTH_FAILED" /run/ovpn.log 2>/dev/null; then
    echo "watchdog: máy chủ từ chối tài khoản OpenVPN" >&2; echo auth > /run/why; return 0
  fi
  if grep -qE "TLS key negotiation failed|TLS handshake failed" /run/ovpn.log 2>/dev/null; then
    echo silent > /run/why; return 0
  fi
  grep -qE "Options error|Exiting due to fatal error" /run/ovpn.log 2>/dev/null && return 0
  return 1
}

driver_down() {
  [ -s /run/openvpn.pid ] && kill "$(cat /run/openvpn.pid)" 2>/dev/null
  sleep 1; return 0
}
