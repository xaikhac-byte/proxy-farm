#!/bin/sh
# IKE source ports; entrypoint rewrites them to a fresh pair on every attempt.
OUTER_UDP_PORTS="500 4500"
# IKEv2 with EAP-MSCHAPv2 username/password — NordVPN, ProtonVPN, Surfshark, PIA, IPVanish
# and every provider whose "IKEv2 manual setup" uses an account login, not a certificate.
#
# strongSwan (charon + swanctl), not libreswan: libreswan has no EAP-MSCHAPv2 client.
# The gateway's certificate is always verified: against the public roots (the Mozilla
# bundle) plus anything in /ca and /secrets/ca-*.pem, or — when EAP_CA is set — against
# that CA only, which is what providers with a private CA (NordVPN, …) need.
#
# Env: SERVER (gateway fqdn), SERVER_IP (optional pin), EAP_USER, EAP_PASS,
#      SERVER_ID (identity in the gateway's certificate; defaults to SERVER),
#      EAP_CA (optional path to the provider's CA, e.g. /secrets/ca-eap-nordvpn.pem)

driver_resolve() {
  : "${SERVER:?SERVER required for ikev2-eap}"
  : "${EAP_USER:?EAP_USER required for ikev2-eap}"
  TUNNEL_LABEL="$SERVER"
  if [ -n "$SERVER_IP" ]; then echo "$SERVER_IP"
  else dig +short "$SERVER" A | grep -E '^[0-9.]+$'
  fi
}

driver_outer() {
  for r in "udp dport 500" "udp dport 4500"; do
    ip rule show | grep -q "ipproto $r" || ip rule add ipproto $r lookup 100
  done
  ip rule show | grep -q "ipproto esp" || ip rule add ipproto 50 lookup 100
}

# swanctl string: quote it and escape what the parser treats specially.
_swq() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

driver_up() {
  IP=$(cat /run/server_ip)
  RID="${SERVER_ID:-$SERVER}"

  X=/etc/swanctl/x509ca
  rm -rf "$X" && mkdir -p "$X" /etc/swanctl/conf.d
  CACERTS=""
  if [ -n "$EAP_CA" ] && [ -s "$EAP_CA" ]; then
    cp "$EAP_CA" "$X/provider-ca.pem"
    CACERTS="cacerts = provider-ca.pem"
  fi
  for f in /usr/share/ca-certificates/mozilla/*.crt /ca/*.pem /secrets/ca-*.pem; do
    [ -f "$f" ] && cp "$f" "$X/$(basename "$f")"
  done

  # Our own resolv.conf stays: pushed DNS often black-holes, and gost uses DoH anyway.
  cat > /etc/strongswan.conf <<EOC
charon {
  load_modular = yes
  install_virtual_ip = yes
  filelog {
    stderr { default = 1 }
    run {
      path = /run/charon.log
      default = 1
      flush_line = yes
    }
  }
  syslog { daemon { default = -1 } }
  plugins {
    include strongswan.d/charon/*.conf
    resolve { load = no }
  }
}
include strongswan.d/*.conf
EOC

  umask 077
  cat > /etc/swanctl/swanctl.conf <<EOC
connections {
  vpn {
    version = 2
    remote_addrs = $IP
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha256-ecp256,aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048,aes256-sha256-ecp256,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,default
    fragmentation = yes
    dpd_delay = 30s
    # The entrypoint owns retries (fresh outer port, back-off, failover to another IP).
    keyingtries = 1
    local {
      auth = eap-mschapv2
      eap_id = $(_swq "$EAP_USER")
    }
    remote {
      auth = pubkey
      id = $(_swq "$RID")
      $CACERTS
    }
    children {
      vpn {
        remote_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16,aes128gcm16,aes256-sha256,aes256-sha1,aes128-sha1,default
        start_action = start
        dpd_action = restart
      }
    }
  }
}
secrets {
  eap-vpn {
    id = $(_swq "$EAP_USER")
    # base64 ("0s…") so any character in the password survives
    secret = 0s$(printf '%s' "$EAP_PASS" | base64 | tr -d '\n')
  }
}
EOC

  : > /run/charon.log
  chown ipsec:ipsec /run/charon.log 2>/dev/null || true   # charon drops to uid ipsec
  rm -f /var/run/charon.vici /var/run/charon.pid
  /usr/lib/strongswan/charon >/dev/null &
  echo $! > /run/charon.pid
  i=0
  until swanctl --stats >/dev/null 2>&1; do
    i=$((i + 1)); [ $i -gt 40 ] && { echo "FATAL: charon did not start"; exit 1; }
    sleep 0.25
  done
  swanctl --load-all --noprompt >&2
}

# Tell the gateway we are leaving (IKE DELETE) so it drops the session now.
driver_down() {
  swanctl --terminate --ike vpn --timeout 3 >/dev/null 2>&1 || true
  [ -s /run/charon.pid ] && kill "$(cat /run/charon.pid)" 2>/dev/null
  return 0
}

# IKE and the Child SA are up: the tunnel exists, data has yet to show.
driver_established() { swanctl --list-sas 2>/dev/null | grep -q INSTALLED; }

driver_stuck() {
  log=/run/charon.log
  if grep -qE "EAP_FAILURE|EAP method EAP_MSCHAPV2 failed|AUTHENTICATION_FAILED" "$log" 2>/dev/null; then
    echo "watchdog: máy chủ từ chối tài khoản IKEv2" >&2; echo auth > /run/why; return 0
  fi
  if grep -qE "constraint check failed|no trusted RSA public key|no trusted ECDSA public key|no issuer certificate found" "$log" 2>/dev/null; then
    echo "watchdog: không tin được chứng chỉ máy chủ (thiếu CA hoặc sai ID máy chủ)" >&2; echo cert > /run/why; return 0
  fi
  sas=$(swanctl --list-sas 2>/dev/null)
  if ! echo "$sas" | grep -q ESTABLISHED; then
    # keyingtries=1: once charon gives up there is nothing left to wait for.
    [ -z "$sas" ] && return 0
    grep -q "retransmit" "$log" 2>/dev/null && return 0
    return 1
  fi
  echo "$sas" | grep -q INSTALLED || return 1
  in=$(ip -s xfrm state list dst "$LOCAL" 2>/dev/null | sed -n 's/^[[:space:]]*\([0-9]*\)(bytes).*/\1/p' | head -1)
  [ "$in" = 0 ] && { echo "watchdog: gateway không gửi dữ liệu về" >&2; echo nodata > /run/why; return 0; }
  return 1
}
