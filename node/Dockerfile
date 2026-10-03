FROM gogost/gost:latest AS gost

# strongSwan, for IKEv2 with username/password (EAP-MSCHAPv2). libreswan has no
# EAP-MSCHAPv2 client, and Alpine's libreswan and strongswan packages both own
# /usr/sbin/ipsec, so they refuse to install side by side. Take only what the
# ikev2-eap driver runs: the charon daemon, its plugins and swanctl.
FROM alpine:3.22 AS swan
RUN apk add --no-cache strongswan

FROM alpine:3.22
RUN apk add --no-cache \
      libreswan nss-tools openssl \
      wireguard-tools-wg \
      openvpn \
      curl ca-certificates iproute2 bind-tools iptables \
      libcap2 libcurl gmp sqlite-libs
COPY --from=swan /usr/lib/ipsec /usr/lib/ipsec
COPY --from=swan /usr/lib/strongswan /usr/lib/strongswan
COPY --from=swan /usr/sbin/swanctl /usr/sbin/swanctl
COPY --from=swan /etc/strongswan.conf /etc/strongswan.conf
COPY --from=swan /etc/strongswan.d /etc/strongswan.d
COPY --from=swan /etc/swanctl /etc/swanctl
# Alpine builds charon to drop to the "ipsec" user, which its package scripts create.
RUN grep -q '^ipsec:' /etc/group || addgroup -S ipsec; \
    grep -q '^ipsec:' /etc/passwd || adduser -S -D -H -G ipsec -s /sbin/nologin ipsec
COPY --from=gost /bin/gost /usr/local/bin/gost
COPY ca /ca
COPY drivers /drivers
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /drivers/*.sh && \
    /usr/lib/strongswan/charon --version >/dev/null 2>&1 || ldd /usr/lib/strongswan/charon
LABEL proxy-farm=node
ENTRYPOINT ["/entrypoint.sh"]
