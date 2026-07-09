# privacyIDEA FreeRADIUS 3 container.
# Build context is the repository root:
#   docker build -f docker/Dockerfile -t privacyidea-freeradius .
FROM debian:bookworm-slim

# FreeRADIUS 3.2 (with rlm_perl) + the Perl deps from cpanfile (all packaged in
# Debian, so no CPAN build step) + envsubst (gettext-base) for config templating.
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
        freeradius \
        freeradius-utils \
        libconfig-inifiles-perl \
        libdata-dump-perl \
        libtry-tiny-perl \
        libjson-perl \
        liburi-encode-perl \
        libwww-perl \
        liblwp-protocol-https-perl \
        gettext-base \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The plugin itself.
COPY privacyidea_radius.pm /usr/share/privacyidea/freeradius/privacyidea_radius.pm

# Purpose-built raddb + the vendor dictionary + entrypoint.
COPY docker/raddb/ /etc/raddb/
COPY dictionary.netknights /etc/raddb/dictionary.netknights
COPY docker/entrypoint.sh /entrypoint.sh

RUN set -eux; \
    mkdir -p /etc/raddb/mods-enabled /etc/raddb/sites-enabled; \
    ln -sf ../mods-available/privacyidea  /etc/raddb/mods-enabled/privacyidea; \
    ln -sf ../sites-available/privacyidea /etc/raddb/sites-enabled/privacyidea; \
    chmod +x /entrypoint.sh

# privacyIDEA connection (standard container "-e VAR=..." configuration).
ENV PI_URL=https://localhost/validate/check \
    PI_REALM= \
    PI_RESOLVER= \
    PI_SSL_CHECK=true \
    PI_SSL_CA_PATH= \
    PI_DEBUG=false \
    PI_TIMEOUT=10 \
    PI_POLL=false \
    PI_POLL_TIMEOUT=60 \
    PI_POLL_INTERVAL=3 \
    PI_ADD_EMPTY_PASS=false \
    PI_SPLIT_NULL_BYTE=false \
    PI_CLIENTATTRIBUTE= \
    RADIUS_CLIENT_NET=0.0.0.0/0
# RADIUS_CLIENT_SECRET is intentionally not defaulted here (avoids baking a
# secret into image metadata); entrypoint.sh falls back to "testing123" for
# local/dev if unset. Always set it at runtime for real deployments.

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["freeradius", "-f", "-d", "/etc/raddb"]
