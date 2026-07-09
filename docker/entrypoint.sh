#!/bin/sh
# Render the env-driven config, then exec the RADIUS server.
set -e

# Defaults (also set as Dockerfile ENV; repeated here so the entrypoint is
# robust when run standalone).
: "${PI_URL:=https://localhost/validate/check}"
: "${PI_SSL_CHECK:=true}"
: "${PI_DEBUG:=false}"
: "${PI_TIMEOUT:=10}"
: "${PI_POLL:=false}"
: "${PI_POLL_TIMEOUT:=60}"
: "${PI_POLL_INTERVAL:=3}"
: "${PI_ADD_EMPTY_PASS:=false}"
: "${PI_SPLIT_NULL_BYTE:=false}"
: "${RADIUS_CLIENT_SECRET:=testing123}"
: "${RADIUS_CLIENT_NET:=0.0.0.0/0}"

# Canonical list of the vars this entrypoint maps into config. These "$NAME"
# allowlists are the single source of truth here: only these are substituted (so
# any other $... in the templates is left untouched), and the export list below
# is derived from them so the names aren't written twice.
#
# Adding an option? Update it in ALL of: rlm_perl.ini.template /
# clients.conf.template, the Dockerfile ENV block, docker-compose.yml, and
# docker/README.md (the descriptions table).
# shellcheck disable=SC2016  # literal $NAMES are intentional: envsubst expands them
PI_VARS='$PI_URL $PI_REALM $PI_RESOLVER $PI_SSL_CHECK $PI_SSL_CA_PATH $PI_DEBUG $PI_TIMEOUT $PI_POLL $PI_POLL_TIMEOUT $PI_POLL_INTERVAL $PI_ADD_EMPTY_PASS $PI_SPLIT_NULL_BYTE $PI_CLIENTATTRIBUTE'
# shellcheck disable=SC2016
CLIENT_VARS='$RADIUS_CLIENT_SECRET $RADIUS_CLIENT_NET'

# Export every mapped var so envsubst (a child process) sees the ones we set via
# the defaults above. Names are derived from the allowlists (strip the '$').
# shellcheck disable=SC2046  # word splitting into separate names is intentional
export $(printf '%s %s' "$PI_VARS" "$CLIENT_VARS" | tr -d '$')

envsubst "$PI_VARS"     < /etc/raddb/rlm_perl.ini.template  > /etc/raddb/rlm_perl.ini
envsubst "$CLIENT_VARS" < /etc/raddb/clients.conf.template  > /etc/raddb/clients.conf

echo "[entrypoint] rendered /etc/raddb/rlm_perl.ini:"
sed 's/^/    /' /etc/raddb/rlm_perl.ini

exec "$@"
