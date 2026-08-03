# privacyIDEA FreeRADIUS container

A FreeRADIUS **3.2** container with the privacyIDEA Perl plugin baked in and
configured entirely through environment variables. FR3 (not 4) on purpose — it
is the stable, supported, security-maintained line; see the project memory /
`../Changelog` for the rationale.

## Quick start

```sh
docker build -f docker/Dockerfile -t privacyidea-freeradius .

docker run --rm -p 1812:1812/udp -p 1813:1813/udp \
    -e PI_URL="https://your-privacyidea/validate/check" \
    -e PI_SSL_CHECK=true \
    -e RADIUS_CLIENT_SECRET="your-nas-secret" \
    -e RADIUS_CLIENT_NET="10.0.0.0/8" \
    privacyidea-freeradius
```

## Environment variables

This table is the canonical reference for what each option *means*. For a
ready-to-run example, see [`docker-compose.yml`](../docker-compose.yml) (it lists
the same options with their defaults, copy-paste ready).

| Variable | Default | Meaning |
|---|---|---|
| `PI_URL` | `https://localhost/validate/check` | privacyIDEA validate endpoint |
| `PI_REALM` | *(empty)* | Static realm (else the request's `Realm`) |
| `PI_RESOLVER` | *(empty)* | `resConf` sent to privacyIDEA |
| `PI_SSL_CHECK` | `true` | Verify the privacyIDEA TLS certificate |
| `PI_SSL_CA_PATH` | *(empty)* | CA directory for verification |
| `PI_DEBUG` | `false` | Verbose module logging |
| `PI_TIMEOUT` | `10` | HTTP timeout (seconds) |
| `PI_POLL` | `false` | Poll `/validate/polltransaction` for push instead of returning a challenge |
| `PI_POLL_TIMEOUT` | `60` | Max seconds to poll for push confirmation |
| `PI_POLL_INTERVAL` | `3` | Seconds between polls |
| `PI_ADD_EMPTY_PASS` | `false` | Send `pass=""` when no `User-Password` |
| `PI_SPLIT_NULL_BYTE` | `false` | Keep only the first NUL-delimited password segment |
| `PI_CLIENTATTRIBUTE` | *(empty)* | Request attribute to send as `client` |
| `RADIUS_CLIENT_SECRET` | `testing123` | Shared secret for the default RADIUS client |
| `RADIUS_CLIENT_NET` | `0.0.0.0/0` | Allowed NAS network for the default client — **restrict this in production** |
| `RADIUS_REQUIRE_MSG_AUTH` | `yes` | Require Message-Authenticator (BlastRADIUS / CVE-2024-3596 mitigation). Use `auto` or `no` only for legacy NAS that cannot send it |
| `RADIUS_MAX_SERVERS` | `64` | Worker-thread cap. A polling push holds a worker for the wait, so raise this for many concurrent pushes |

`PI_*` values are rendered into `/etc/raddb/rlm_perl.ini` at container start
(the Perl module reads that INI, not FreeRADIUS-native config, so this templating
is how env vars reach it). `RADIUS_CLIENT_*` / `RADIUS_REQUIRE_MSG_AUTH` render
into `clients.conf`, and `RADIUS_MAX_SERVERS` into `radiusd.conf`.

## Multiple RADIUS clients (NAS devices)

The env vars configure a **single** default client. For more than one NAS — each
with its own IP and secret — mount FreeRADIUS `client { ... }` files into
`/etc/raddb/clients.d/` (included automatically alongside the default client):

```sh
docker run ... \
    -v /path/to/my-clients.conf:/etc/raddb/clients.d/my-clients.conf:ro \
    privacyidea-freeradius
```

Put only valid FreeRADIUS client config in that directory — every file there is
parsed as config.

## Configuring anything else (escape hatch)

Only the common options are env-driven. For anything the env vars don't cover
(TLS/RadSec, EAP, proxying, custom policy, thread-pool internals, …), bind-mount
your own file over the one in the image — the server runs `freeradius -d /etc/raddb`,
so any file under `/etc/raddb` can be overridden:

```sh
docker run ... \
    -v /path/to/radiusd.conf:/etc/raddb/radiusd.conf:ro \
    privacyidea-freeradius
```

(Note the entrypoint renders `radiusd.conf` / `clients.conf` / `rlm_perl.ini`
from their `.template` files at start; a read-only bind-mount over the rendered
target takes precedence, or mount over the `.template` to keep templating.)

## Push polling caveat

With `PI_POLL=true`, a push authentication holds a FreeRADIUS worker thread for
up to `PI_POLL_TIMEOUT` seconds. This keeps your privacyIDEA server unblocked
(no server-side `push_wait`) but means concurrent pushes consume worker threads.
Raise `RADIUS_MAX_SERVERS` and your NAS request timeout accordingly.

## Debugging

```sh
docker run --rm ... privacyidea-freeradius freeradius -X -d /etc/raddb
```

## Local test stack

`docker compose up --build` starts the container against a mock privacyIDEA
(`docker/mock/`). Run the assertions with:

```sh
bash tests/integration.sh
```

This is what CI runs (`.github/workflows/docker.yml`): build → `freeradius -XC`
→ integration test with radclient.

## Layout

```
docker/
  Dockerfile
  entrypoint.sh                 # renders templates, execs freeradius
  raddb/
    radiusd.conf                # minimal, validated main config
    dictionary                  # system dict + vendor dict
    clients.conf.template       # <- RADIUS_CLIENT_*
    rlm_perl.ini.template       # <- PI_*
    mods-available/privacyidea  # rlm_perl module definition
    sites-available/privacyidea # virtual server (auth + acct)
  mock/mock_privacyidea.py      # canned privacyIDEA for tests
```
