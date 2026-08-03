#!/bin/bash
# Integration test: brings up the compose stack (FreeRADIUS + mock privacyIDEA)
# and drives radclient (inside the freeradius container) through the auth flows.
set -u

COMPOSE="docker compose"
SECRET="testing123"
fail=0

# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== building image =="
# Build with host network: some build environments cannot reach package mirrors
# over the default bridge network. Harmless where the bridge already works (CI).
docker build --network=host -f docker/Dockerfile -t privacyidea-freeradius . \
    || { echo "image build failed"; exit 2; }

echo "== starting stack =="
$COMPOSE up -d || { echo "compose up failed"; exit 2; }

echo "== waiting for radiusd =="
ready=0
for _ in $(seq 1 60); do
    if $COMPOSE logs freeradius 2>&1 | grep -q "Ready to process requests"; then ready=1; break; fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "radiusd did not become ready"; $COMPOSE logs freeradius | tail -40; exit 2
fi

# Classify a radclient run. Defaults to "no-reply" so a hung/dead server is NOT
# silently counted as a reject (which would false-green the reject assertion).
verdict() {
    echo "$1" | grep -q "Received Access-Accept"    && { echo "Access-Accept";    return; }
    echo "$1" | grep -q "Received Access-Challenge"  && { echo "Access-Challenge"; return; }
    echo "$1" | grep -q "Received Access-Reject"     && { echo "Access-Reject";    return; }
    echo "no-reply"
}

run() { # name password expected
    local name="$1" pw="$2" want="$3" out got
    out=$(rc "$pw")
    got=$(verdict "$out")
    if [ "$got" = "$want" ]; then
        echo "PASS  $name ($pw -> $got)"
    else
        echo "FAIL  $name ($pw -> $got, want $want)"; echo "$out" | tail -20; fail=1
    fi
}

rc() { # helper: run radclient inside the container, echo full output.
    # Message-Authenticator=0x00 makes radclient sign the request (required when
    # RADIUS_REQUIRE_MSG_AUTH=yes, the secure default).
    $COMPOSE exec -T freeradius sh -c \
        "echo 'User-Name=alice,User-Password=$1${2:+,State=$2},Message-Authenticator=0x00' | radclient -x -t 10 -r 1 127.0.0.1:1812 auth $SECRET" 2>&1
}

run "simple accept" secret Access-Accept   # immediate value=true
run "push poll"     push   Access-Accept   # client_mode=poll -> polled server-side
run "reject"        wrong  Access-Reject

# push_code_to_phone: interactive challenge, then the phone code as pass.
echo "== code_to_phone (interactive challenge) =="
o1=$(rc pushcode)
if echo "$o1" | grep -q "Received Access-Challenge"; then echo "PASS  code_to_phone challenge"; else echo "FAIL  code_to_phone challenge"; echo "$o1" | tail -15; fail=1; fi
STATE=$(echo "$o1" | grep -oE "State = 0x[0-9a-fA-F]+" | head -1 | awk '{print $3}')
o2=$(rc 11 "$STATE")
if echo "$o2" | grep -q "Received Access-Accept"; then echo "PASS  code_to_phone correct code"; else echo "FAIL  code_to_phone correct code"; echo "$o2" | tail -15; fail=1; fi

o3=$(rc pushcode); STATE3=$(echo "$o3" | grep -oE "State = 0x[0-9a-fA-F]+" | head -1 | awk '{print $3}')
o4=$(rc 99 "$STATE3")
if echo "$o4" | grep -q "Received Access-Reject"; then echo "PASS  code_to_phone wrong code"; else echo "FAIL  code_to_phone wrong code"; echo "$o4" | tail -15; fail=1; fi

echo "---"
if [ "$fail" -eq 0 ]; then echo "INTEGRATION: all passed"; else echo "INTEGRATION: FAILURES"; fi
exit $fail
