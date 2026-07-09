#!/usr/bin/env python3
"""Minimal mock privacyIDEA for driving the FreeRADIUS module end-to-end.

Responses mirror validate-doc/push.md. Behaviour keyed on the submitted pass:
  pass=secret    -> immediate ACCEPT (value=true)
  pass=push      -> push poll CHALLENGE      (client_mode=poll,        tx=TX-PUSH-1)
  pass=pushcode  -> push code_to_phone CHALLENGE (client_mode=interactive, tx=TX-CODE-1)
  else           -> REJECT

Challenge continuation (transaction_id OR state present -- privacyIDEA accepts
either; the FreeRADIUS module sends "state"):
  empty pass + TX-PUSH-1 -> ACCEPT   (poll finalize)
  TX-CODE-1  + pass=11   -> ACCEPT   (correct code read off the phone)
  anything else          -> REJECT   ("Response did not match the challenge.")

polltransaction TX-PUSH-1: first poll returns pending, second returns accept.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

poll_counts = {}
PHONE_CODE = "11"

def envelope(value, status=True, detail=None):
    d = {"result": {"status": status, "value": value}}
    if detail is not None:
        d["detail"] = detail
    return json.dumps(d).encode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        form = parse_qs(self.rfile.read(length).decode())
        g = lambda k: form.get(k, [''])[0]
        if urlparse(self.path).path == "/validate/check":
            pw = g('pass')
            tx = g('transaction_id') or g('state')
            if tx:
                if pw == "" and tx == "TX-PUSH-1":
                    self._send(envelope(True, detail={"message": "Found matching challenge", "serial": "PIPU001"}))
                elif tx == "TX-CODE-1" and pw == PHONE_CODE:
                    self._send(envelope(True, detail={"message": "Found matching challenge", "serial": "PIPU001"}))
                else:
                    self._send(envelope(False, detail={"message": "Response did not match the challenge.", "serial": "PIPU001", "type": "push"}))
            elif pw == "push":
                self._send(envelope(False, detail={
                    "transaction_id": "TX-PUSH-1", "client_mode": "poll",
                    "message": "Please confirm the authentication on your mobile device!",
                    "multi_challenge": [{"transaction_id": "TX-PUSH-1", "client_mode": "poll", "type": "push"}]}))
            elif pw == "pushcode":
                self._send(envelope(False, detail={
                    "transaction_id": "TX-CODE-1", "client_mode": "interactive",
                    "message": "Please enter the code displayed on your smartphone.",
                    "multi_challenge": [{"transaction_id": "TX-CODE-1", "client_mode": "interactive", "type": "push"}]}))
            elif pw == "secret":
                self._send(envelope(True, detail={"message": "matched", "serial": "SPASS1"}))
            else:
                self._send(envelope(False, detail={"message": "wrong otp value"}))
        else:
            self._send(b'{}', 404)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/validate/polltransaction":
            tx = parse_qs(u.query).get('transaction_id', [''])[0]
            poll_counts[tx] = poll_counts.get(tx, 0) + 1
            if poll_counts[tx] >= 2:
                self._send(envelope(True, detail={"challenge_status": "accept"}))
            else:
                self._send(envelope(False, detail={"challenge_status": "pending"}))
        else:
            self._send(b'{}', 404)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 15000
    # Bind all interfaces so the FreeRADIUS container can reach it over the
    # docker network (not just localhost within this container).
    HTTPServer(("0.0.0.0", port), H).serve_forever()
