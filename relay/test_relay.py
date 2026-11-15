#!/usr/bin/env python3
"""Tests of the relay: logic with a fake clock, then one pass over HTTP.

Run: python3 -m unittest discover -s relay
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay as R  # noqa: E402

CH = "a" * 32
RID = "b" * 32
SIGNER = "c" * 16
ENROLL, AGENT, PAIR, PHONE = "enroll-secret", "agent-token", "pair-token", "phone-token"
APPLE = "https://web.push.apple.com/abc"


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakePush:
    def __init__(self, gone=False):
        self.sent = []
        self.gone = gone
        self.done = threading.Event()

    def send(self, sub, payload):
        self.sent.append((sub["endpoint"], payload))
        self.done.set()
        return "fake push", self.gone


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.clock = Clock()
        self.push = FakePush()
        self.relay = R.Relay(self.dir.name, ENROLL, self.push, self.clock)

    def create(self):
        return self.relay.create_channel(ENROLL, {
            "ch": CH, "agent_auth": R.digest(AGENT), "pair_auth": R.digest(PAIR), "hello": "hi"})

    def pair(self):
        self.create()
        return self.relay.post_pair(CH, PAIR, {
            "signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "answer"})

    def request(self, rid=RID, ttl=90):
        return self.relay.post_request(CH, AGENT, {
            "id": rid, "to": SIGNER, "exp": self.clock.t + ttl, "msg": "sealed"})

    def saved_state(self):
        with open(os.path.join(self.dir.name, "state.json"), encoding="utf-8") as f:
            return f.read()

    # -- pairing --

    def test_channel_creation_needs_the_enrolment_secret(self):
        self.assertEqual(self.relay.create_channel("wrong", {})[0], 401)
        self.assertEqual(self.relay.create_channel(None, {})[0], 401)
        self.assertEqual(self.create(), (200, {"state": "created"}))
        self.assertEqual(self.create(), (200, {"state": "exists"}))

    def test_channel_creation_rejects_malformed_fields(self):
        ok = {"ch": CH, "agent_auth": "0" * 64, "pair_auth": "0" * 64, "hello": "x"}
        for field, bad in (("ch", "A" * 32), ("ch", "abc"), ("agent_auth", "x"),
                           ("pair_auth", None), ("hello", "x" * (R.MAX_BLOB + 1))):
            self.assertEqual(self.relay.create_channel(ENROLL, {**ok, field: bad})[0], 400, field)

    def test_pairing_hands_the_answer_to_the_agent_and_works_once(self):
        self.create()
        self.assertEqual(self.relay.get_hello(CH, PAIR), (200, {"hello": "hi"}))
        self.assertEqual(self.relay.get_hello(CH, AGENT)[0], 401)
        self.assertEqual(self.relay.get_pair_answer(CH, AGENT), (204, None))
        self.assertEqual(self.pair(), (200, {"state": "paired"}))
        self.assertEqual(self.relay.get_pair_answer(CH, AGENT),
                         (200, {"state": "answered", "signer": SIGNER, "msg": "answer"}))
        # The pairing secret is spent: nobody else can enrol as a signer.
        self.assertEqual(self.relay.get_hello(CH, PAIR)[0], 401)
        self.assertEqual(self.relay.post_pair(CH, PAIR, {
            "signer": "d" * 16, "signer_auth": "0" * 64, "msg": "x"})[0], 401)

    def test_an_unpaired_channel_expires(self):
        self.create()
        self.clock.t += R.PAIR_WINDOW + 1
        self.relay.create_channel(ENROLL, {
            "ch": "e" * 32, "agent_auth": "0" * 64, "pair_auth": "0" * 64, "hello": ""})
        self.assertEqual(self.relay.get_hello(CH, PAIR)[0], 401)

    def test_state_survives_a_restart_but_tokens_are_not_stored(self):
        self.pair()
        raw = self.saved_state()
        for secret in (ENROLL, AGENT, PAIR, PHONE):
            self.assertNotIn(secret, raw)
        again = R.Relay(self.dir.name, ENROLL, self.push, self.clock)
        self.assertEqual(again.get_requests(CH, PHONE), (200, {"requests": []}))

    # -- requests and responses --

    def test_request_reaches_the_signer_and_the_answer_reaches_the_agent(self):
        self.pair()
        self.assertEqual(self.request(), (200, {"state": "queued", "push": False}))
        self.assertEqual(self.relay.get_response(CH, AGENT, RID), (204, None))
        status, body = self.relay.get_requests(CH, PHONE)
        self.assertEqual((status, body["requests"]),
                         (200, [{"id": RID, "exp": self.clock.t + 90, "msg": "sealed"}]))
        self.assertEqual(self.relay.post_response(CH, PHONE, RID, {"msg": "signed"}),
                         (200, {"state": "accepted"}))
        self.assertEqual(self.relay.get_response(CH, AGENT, RID),
                         (200, {"state": "answered", "msg": "signed"}))
        # Answered requests are no longer offered, and cannot be answered twice.
        self.assertEqual(self.relay.get_requests(CH, PHONE), (200, {"requests": []}))
        self.assertEqual(self.relay.post_response(CH, PHONE, RID, {"msg": "again"}),
                         (200, {"state": "duplicate"}))

    def test_roles_cannot_be_swapped(self):
        self.pair()
        self.assertEqual(self.relay.post_request(CH, PHONE, {
            "id": RID, "to": SIGNER, "exp": self.clock.t + 10, "msg": "x"})[0], 401)
        self.request()
        self.assertEqual(self.relay.get_requests(CH, AGENT)[0], 401)
        self.assertEqual(self.relay.post_response(CH, AGENT, RID, {"msg": "x"})[0], 401)
        self.assertEqual(self.relay.get_response(CH, PHONE, RID)[0], 401)
        self.assertEqual(self.relay.get_requests("f" * 32, PHONE)[0], 401)

    def test_normal_situations_never_answer_4xx(self):
        self.pair()
        self.assertEqual(self.relay.get_response(CH, AGENT, RID), (200, {"state": "unknown"}))
        self.assertEqual(self.relay.post_response(CH, PHONE, RID, {"msg": "x"}),
                         (200, {"state": "unknown"}))
        self.assertEqual(self.request(ttl=R.MAX_TTL + 1), (200, {"state": "expired"}))
        self.assertEqual(self.request(ttl=0), (200, {"state": "expired"}))
        self.request()
        self.assertEqual(self.request(), (200, {"state": "duplicate"}))
        self.assertEqual(self.relay.post_request(CH, AGENT, {
            "id": "1" * 32, "to": "d" * 16, "exp": self.clock.t + 10, "msg": "x"}),
            (200, {"state": "unknown-signer"}))
        self.clock.t += 91
        self.assertEqual(self.relay.get_response(CH, AGENT, RID), (200, {"state": "expired"}))
        self.assertEqual(self.relay.post_response(CH, PHONE, RID, {"msg": "late"}),
                         (200, {"state": "expired"}))
        self.assertEqual(self.relay.get_requests(CH, PHONE), (200, {"requests": []}))

    def test_pending_requests_are_capped(self):
        self.pair()
        for i in range(R.MAX_PENDING):
            self.assertEqual(self.request(rid=f"{i:032x}")[1]["state"], "queued")
        self.assertEqual(self.request(rid="f" * 32), (200, {"state": "busy"}))
        # Answering one frees a slot.
        self.relay.post_response(CH, PHONE, f"{0:032x}", {"msg": "ok"})
        self.assertEqual(self.request(rid="f" * 32)[1]["state"], "queued")

    def test_long_poll_wakes_up_when_the_answer_arrives(self):
        self.pair()
        self.request()
        got = []
        waiter = threading.Thread(
            target=lambda: got.append(self.relay.get_response(CH, AGENT, RID, wait=10)))
        waiter.start()
        self.relay.post_response(CH, PHONE, RID, {"msg": "signed"})
        waiter.join(5)
        self.assertEqual(got, [(200, {"state": "answered", "msg": "signed"})])

    def test_long_poll_with_known_ids_only_returns_on_news(self):
        import time
        self.pair()
        self.request()
        # Without `known`, a pending request answers at once, every time.
        started = time.monotonic()
        self.relay.get_requests(CH, PHONE, wait=5)
        self.assertLess(time.monotonic() - started, 1)
        # The caller already holds it: the call must wait, not spin.
        started = time.monotonic()
        status, body = self.relay.get_requests(CH, PHONE, wait=0.4, known={RID})
        self.assertGreaterEqual(time.monotonic() - started, 0.35)
        self.assertEqual([r["id"] for r in body["requests"]], [RID])
        # A new request, or the disappearance of a known one, is news.
        got = []
        waiter = threading.Thread(
            target=lambda: got.append(self.relay.get_requests(CH, PHONE, wait=10, known={RID})))
        waiter.start()
        self.request(rid="1" * 32)
        waiter.join(5)
        self.assertEqual(sorted(r["id"] for r in got[0][1]["requests"]), sorted([RID, "1" * 32]))
        started = time.monotonic()
        self.relay.get_requests(CH, PHONE, wait=5, known={RID, "1" * 32, "2" * 32})
        self.assertLess(time.monotonic() - started, 1)
        started = time.monotonic()
        self.assertEqual(self.relay.get_requests(CH, PHONE, wait=0.3, known=set())[1]["requests"][0]["id"], RID)
        self.assertLess(time.monotonic() - started, 0.25)

    def test_long_poll_does_not_outlast_the_request(self):
        import time
        self.pair()
        self.request(ttl=0.3)
        started = time.monotonic()
        self.relay.get_response(CH, AGENT, RID, wait=20)
        self.assertLess(time.monotonic() - started, 2)

    # -- push --

    def test_subscription_must_point_to_a_known_push_service(self):
        self.pair()
        keys = {"p256dh": "x", "auth": "y"}
        for endpoint in ("https://evil.example/x", "http://web.push.apple.com/x",
                         "https://push.apple.com.evil.example/x", None):
            self.assertEqual(self.relay.put_subscription(
                CH, PHONE, {"endpoint": endpoint, "keys": keys})[0], 400, endpoint)
        self.assertEqual(self.relay.put_subscription(CH, AGENT, {"endpoint": APPLE, "keys": keys})[0],
                         401)
        self.assertEqual(self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": keys}),
                         (200, {"state": "stored"}))

    def test_a_request_sends_a_content_free_push(self):
        self.pair()
        self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": {"p256dh": "x", "auth": "y"}})
        self.assertEqual(self.request(), (200, {"state": "queued", "push": True}))
        self.assertTrue(self.push.done.wait(5))
        self.assertEqual(self.push.sent, [(APPLE, {"t": "sign"})])

    def test_a_gone_subscription_is_forgotten(self):
        self.pair()
        self.push.gone = True
        self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": {"p256dh": "x", "auth": "y"}})
        self.request()
        self.assertTrue(self.push.done.wait(5))
        # The push thread drops the subscription and saves; wait for the save.
        for _ in range(100):
            if '"sub": null' in self.saved_state():
                break
            threading.Event().wait(0.02)
        self.assertIn('"sub": null', self.saved_state())

    def test_push_encryption_roundtrip(self):
        R.selftest()


class HttpTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        web = os.path.join(self.dir.name, "web")
        os.makedirs(os.path.join(web, "lib"))
        os.makedirs(os.path.join(web, "test"))
        for name, text in (("index.html", "<!doctype html>"), ("lib/x.js", "export {};"),
                           ("clavix-icon-180.png", "PNG"), ("test/secret.js", "no"), ("notes.txt", "no")):
            with open(os.path.join(web, name), "w", encoding="utf-8") as f:
                f.write(text)
        self.server = R.serve("127.0.0.1", 0, os.path.join(self.dir.name, "state"), ENROLL, web,
                              "mailto:test@example.com", False)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, method, path, body=None, token=None, raw=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_whole_exchange_over_http(self):
        status, _, body = self.call("POST", "/api/channels", token=ENROLL, body={
            "ch": CH, "agent_auth": R.digest(AGENT), "pair_auth": R.digest(PAIR), "hello": "hi"})
        self.assertEqual((status, json.loads(body)), (200, {"state": "created"}))
        self.assertEqual(json.loads(self.call("GET", f"/api/ch/{CH}/pair", token=PAIR)[2]),
                         {"hello": "hi"})
        self.call("POST", f"/api/ch/{CH}/pair", token=PAIR, body={
            "signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "answer"})
        self.assertEqual(json.loads(self.call("GET", f"/api/ch/{CH}/pair/answer", token=AGENT)[2])["msg"],
                         "answer")
        import time
        self.call("POST", f"/api/ch/{CH}/requests", token=AGENT, body={
            "id": RID, "to": SIGNER, "exp": time.time() + 30, "msg": "sealed"})
        status, _, body = self.call("GET", f"/api/ch/{CH}/responses/{RID}?wait=0", token=AGENT)
        self.assertEqual((status, body), (204, b""))
        requests = json.loads(self.call("GET", f"/api/ch/{CH}/requests", token=PHONE)[2])["requests"]
        self.assertEqual([r["msg"] for r in requests], ["sealed"])
        self.call("POST", f"/api/ch/{CH}/responses/{RID}", token=PHONE, body={"msg": "signed"})
        self.assertEqual(
            json.loads(self.call("GET", f"/api/ch/{CH}/responses/{RID}", token=AGENT)[2]),
            {"state": "answered", "msg": "signed"})

    def test_known_parameter_over_http(self):
        self.call("POST", "/api/channels", token=ENROLL, body={
            "ch": CH, "agent_auth": R.digest(AGENT), "pair_auth": R.digest(PAIR), "hello": "hi"})
        self.call("POST", f"/api/ch/{CH}/pair", token=PAIR, body={
            "signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "answer"})
        for query in ("known=", f"known={RID}", f"known={RID},{'1' * 32}&wait=0"):
            self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests?{query}", token=PHONE)[0], 200, query)
        for query in ("known=abc", f"known={RID},", "known=%27"):
            self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests?{query}", token=PHONE)[0], 400, query)

    def test_errors_and_limits(self):
        self.assertEqual(self.call("GET", "/api/ch/nope/requests")[0], 404)
        self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests")[0], 401)
        self.assertEqual(self.call("POST", "/api/channels", token=ENROLL, raw=b"not json")[0], 400)
        self.assertEqual(self.call("POST", "/api/channels", token=ENROLL,
                                   raw=b"[" + b"1," * R.MAX_BODY + b"1]")[0], 400)

    def test_page_is_served_with_its_security_headers(self):
        status, headers, body = self.call("GET", "/")
        self.assertEqual((status, body), (200, b"<!doctype html>"))
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("publickey-credentials-get=(self)", headers["Permissions-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-cache")
        self.assertEqual(self.call("GET", "/lib/x.js")[0], 200)
        # Only the page and its modules are reachable.
        for path in ("/test/secret.js", "/notes.txt", "/../relay.py", "/lib/../test/secret.js"):
            self.assertEqual(self.call("GET", path)[0], 404, path)

    def test_icon_paths_browsers_ask_for_unprompted_are_answered(self):
        for path in ("/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
                     "/apple-touch-icon-240x240.png", "/apple-touch-icon-240x240-precomposed.png",
                     "/favicon.ico", "/icon.png"):
            status, headers, body = self.call("GET", path)
            self.assertEqual((status, body, headers["Content-Type"]), (200, b"PNG", "image/png"), path)
        for path in ("/apple-touch-icon.png/x", "/apple-touch-icon..png", "/favicon.ico.bak"):
            self.assertEqual(self.call("GET", path)[0], 404, path)

    def test_health_and_vapid_key(self):
        self.assertEqual(json.loads(self.call("GET", "/healthz")[2]), {"ok": True})
        key = json.loads(self.call("GET", "/api/vapid-public-key")[2])["key"]
        self.assertEqual(len(R.unb64u(key)), 65)

    def test_version_is_announced(self):
        self.assertEqual(json.loads(self.call("GET", "/api/version")[2]), {"version": R.VERSION})
        self.assertRegex(R.VERSION, r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")


if __name__ == "__main__":
    unittest.main()
