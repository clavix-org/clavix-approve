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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

try:
    import httpx
except ImportError:
    httpx = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay as R  # noqa: E402

CH = "a" * 32
RID = "b" * 32
SIGNER = "c" * 16
ENROLL, AGENT, PAIR, PHONE = "enroll-secret", "agent-token", "pair-token", "phone-token"
APPLE = "https://web.push.apple.com/abc"
TOKEN = "0123456789abcdef" * 4


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakePush:
    def __init__(self, gone=False, supports_apns=True):
        self.sent = []
        self.gone = gone
        self.supports_apns = supports_apns
        self.done = threading.Event()

    def send(self, sub, payload):
        self.sent.append((sub.get("endpoint") or sub.get("apns"), payload))
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

    # -- revocation --

    def test_either_end_can_revoke_and_everything_goes(self):
        for token in (AGENT, PHONE):
            with self.subTest(by=token):
                self.pair()
                self.relay.put_subscription(CH, PHONE, {
                    "endpoint": "https://web.push.apple.com/x", "keys": {"p256dh": "k", "auth": "a"}})
                self.request()
                self.assertEqual(self.relay.revoke(CH, token), (200, {"state": "revoked"}))
                self.assertNotIn(CH, self.saved_state())
                self.assertNotIn(CH, self.relay.pending)
                self.assertEqual(self.relay.get_requests(CH, PHONE)[0], 401)
                self.assertEqual(self.request()[0], 401)
                self.assertEqual(self.relay.get_response(CH, AGENT, RID)[0], 401)
                # Gone after a restart too.
                again = R.Relay(self.dir.name, ENROLL, self.push, self.clock)
                self.assertEqual(again.get_requests(CH, PHONE)[0], 401)

    def test_revocation_needs_a_token_of_the_channel(self):
        self.create()
        self.assertEqual(self.relay.revoke(CH, PAIR)[0], 401)   # the pairing secret cannot
        self.relay.post_pair(CH, PAIR, {
            "signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "answer"})
        for token in (None, "", ENROLL, "wrong"):
            self.assertEqual(self.relay.revoke(CH, token)[0], 401)
        self.assertEqual(self.relay.revoke("0" * 32, AGENT)[0], 401)
        self.assertEqual(self.relay.get_requests(CH, PHONE)[0], 200)
        # Revoking twice: the second time the channel is simply unknown.
        self.relay.revoke(CH, AGENT)
        self.assertEqual(self.relay.revoke(CH, AGENT)[0], 401)

    def test_revocation_ends_the_long_polls_on_the_channel(self):
        self.pair()
        self.request()
        got = []
        waiters = [
            threading.Thread(target=lambda: got.append(
                ("signer", self.relay.get_requests(CH, PHONE, wait=10, known={RID})[0]))),
            threading.Thread(target=lambda: got.append(
                ("agent", self.relay.get_response(CH, AGENT, RID, wait=10)[0]))),
        ]
        for w in waiters:
            w.start()
        import time
        time.sleep(0.2)
        self.relay.revoke(CH, AGENT)
        for w in waiters:
            w.join(5)
        self.assertEqual(sorted(got), [("agent", 401), ("signer", 401)])

    def test_revoking_one_channel_leaves_the_others(self):
        self.pair()
        other = "f" * 32
        self.relay.create_channel(ENROLL, {
            "ch": other, "agent_auth": R.digest("agent2"), "pair_auth": R.digest(PAIR), "hello": "hi"})
        self.relay.revoke(CH, AGENT)
        self.assertEqual(self.relay.get_hello(other, PAIR), (200, {"hello": "hi"}))

    # -- several devices --

    def add_device(self, signer="2" * 16, token="phone2", pair="pair2"):
        self.assertEqual(self.relay.open_pairing(CH, AGENT, {"pair_auth": R.digest(pair), "hello": "hi2"}),
                         (200, {"state": "open"}))
        return self.relay.post_pair(CH, pair, {"signer": signer, "signer_auth": R.digest(token), "msg": "a2"})

    def test_a_second_device_pairs_on_the_same_channel(self):
        self.pair()
        self.assertEqual(self.relay.get_hello(CH, PAIR)[0], 401)   # the first secret worked once
        self.assertEqual(self.add_device(), (200, {"state": "paired"}))
        self.assertEqual(self.relay.get_pair_answer(CH, AGENT)[1]["signer"], "2" * 16)
        # Each device sees only what is addressed to it.
        self.request()
        self.assertEqual(len(self.relay.get_requests(CH, PHONE)[1]["requests"]), 1)
        self.assertEqual(self.relay.get_requests(CH, "phone2")[1]["requests"], [])
        # Only the agent opens a pairing, and the new secret works once too.
        self.assertEqual(self.relay.open_pairing(CH, PHONE, {"pair_auth": R.digest("x"), "hello": "h"})[0], 401)
        self.assertEqual(self.relay.post_pair(CH, "pair2", {
            "signer": "3" * 16, "signer_auth": R.digest("p3"), "msg": "m"})[0], 401)

    def test_devices_are_capped_and_the_window_closes(self):
        self.pair()
        for i in range(2, R.MAX_SIGNERS + 1):
            self.assertEqual(self.add_device(str(i) * 16, f"t{i}", f"p{i}")[1]["state"], "paired")
        self.assertEqual(self.relay.open_pairing(CH, AGENT, {"pair_auth": R.digest("p9"), "hello": "h"}),
                         (200, {"state": "full"}))
        self.relay.revoke(CH, AGENT, {"signer": "2" * 16})
        self.relay.open_pairing(CH, AGENT, {"pair_auth": R.digest("late"), "hello": "h"})
        self.clock.t += R.PAIR_WINDOW + 1
        self.assertEqual(self.relay.get_hello(CH, "late")[0], 401)

    def test_one_device_can_be_revoked_alone(self):
        self.pair()
        self.add_device()
        self.request()
        # By the agent, naming the device.
        self.assertEqual(self.relay.revoke(CH, AGENT, {"signer": SIGNER}), (200, {"state": "revoked"}))
        self.assertEqual(self.relay.get_requests(CH, PHONE)[0], 401)
        self.assertEqual(self.relay.get_requests(CH, "phone2")[0], 200)
        self.assertEqual(self.relay.get_response(CH, AGENT, RID), (200, {"state": "unknown"}))   # its requests went
        self.assertEqual(self.relay.revoke(CH, AGENT, {"signer": SIGNER}), (200, {"state": "unknown-signer"}))
        self.assertEqual(self.relay.revoke(CH, AGENT, {"signer": "nope"})[0], 400)
        # A device cannot name another one.
        self.assertEqual(self.relay.revoke(CH, "phone2", {"signer": "2" * 16})[0], 401)
        # The last device leaving takes the channel with it.
        self.assertEqual(self.relay.revoke(CH, "phone2"), (200, {"state": "revoked"}))
        self.assertNotIn(CH, self.saved_state())

    def test_a_device_revoking_itself_leaves_the_others(self):
        self.pair()
        self.add_device()
        got = []
        waiter = threading.Thread(target=lambda: got.append(
            self.relay.get_requests(CH, PHONE, wait=10, known=set())[0]))
        waiter.start()
        import time
        time.sleep(0.2)
        self.assertEqual(self.relay.revoke(CH, PHONE), (200, {"state": "revoked"}))
        waiter.join(5)
        self.assertEqual(got, [401])
        self.assertEqual(self.relay.get_requests(CH, "phone2")[0], 200)
        self.assertEqual(self.request("2" * 32)[1]["state"], "unknown-signer")

    def test_the_agent_learns_whether_the_device_picked_the_request_up(self):
        self.pair()
        self.request()
        self.assertEqual(self.relay.get_response(CH, AGENT, RID), (204, None))
        self.assertEqual(self.relay.get_response(CH, AGENT, RID, report_seen=True),
                         (200, {"state": "pending", "seen": False}))
        self.relay.get_requests(CH, PHONE)
        self.assertEqual(self.relay.get_response(CH, AGENT, RID, report_seen=True),
                         (200, {"state": "pending", "seen": True}))

    def test_a_cancelled_request_is_no_longer_offered(self):
        self.pair()
        self.request()
        self.assertEqual(self.relay.cancel(CH, PHONE, RID)[0], 401)
        self.assertEqual(self.relay.cancel(CH, AGENT, RID), (200, {"state": "cancelled"}))
        self.assertEqual(self.relay.get_requests(CH, PHONE), (200, {"requests": []}))
        self.assertEqual(self.relay.post_response(CH, PHONE, RID, {"msg": "late"}), (200, {"state": "expired"}))
        self.assertEqual(self.relay.cancel(CH, AGENT, "f" * 32), (200, {"state": "unknown"}))

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

    # -- APNs subscription --

    def test_an_apns_subscription_is_checked_and_stored(self):
        self.pair()
        for body in ({"apns": "zz" * 32, "sandbox": True}, {"apns": "ab" * 31, "sandbox": True},
                     {"apns": "AB" * 32, "sandbox": True}, {"apns": TOKEN},
                     {"apns": TOKEN, "sandbox": "yes"}, {"apns": 12, "sandbox": False}):
            self.assertEqual(self.relay.put_subscription(CH, PHONE, body)[0], 400, body)
        self.assertEqual(self.relay.put_subscription(CH, AGENT, {"apns": TOKEN, "sandbox": True})[0],
                         401)
        self.assertEqual(self.relay.put_subscription(CH, PHONE, {"apns": TOKEN, "sandbox": True}),
                         (200, {"state": "stored"}))
        self.assertIn(TOKEN, self.saved_state())
        self.assertEqual(self.request(), (200, {"state": "queued", "push": True}))
        self.assertTrue(self.push.done.wait(5))
        self.assertEqual(self.push.sent, [(TOKEN, {"t": "sign"})])

    def test_a_relay_without_apns_keeps_the_web_push_subscription(self):
        self.push.supports_apns = False
        self.pair()
        self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": {"p256dh": "x", "auth": "y"}})
        self.assertEqual(self.relay.put_subscription(CH, PHONE, {"apns": TOKEN, "sandbox": False}),
                         (200, {"state": "unsupported"}))
        self.assertIn(APPLE, self.saved_state())
        self.assertNotIn(TOKEN, self.saved_state())


def p8_key():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return key, pem


@unittest.skipIf(httpx is None, "httpx not installed")
class ApnsTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.calls = []
        self.answer = (200, b"")
        self.key, pem = p8_key()

        def handler(request):
            self.calls.append(request)
            return httpx.Response(self.answer[0], content=self.answer[1])
        client = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(client.close)
        self.apns = R.ApnsPush(pem, "KEYID12345", "TEAMID1234", "org.clavix.approve",
                               client=client, now=self.clock)

    def send(self, sandbox=False):
        return self.apns.send({"apns": TOKEN, "sandbox": sandbox}, {"t": "sign"})

    def jwt_claims(self, request):
        head, body, sig = request.headers["authorization"].split(" ")[1].split(".")
        raw = R.unb64u(sig)
        self.key.public_key().verify(
            encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        return json.loads(R.unb64u(head)), json.loads(R.unb64u(body))

    def test_the_notification_is_content_free_and_signed(self):
        self.assertEqual(self.send(), ("push accepted by APNs (HTTP 200)", False))
        r = self.calls[0]
        self.assertEqual(str(r.url), f"https://api.push.apple.com/3/device/{TOKEN}")
        self.assertEqual(r.headers["apns-topic"], "org.clavix.approve")
        self.assertEqual(r.headers["apns-push-type"], "alert")
        self.assertEqual(r.headers["apns-priority"], "10")
        self.assertEqual(int(r.headers["apns-expiration"]), int(self.clock.t) + 90)
        self.assertEqual(json.loads(r.content), {"aps": {
            "alert": {"title": "Clavix", "body": "Une demande de signature attend"},
            "sound": "default", "interruption-level": "time-sensitive"}})
        self.assertEqual(self.jwt_claims(r), ({"alg": "ES256", "kid": "KEYID12345"},
                                              {"iss": "TEAMID1234", "iat": int(self.clock.t)}))

    def test_a_development_build_goes_to_the_sandbox(self):
        self.send(sandbox=True)
        self.assertEqual(self.calls[0].url.host, "api.sandbox.push.apple.com")

    def test_the_provider_token_is_reused_then_renewed(self):
        self.send()
        self.clock.t += 30 * 60
        self.send()
        self.clock.t += 15 * 60
        self.send()
        tokens = [c.headers["authorization"] for c in self.calls]
        self.assertEqual(tokens[0], tokens[1])
        self.assertNotEqual(tokens[1], tokens[2])

    def test_a_refused_provider_token_is_renewed_at_once(self):
        self.answer = (403, b'{"reason":"ExpiredProviderToken"}')
        self.assertEqual(self.send(), ("push rejected by APNs (HTTP 403 ExpiredProviderToken)", False))
        self.clock.t += 1
        self.answer = (200, b"")
        self.send()
        self.assertNotEqual(self.calls[0].headers["authorization"],
                            self.calls[1].headers["authorization"])

    def test_a_dead_device_token_is_reported_gone(self):
        for answer, gone in (((410, b'{"reason":"Unregistered"}'), True),
                             ((400, b'{"reason":"BadDeviceToken"}'), True),
                             ((400, b'{"reason":"BadTopic"}'), False),
                             ((429, b'{"reason":"TooManyRequests"}'), False),
                             ((500, b"oops"), False)):
            self.answer = answer
            self.assertEqual(self.send()[1], gone, answer)

    def test_the_route_follows_the_subscription(self):
        web = FakePush()
        pushers = R.Pushers(web, self.apns)
        pushers.send({"apns": TOKEN, "sandbox": False}, {"t": "sign"})
        pushers.send({"endpoint": APPLE, "keys": {}}, {"t": "sign"})
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(web.sent, [(APPLE, {"t": "sign"})])
        self.assertTrue(pushers.supports_apns)
        self.assertFalse(R.Pushers(web).supports_apns)
        self.assertEqual(R.Pushers(web).send({"apns": TOKEN, "sandbox": False}, {}),
                         ("APNs not configured, not sent", False))

    def test_bad_settings_are_refused(self):
        _, pem = p8_key()
        with self.assertRaises(ValueError):
            R.ApnsPush(pem, "short", "TEAMID1234", "t", enabled=False)
        rsa_pem = rsa.generate_private_key(65537, 2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        with self.assertRaises(ValueError):
            R.ApnsPush(rsa_pem, "KEYID12345", "TEAMID1234", "t", enabled=False)


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

    def test_revocation_over_http(self):
        self.call("POST", "/api/channels", token=ENROLL, body={
            "ch": CH, "agent_auth": R.digest(AGENT), "pair_auth": R.digest(PAIR), "hello": "hi"})
        self.call("POST", f"/api/ch/{CH}/pair", token=PAIR, body={
            "signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "answer"})
        self.assertEqual(self.call("GET", f"/api/ch/{CH}/revoke", token=PHONE)[0], 404)
        status, _, body = self.call("POST", f"/api/ch/{CH}/revoke", token=PHONE, body={})
        self.assertEqual((status, json.loads(body)), (200, {"state": "revoked"}))
        self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests", token=PHONE)[0], 401)
        self.assertEqual(self.call("POST", f"/api/ch/{CH}/revoke", token=AGENT, body={})[0], 401)

    def test_devices_pickup_and_cancel_over_http(self):
        import time
        self.call("POST", "/api/channels", token=ENROLL, body={
            "ch": CH, "agent_auth": R.digest(AGENT), "pair_auth": R.digest(PAIR), "hello": "hi"})
        self.call("POST", f"/api/ch/{CH}/pair", token=PAIR, body={
            "signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "answer"})
        status, _, body = self.call("POST", f"/api/ch/{CH}/pair/open", token=AGENT,
                                    body={"pair_auth": R.digest("p2"), "hello": "h2"})
        self.assertEqual((status, json.loads(body)), (200, {"state": "open"}))
        self.call("POST", f"/api/ch/{CH}/requests", token=AGENT, body={
            "id": RID, "to": SIGNER, "exp": time.time() + 30, "msg": "sealed"})
        status, _, body = self.call("GET", f"/api/ch/{CH}/responses/{RID}?wait=0&seen=1", token=AGENT)
        self.assertEqual((status, json.loads(body)), (200, {"state": "pending", "seen": False}))
        self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests/{RID}/cancel", token=AGENT)[0], 404)
        status, _, body = self.call("POST", f"/api/ch/{CH}/requests/{RID}/cancel", token=AGENT, body={})
        self.assertEqual((status, json.loads(body)), (200, {"state": "cancelled"}))
        status, _, body = self.call("POST", f"/api/ch/{CH}/revoke", token=AGENT, body={"signer": SIGNER})
        self.assertEqual((status, json.loads(body)), (200, {"state": "revoked"}))

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

    def test_the_page_carries_the_version(self):
        self.assertRegex(R.VERSION, r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")
        with tempfile.TemporaryDirectory() as web:
            with open(os.path.join(web, "index.html"), "wb") as f:
                f.write(b"<p>Version @VERSION@</p>")
            static = R.load_static(web)
        expected = b"<p>Version " + R.VERSION.encode() + b"</p>"
        self.assertEqual(static["/"][1], expected)
        self.assertEqual(static["/index.html"][1], expected)


if __name__ == "__main__":
    unittest.main()
