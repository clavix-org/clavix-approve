#!/usr/bin/env python3
"""Tests of the relay: logic with a fake clock, then one pass over HTTP.

Run: python3 -m unittest discover -s relay
"""
import collections
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import time
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
# A valid Web Push key pair, as a browser hands it over.
KEYS = {"p256dh": R.b64u(R.raw_pub(ec.generate_private_key(ec.SECP256R1()))),
        "auth": R.b64u(os.urandom(16))}


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakePush:
    def __init__(self, gone=False, supports_apns=True):
        self.sent = []
        self.groups = []
        self.gone = gone
        self.supports_apns = supports_apns
        self.done = threading.Event()

    def send(self, sub, payload, group=None):
        self.sent.append((sub.get("endpoint") or sub.get("apns"), payload))
        self.groups.append(group)
        self.done.set()
        return "fake push", self.gone


def saved_state(state_dir):
    """Everything the relay wrote to its database, as text."""
    db = sqlite3.connect(os.path.join(state_dir, "state.db"))
    try:
        return "\n".join(f"{ch} {data}" for ch, data in db.execute("SELECT ch, data FROM channels"))
    finally:
        db.close()


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.clock = Clock()
        self.push = FakePush()
        self.relay = R.Relay(self.dir.name, ENROLL, self.push, self.clock)
        self.addCleanup(self.relay.close)

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
        return saved_state(self.dir.name)

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

    def test_the_agent_reveals_its_nonce_to_the_device_once(self):
        nonce = "N" * 43
        self.pair()
        self.assertEqual(self.relay.get_reveal(CH, PHONE), (204, None))
        # Only the agent reveals, only to a device of the channel, only a nonce.
        self.assertEqual(self.relay.post_reveal(CH, PHONE, {"signer": SIGNER, "nonce": nonce})[0], 401)
        self.assertEqual(self.relay.post_reveal(CH, AGENT, {"signer": SIGNER, "nonce": "short"})[0], 400)
        self.assertEqual(self.relay.post_reveal(CH, AGENT, {"signer": "d" * 16, "nonce": nonce}),
                         (200, {"state": "unknown-signer"}))
        self.assertEqual(self.relay.post_reveal(CH, AGENT, {"signer": SIGNER, "nonce": nonce}),
                         (200, {"state": "revealed"}))
        self.assertEqual(self.relay.post_reveal(CH, AGENT, {"signer": SIGNER, "nonce": "M" * 43}),
                         (200, {"state": "exists"}))
        self.assertEqual(self.relay.get_reveal(CH, PHONE), (200, {"nonce": nonce}))
        self.assertEqual(self.relay.get_reveal(CH, AGENT)[0], 401)

    def test_waiting_for_the_reveal_wakes_up_and_ends_with_the_device(self):
        self.pair()
        got = []
        t = threading.Thread(target=lambda: got.append(self.relay.get_reveal(CH, PHONE, wait=5)))
        t.start()
        time.sleep(0.1)
        self.relay.post_reveal(CH, AGENT, {"signer": SIGNER, "nonce": "N" * 43})
        t.join(5)
        self.assertEqual(got, [(200, {"nonce": "N" * 43})])
        self.relay.revoke(CH, PHONE)
        self.assertEqual(self.relay.get_reveal(CH, PHONE, wait=1)[0], 401)

    def test_a_reveal_is_stored_and_wakes_only_its_own_channel(self):
        self.pair()
        other = "e" * 32
        self.relay.create_channel(ENROLL, {
            "ch": other, "agent_auth": R.digest("agent2"), "pair_auth": R.digest("pair2"), "hello": "hi"})
        self.relay.post_pair(other, "pair2", {"signer": SIGNER, "signer_auth": R.digest("phone2"), "msg": "a"})
        got = []
        t = threading.Thread(target=lambda: got.append(self.relay.get_reveal(other, "phone2", wait=1)))
        t.start()
        time.sleep(0.1)
        self.relay.post_reveal(CH, AGENT, {"signer": SIGNER, "nonce": "N" * 43})
        t.join(5)
        # The other channel's device gets nothing: a reveal is per channel and device.
        self.assertEqual(got, [(204, None)])
        again = R.Relay(self.dir.name, ENROLL, self.push, self.clock)
        self.assertEqual(again.get_reveal(CH, PHONE), (200, {"nonce": "N" * 43}))
        self.assertEqual(again.get_reveal(other, "phone2"), (204, None))

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
                    "endpoint": "https://web.push.apple.com/x", "keys": KEYS})
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
        keys = KEYS
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
        self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": KEYS})
        self.assertEqual(self.request(), (200, {"state": "queued", "push": True}))
        self.assertTrue(self.push.done.wait(5))
        self.assertEqual(self.push.sent, [(APPLE, {"t": "sign"})])

    def test_a_gone_subscription_is_forgotten(self):
        self.pair()
        self.push.gone = True
        self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": KEYS})
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
        self.assertEqual(self.push.groups, [CH])

    def test_a_relay_without_apns_keeps_the_web_push_subscription(self):
        self.push.supports_apns = False
        self.pair()
        self.relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": KEYS})
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

    def send(self, sandbox=False, group=None):
        return self.apns.send({"apns": TOKEN, "sandbox": sandbox}, {"t": "sign"}, group)

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

    def test_a_channel_shows_one_notification_at_most(self):
        group = R.apns_group(CH)
        self.assertRegex(group, r"^[0-9a-f]{32}$")
        self.assertNotIn(CH, group)
        self.assertNotEqual(group, R.apns_group(CH + "x"))
        self.send(group=group)
        r = self.calls[0]
        self.assertEqual(r.headers["apns-collapse-id"], group)
        self.assertEqual(json.loads(r.content)["aps"]["thread-id"], group)
        self.send()
        self.assertNotIn("apns-collapse-id", self.calls[1].headers)
        self.assertNotIn("thread-id", json.loads(self.calls[1].content)["aps"])

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
        pushers.send({"apns": TOKEN, "sandbox": False}, {"t": "sign"}, group=CH)
        pushers.send({"endpoint": APPLE, "keys": {}}, {"t": "sign"}, group=CH)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0].headers["apns-collapse-id"], R.apns_group(CH))
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


class LimitsTest(unittest.TestCase):
    """Enrolment modes, every limit, the lifecycle, and the audit's
    proofs of concept turned into regression tests."""

    def make(self, enroll=None, **limits):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.clock = Clock()
        self.push = FakePush()
        relay = R.Relay(self.dir.name, enroll, self.push, self.clock, R.Limits(**limits))
        self.addCleanup(relay.close)
        return relay

    @staticmethod
    def channel(relay, ch=CH, ip=None, token=None, agent=AGENT, pair=PAIR):
        return relay.create_channel(token, {
            "ch": ch, "agent_auth": R.digest(agent), "pair_auth": R.digest(pair), "hello": "hi"}, ip)

    @classmethod
    def paired(cls, relay, ch=CH, agent=AGENT, phone=PHONE):
        cls.channel(relay, ch, agent=agent, pair="pair-" + ch)
        relay.post_pair(ch, "pair-" + ch, {"signer": SIGNER, "signer_auth": R.digest(phone), "msg": "a"})

    def request(self, relay, rid, ch=CH, msg="sealed", ttl=90):
        return relay.post_request(ch, AGENT, {"id": rid, "to": SIGNER, "exp": self.clock.t + ttl,
                                              "msg": msg})

    # -- enrolment --

    def test_open_enrolment_takes_any_token_or_none(self):
        relay = self.make()
        self.assertTrue(relay.open_enrolment)
        self.assertEqual(self.channel(relay, "1" * 32, token=None), (200, {"state": "created"}))
        self.assertEqual(self.channel(relay, "2" * 32, token=""), (200, {"state": "created"}))
        self.assertEqual(self.channel(relay, "3" * 32, token="any old secret"), (200, {"state": "created"}))

    def test_closed_enrolment_needs_the_secret(self):
        relay = self.make(ENROLL)
        self.assertFalse(relay.open_enrolment)
        self.assertEqual(self.channel(relay, token=None)[0], 401)
        self.assertEqual(self.channel(relay, token="wrong")[0], 401)
        self.assertEqual(self.channel(relay, token=ENROLL), (200, {"state": "created"}))

    def test_the_enrolment_mode_comes_from_the_environment(self):
        self.assertIsNone(R.enrolment_secret({}))
        self.assertIsNone(R.enrolment_secret({"RELAY_ENROLL_SECRET": ""}))
        self.assertEqual(R.enrolment_secret({"RELAY_ENROLL_SECRET": "s"}), "s")
        self.assertEqual(R.enrolment_secret({"RELAY_ENROLL_SECRET": "s", "RELAY_ENROLL": "closed"}), "s")
        self.assertIsNone(R.enrolment_secret({"RELAY_ENROLL_SECRET": "s", "RELAY_ENROLL": "open"}))
        for env in ({"RELAY_ENROLL": "closed"}, {"RELAY_ENROLL": "maybe", "RELAY_ENROLL_SECRET": "s"}):
            with self.assertRaises(ValueError):
                R.enrolment_secret(env)

    def test_limits_come_from_the_environment(self):
        self.assertEqual(R.Limits.from_env({}), R.Limits())
        limits = R.Limits.from_env({"RELAY_MAX_DEVICES": "2", "RELAY_TRUSTED_PROXIES": "0",
                                    "RELAY_PUSH_INTERVAL": "", "RELAY_OTHER": "x"})
        self.assertEqual((limits.max_devices, limits.trusted_proxies, limits.push_interval), (2, 0, 10))
        for env in ({"RELAY_MAX_DEVICES": "two"}, {"RELAY_MAX_DEVICES": "0"},
                    {"RELAY_TRUSTED_PROXIES": "-1"}):
            with self.assertRaises(ValueError):
                R.Limits.from_env(env)
        self.assertTrue(R.on_off({}, "RELAY_SERVE_WEB"))
        self.assertFalse(R.on_off({"RELAY_SERVE_WEB": "off"}, "RELAY_SERVE_WEB"))
        self.assertFalse(R.on_off({"RELAY_SERVE_WEB": "Off "}, "RELAY_SERVE_WEB"))

    # -- channels --

    def test_channels_per_address_per_hour_and_per_day(self):
        relay = self.make(channels_per_ip_hour=2, channels_per_ip_day=3)
        ip = "192.0.2.1"
        self.assertEqual(self.channel(relay, "1" * 32, ip)[1]["state"], "created")
        self.assertEqual(self.channel(relay, "1" * 32, ip)[1]["state"], "exists")   # not counted
        self.assertEqual(self.channel(relay, "2" * 32, ip)[1]["state"], "created")
        status, body = self.channel(relay, "3" * 32, ip)
        self.assertEqual(status, 429)
        self.assertTrue(3500 < body["retry_after"] <= 3600)
        self.assertEqual(self.channel(relay, "3" * 32, "192.0.2.2")[1]["state"], "created")
        self.clock.t += 3601
        self.assertEqual(self.channel(relay, "4" * 32, ip)[1]["state"], "created")
        status, body = self.channel(relay, "5" * 32, ip)
        self.assertEqual(status, 429)
        self.assertTrue(body["retry_after"] > 3600)   # the daily cap
        self.clock.t += 86400
        self.assertEqual(self.channel(relay, "5" * 32, ip)[1]["state"], "created")

    def test_the_global_safety_cap(self):
        relay = self.make(max_channels=2)
        for ch in ("1" * 32, "2" * 32):
            self.assertEqual(self.channel(relay, ch)[1]["state"], "created")
        self.assertEqual(self.channel(relay, "3" * 32), (200, {"state": "full"}))

    def test_devices_per_channel(self):
        relay = self.make(max_devices=1)
        self.paired(relay)
        self.assertEqual(relay.open_pairing(CH, AGENT, {"pair_auth": R.digest("p2"), "hello": "h"}),
                         (200, {"state": "full"}))

    def test_an_idle_channel_expires_paired_or_not(self):
        relay = self.make(channel_idle_days=90)
        self.paired(relay, "1" * 32)
        self.paired(relay, "2" * 32, agent="agent2", phone="phone2")
        self.clock.t += 60 * 86400
        self.assertEqual(relay.get_requests("2" * 32, "phone2")[0], 200)   # in use
        self.clock.t += 31 * 86400
        self.channel(relay, "3" * 32)   # any creation sweeps
        self.assertEqual(relay.get_requests("1" * 32, PHONE)[0], 401)
        self.assertNotIn("1" * 32, saved_state(self.dir.name))
        self.assertEqual(relay.get_requests("2" * 32, "phone2")[0], 200)
        # Activity is on disk too, so it survives a restart.
        self.clock.t += ACTIVITY_GRAIN_PLUS
        relay.get_requests("2" * 32, "phone2")
        again = R.Relay(self.dir.name, None, self.push, self.clock)
        self.addCleanup(again.close)
        self.assertEqual(again.channels["2" * 32]["last_active"], int(self.clock.t))

    def test_the_hello_is_not_kept_after_the_pairing_window(self):
        relay = self.make()
        self.paired(relay)
        self.clock.t += R.PAIR_WINDOW + R.SWEEP_EVERY + 1
        self.channel(relay, "3" * 32)
        self.assertIsNone(relay.channels[CH]["hello"])
        self.assertIsNone(relay.channels[CH]["answer"])
        self.assertNotIn('"hi"', saved_state(self.dir.name).split("\n")[0])

    def test_poc_filling_the_relay_with_channels(self):
        """Audit H3: 1000 paired channels used to lock out every new pairing
        for good. Now one address is stopped early, the cap is a high
        safety net, and idle channels go."""
        relay = self.make(max_channels=50)
        created = 0
        for i in range(1, 100):
            status, body = self.channel(relay, f"{i:032x}", ip="198.51.100.7", pair="p")
            if status == 429:
                break
            relay.post_pair(f"{i:032x}", "p", {"signer": SIGNER, "signer_auth": R.digest("s"), "msg": "m"})
            created += 1
        self.assertEqual(created, R.Limits().channels_per_ip_hour)
        # Many addresses reach the safety cap...
        for i in range(100, 200):
            if self.channel(relay, f"{i:032x}", ip=f"203.0.113.{i - 99}", pair="p")[1]["state"] == "full":
                break
            relay.post_pair(f"{i:032x}", "p", {"signer": SIGNER, "signer_auth": R.digest("s"), "msg": "m"})
        self.assertEqual(len(relay.channels), 50)
        self.assertEqual(self.channel(relay, "f" * 32, ip="192.0.2.9"), (200, {"state": "full"}))
        # ...and idle expiry frees it without the operator.
        self.clock.t += 91 * 86400
        self.assertEqual(self.channel(relay, "f" * 32, ip="192.0.2.9"), (200, {"state": "created"}))

    # -- requests --

    def test_requests_per_channel_per_minute(self):
        relay = self.make(requests_per_minute=3)
        self.paired(relay)
        for i in range(3):
            self.assertEqual(self.request(relay, f"{i:032x}")[1]["state"], "queued")
        status, body = self.request(relay, "f" * 32)
        self.assertEqual((status, body["retry_after"]), (429, 60))
        self.clock.t += 61
        self.assertEqual(self.request(relay, "f" * 32)[1]["state"], "queued")

    def test_messages_are_capped(self):
        relay = self.make(max_msg=100)
        self.paired(relay)
        self.assertEqual(self.request(relay, RID, msg="x" * 101)[0], 400)
        self.assertEqual(self.request(relay, RID, msg="x" * 100)[1]["state"], "queued")
        self.assertEqual(relay.post_response(CH, PHONE, RID, {"msg": "y" * 101})[0], 400)
        self.assertEqual(relay.post_response(CH, PHONE, RID, {"msg": "y" * 100})[1]["state"], "accepted")
        self.assertEqual(R.Limits().max_msg, 16 * 1024)

    def test_the_global_budget_for_pending_data(self):
        relay = self.make(pending_budget=250)
        self.paired(relay)
        self.assertEqual(self.request(relay, "1" * 32, msg="x" * 200)[1]["state"], "queued")
        status, body = self.request(relay, "2" * 32, msg="x" * 100)
        self.assertEqual((status, body["retry_after"]), (503, 5))
        relay.cancel(CH, AGENT, "1" * 32)   # frees its bytes at once
        self.assertEqual(relay.pending_bytes, 0)
        self.assertEqual(self.request(relay, "2" * 32, msg="x" * 100)[1]["state"], "queued")

    def test_every_stored_entry_counts_and_data_is_dropped(self):
        relay = self.make(max_entries=4, max_pending=8, requests_per_minute=1000)
        self.paired(relay)
        self.request(relay, "1" * 32)
        relay.cancel(CH, AGENT, "1" * 32)
        self.assertIsNone(relay.pending[CH]["1" * 32]["msg"])   # cancelled: msg dropped
        self.request(relay, "2" * 32)
        relay.post_response(CH, PHONE, "2" * 32, {"msg": "signed"})
        self.assertIsNone(relay.pending[CH]["2" * 32]["msg"])   # answered: msg dropped
        self.assertEqual(relay.get_response(CH, AGENT, "2" * 32)[1]["msg"], "signed")
        self.request(relay, "3" * 32)
        self.request(relay, "4" * 32)
        self.assertEqual(self.request(relay, "5" * 32), (200, {"state": "busy"}))
        # Kept KEEP_AFTER_EXPIRY past their expiry, then gone.
        self.clock.t += 90 + R.KEEP_AFTER_EXPIRY + 1
        self.assertEqual(self.request(relay, "5" * 32)[1]["state"], "queued")
        self.assertEqual(list(relay.pending[CH]), ["5" * 32])
        self.assertEqual(relay.pending_bytes, len("sealed"))

    def test_poc_cancel_loop_no_longer_grows_memory(self):
        """Audit H4: post then cancel, 2000 times with 60 KB each, used to
        hold 2000 entries and 120 MB."""
        relay = self.make(max_msg=60000, requests_per_minute=10 ** 6)
        self.paired(relay)
        big = "A" * 60000
        states = collections.Counter()
        for i in range(2000):
            rid = f"{i:032x}"
            states[self.request(relay, rid, msg=big)[1]["state"]] += 1
            relay.cancel(CH, AGENT, rid)
        self.assertEqual(states["queued"], R.Limits().max_entries)
        self.assertEqual(states["busy"], 2000 - R.Limits().max_entries)
        self.assertLessEqual(len(relay.pending[CH]), R.Limits().max_entries)
        self.assertEqual(relay.pending_bytes, 0)
        # Answering instead of cancelling holds no request bytes either.
        relay2 = self.make(requests_per_minute=10 ** 6)
        self.paired(relay2)
        for i in range(100):
            rid = f"{i:032x}"
            if self.request(relay2, rid, msg="x" * 16000)[1]["state"] == "queued":
                relay2.post_response(CH, PHONE, rid, {"msg": "y" * 100})
        self.assertLessEqual(len(relay2.pending[CH]), R.Limits().max_entries)
        self.assertEqual(relay2.pending_bytes, 100 * len(relay2.pending[CH]))
        # And with the default rate limit, the loop is stopped at once anyway.
        relay3 = self.make()
        self.paired(relay3)
        codes = [self.request(relay3, f"{i:032x}")[0] for i in range(100)]
        self.assertEqual(codes.count(429), 100 - R.Limits().requests_per_minute)

    # -- push --

    def subscribe(self, relay, ch=CH, phone=PHONE, token=TOKEN):
        return relay.put_subscription(ch, phone, {"apns": token, "sandbox": False})

    def wait_pushes(self, n):
        for _ in range(250):
            if len(self.push.sent) >= n:
                break
            threading.Event().wait(0.02)
        threading.Event().wait(0.05)
        return len(self.push.sent)

    def test_pushes_per_interval_and_per_day(self):
        relay = self.make(push_interval=10, push_per_day=3, requests_per_minute=1000)
        self.paired(relay)
        self.subscribe(relay)
        pushed = []
        for i in range(6):
            rid = f"{i:032x}"
            pushed.append(self.request(relay, rid)[1]["push"])
            relay.cancel(CH, AGENT, rid)
            pushed.append(self.request(relay, "f" * 31 + str(i))[1]["push"])   # within 10 s
            relay.cancel(CH, AGENT, "f" * 31 + str(i))
            self.clock.t += 11
        self.assertEqual(pushed, [True, False] * 3 + [False, False] * 3)
        self.assertEqual(self.wait_pushes(3), 3)

    def test_pushes_are_limited_per_device_across_channels(self):
        relay = self.make(push_interval=10, requests_per_minute=1000)
        self.paired(relay, "1" * 32)
        self.paired(relay, "2" * 32, phone="phone2")
        self.subscribe(relay, "1" * 32)
        self.assertTrue(self.request(relay, "1" * 32, ch="1" * 32)[1]["push"])
        # The same device token registered on another channel moves there...
        self.subscribe(relay, "2" * 32, "phone2")
        self.assertIsNone(relay.channels["1" * 32]["signers"][SIGNER]["sub"])
        self.assertEqual(relay.channels["2" * 32]["signers"][SIGNER]["sub"]["apns"], TOKEN)
        self.assertNotIn(TOKEN, saved_state(self.dir.name).split("\n")[0])
        self.assertFalse(self.request(relay, "2" * 32, ch="1" * 32)[1]["push"])
        # ...and keeps its own push budget: no second push within 10 s.
        self.assertFalse(self.request(relay, "3" * 32, ch="2" * 32)[1]["push"])
        self.clock.t += 11
        self.assertTrue(self.request(relay, "4" * 32, ch="2" * 32)[1]["push"])

    def test_poc_junk_token_cannot_make_the_relay_hammer_apns(self):
        """Audit M3: a junk (or someone else's) token and a request loop
        used to send one push, on its own thread, per request."""
        relay = self.make(requests_per_minute=10 ** 6)
        self.paired(relay)
        self.assertEqual(self.subscribe(relay, token="ee" * 32), (200, {"state": "stored"}))
        threads = threading.active_count()
        for i in range(200):
            rid = f"{i:032x}"
            self.request(relay, rid)
            relay.cancel(CH, AGENT, rid)
        self.assertEqual(self.wait_pushes(1), 1)
        self.assertLessEqual(threading.active_count(), threads + R.Limits().push_workers)

    def test_the_push_queue_is_bounded(self):
        q = R.PushQueue(1, 1)
        gate = threading.Event()
        started = threading.Event()

        def slow():
            started.set()
            gate.wait(5)
        self.assertTrue(q.submit(slow))
        started.wait(5)
        self.assertTrue(q.submit(slow))    # waits in the queue
        self.assertFalse(q.submit(slow))   # dropped
        gate.set()

    def test_web_push_keys_are_checked_at_subscription(self):
        relay = self.make()
        self.paired(relay)
        point = R.b64u(b"\x04" + b"\x01" * 64)   # 65 bytes, not on the curve
        for keys in ({"p256dh": "x", "auth": "y"}, {"p256dh": KEYS["p256dh"], "auth": "y"},
                     {"p256dh": point, "auth": KEYS["auth"]},
                     {"p256dh": KEYS["p256dh"], "auth": R.b64u(os.urandom(17))},
                     {"p256dh": KEYS["p256dh"] + "!", "auth": KEYS["auth"]},
                     {"p256dh": KEYS["p256dh"]}, None, "keys"):
            self.assertEqual(relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": keys})[0],
                             400, keys)
        self.assertEqual(relay.put_subscription(CH, PHONE, {"endpoint": APPLE + "x" * 1024,
                                                            "keys": KEYS})[0], 400)
        padded = {"p256dh": KEYS["p256dh"] + "=", "auth": KEYS["auth"] + "=="}
        self.assertEqual(relay.put_subscription(CH, PHONE, {"endpoint": APPLE, "keys": padded}),
                         (200, {"state": "stored"}))

    # -- long-polls --

    def test_concurrent_long_polls_per_token_and_per_address(self):
        relay = self.make(polls_per_token=2, polls_per_ip=3)
        a = relay.acquire_poll("t1", "192.0.2.1")
        b = relay.acquire_poll("t1", "192.0.2.1")
        self.assertIsNone(relay.acquire_poll("t1", "192.0.2.2"))   # token at its limit
        c = relay.acquire_poll("t2", "192.0.2.1")
        self.assertIsNone(relay.acquire_poll("t3", "192.0.2.1"))   # address at its limit
        self.assertIsNotNone(relay.acquire_poll("t3", "192.0.2.2"))
        a()
        self.assertIsNotNone(relay.acquire_poll("t1", "192.0.2.3"))
        b(), c()
        self.assertIsNotNone(relay.acquire_poll("t4", "192.0.2.1"))

    # -- storage --

    def test_the_old_json_state_is_imported_once(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        old = {"channels": {CH: {"agent_auth": R.digest(AGENT), "pair_auth": None, "hello": "",
                                 "answer": None, "created": 1, "pair_until": 901,
                                 "signers": {SIGNER: {"auth": R.digest(PHONE), "sub": None}}}}}
        with open(os.path.join(self.dir.name, "state.json"), "w", encoding="utf-8") as f:
            json.dump(old, f)
        relay = R.Relay(self.dir.name, None, FakePush(), Clock())
        self.addCleanup(relay.close)
        self.assertEqual(relay.get_requests(CH, PHONE), (200, {"requests": []}))
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "state.json")))
        self.assertTrue(os.path.exists(os.path.join(self.dir.name, "state.json.migrated")))
        self.assertIn(CH, saved_state(self.dir.name))
        self.assertEqual(os.stat(os.path.join(self.dir.name, "state.db")).st_mode & 0o077, 0)
        db = sqlite3.connect(os.path.join(self.dir.name, "state.db"))
        self.addCleanup(db.close)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_an_event_wakes_only_its_own_channel(self):
        relay = self.make()
        self.paired(relay, "1" * 32)
        self.assertIsNot(relay._cond("1" * 32), relay._cond("2" * 32))
        wakes = []
        cond = relay._cond("2" * 32)
        original = cond.wait
        cond.wait = lambda t=None: (wakes.append(1), original(t))[1]
        self.paired(relay, "2" * 32, agent="agent2", phone="phone2")
        waiter = threading.Thread(target=relay.get_requests, args=("2" * 32, "phone2", 0.5, set()))
        waiter.start()
        threading.Event().wait(0.1)
        self.request(relay, "1" * 32, ch="1" * 32)   # another channel: no wake-up
        waiter.join(5)
        self.assertEqual(len(wakes), 1)


ACTIVITY_GRAIN_PLUS = R.ACTIVITY_GRAIN + 1


class ClientAddressTest(unittest.TestCase):
    def test_the_peer_unless_proxies_are_trusted(self):
        self.assertEqual(R.client_address("192.0.2.1", "198.51.100.1", 0), "192.0.2.1")
        self.assertEqual(R.client_address("10.0.0.1", "198.51.100.1", 1), "198.51.100.1")
        # A client cannot spoof by sending its own header: proxies append.
        self.assertEqual(R.client_address("10.0.0.1", "6.6.6.6, 198.51.100.1", 1), "198.51.100.1")
        self.assertEqual(R.client_address("10.0.0.1", "6.6.6.6, 198.51.100.1, 10.0.0.2", 2),
                         "198.51.100.1")
        self.assertEqual(R.client_address("10.0.0.1", None, 1), "10.0.0.1")
        self.assertEqual(R.client_address("10.0.0.1", "junk", 1), "10.0.0.1")

    def test_a_proxy_set_header_fails_closed(self):
        self.assertEqual(R.header_address("8.8.4.4"), "8.8.4.4")
        self.assertEqual(R.header_address(" 2606:4700::1 "), "2606:4700::/64")
        for value in (None, "", "junk", "10.0.0.1", "192.168.1.1", "127.0.0.1", "::1",
                      "169.254.1.1", "fe80::1", "0.0.0.0", "8.8.4.4, 1.1.1.1"):
            self.assertEqual(R.header_address(value), R.UNKNOWN_CLIENT, value)

    def test_ipv6_counts_by_64(self):
        self.assertEqual(R.client_address("2001:db8:1:2:3:4:5:6", None, 0), "2001:db8:1:2::/64")
        self.assertEqual(R.client_address("2001:db8:1:2::9", None, 0), "2001:db8:1:2::/64")
        self.assertEqual(R.client_address("::ffff:192.0.2.1", None, 0), "192.0.2.1")


class HttpLimitsTest(unittest.TestCase):
    def start(self, enroll=None, serve_web=True, ip_header=None, **limits):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        web = os.path.join(self.dir.name, "web")
        os.makedirs(web)
        with open(os.path.join(web, "index.html"), "w", encoding="utf-8") as f:
            f.write("<!doctype html>")
        server = R.serve("127.0.0.1", 0, os.path.join(self.dir.name, "state"), enroll, web,
                         "mailto:test@example.com", False, serve_web=serve_web,
                         limits=R.Limits(**limits), ip_header=ip_header)
        self.port = server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    call = HttpTest.call

    def create(self, ch=CH, token=None, headers=None):
        body = json.dumps({"ch": ch, "agent_auth": R.digest(AGENT), "pair_auth": R.digest(PAIR),
                           "hello": "hi"}).encode()
        req = urllib.request.Request(self.base + "/api/channels", data=body, method="POST",
                                     headers={**({"Authorization": f"Bearer {token}"} if token else {}),
                                              **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, e.headers, json.loads(e.read())

    def test_open_enrolment_over_http_and_429_with_retry_after(self):
        self.start(channels_per_ip_hour=1)
        self.assertEqual(self.create()[2], {"state": "created"})   # no Authorization at all
        status, headers, body = self.create("1" * 32, token="whatever")
        self.assertEqual(status, 429)
        self.assertEqual(headers["Retry-After"], str(body["retry_after"]))

    def test_closed_enrolment_over_http(self):
        self.start(ENROLL)
        self.assertEqual(self.create()[0], 401)
        self.assertEqual(self.create(token=ENROLL)[2], {"state": "created"})

    def test_forwarded_for_is_used_only_behind_trusted_proxies(self):
        self.start(channels_per_ip_hour=1, trusted_proxies=1)
        self.assertEqual(self.create("1" * 32, headers={"X-Forwarded-For": "192.0.2.1"})[0], 200)
        self.assertEqual(self.create("2" * 32, headers={"X-Forwarded-For": "192.0.2.1"})[0], 429)
        self.assertEqual(self.create("3" * 32, headers={"X-Forwarded-For": "192.0.2.2"})[0], 200)
        self.start(channels_per_ip_hour=1)   # no trusted proxy: the header is ignored
        self.assertEqual(self.create("1" * 32, headers={"X-Forwarded-For": "192.0.2.1"})[0], 200)
        self.assertEqual(self.create("2" * 32, headers={"X-Forwarded-For": "192.0.2.2"})[0], 429)

    def test_the_client_address_header_is_the_only_source_when_set(self):
        self.start(channels_per_ip_hour=1, trusted_proxies=1, ip_header="X-Real-IP")
        h = {"X-Real-IP": "8.8.4.4", "X-Forwarded-For": "9.9.9.9"}
        self.assertEqual(self.create("1" * 32, headers=h)[0], 200)
        self.assertEqual(self.create("2" * 32, headers={**h, "X-Forwarded-For": "1.1.1.1"})[0], 429)
        self.assertEqual(self.create("3" * 32, headers={"X-Real-IP": "8.8.8.8"})[0], 200)
        # Missing or private: one shared bucket, never the forwarded header.
        self.assertEqual(self.create("4" * 32, headers={"X-Forwarded-For": "1.1.1.1"})[0], 200)
        for headers in ({}, {"X-Real-IP": "10.1.2.3"}, {"X-Real-IP": "127.0.0.1"},
                        {"X-Real-IP": "fe80::1"}, {"X-Real-IP": "junk"}):
            self.assertEqual(self.create("5" * 32, headers=headers)[0], 429, headers)

    def test_the_body_is_capped(self):
        self.start(max_body=1024)
        status = self.call("POST", "/api/channels", raw=b'{"x":"' + b"a" * 1100 + b'"}')[0]
        self.assertEqual(status, 400)

    def test_long_polls_over_their_limit_get_429(self):
        server = self.start(polls_per_token=1)
        relay = server.relay
        relay.create_channel(None, {"ch": CH, "agent_auth": R.digest(AGENT),
                                    "pair_auth": R.digest(PAIR), "hello": "hi"})
        relay.post_pair(CH, PAIR, {"signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "a"})
        first = threading.Thread(target=self.call, args=(
            "GET", f"/api/ch/{CH}/requests?wait=2&known=", None, PHONE))
        first.start()
        threading.Event().wait(0.3)
        status, headers, _ = self.call("GET", f"/api/ch/{CH}/requests?wait=2&known=", token=PHONE)
        self.assertEqual((status, headers["Retry-After"]), (429, "10"))
        self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests", token=PHONE)[0], 200)   # no wait
        first.join(5)
        self.assertEqual(self.call("GET", f"/api/ch/{CH}/requests?wait=0.1&known=", token=PHONE)[0], 200)

    def test_the_reveal_over_http_and_within_the_limits(self):
        server = self.start(polls_per_token=1, max_body=1024)
        relay = server.relay
        relay.create_channel(None, {"ch": CH, "agent_auth": R.digest(AGENT),
                                    "pair_auth": R.digest(PAIR), "hello": "hi"})
        relay.post_pair(CH, PAIR, {"signer": SIGNER, "signer_auth": R.digest(PHONE), "msg": "a"})
        path = f"/api/ch/{CH}/pair/reveal"
        # Tokens: the agent posts, the device reads; nobody else.
        self.assertEqual(self.call("GET", path, token=PHONE)[0], 204)
        self.assertEqual(self.call("GET", path, token=AGENT)[0], 401)
        self.assertEqual(self.call("GET", path, token=PAIR)[0], 401)
        self.assertEqual(self.call("POST", path, token=PHONE, body={"signer": SIGNER, "nonce": "N" * 43})[0], 401)
        self.assertEqual(self.call("POST", path, token=AGENT, body={"signer": SIGNER, "nonce": "x"})[0], 400)
        # The body cap applies as on every route.
        self.assertEqual(self.call("POST", path, token=AGENT, raw=b'{"x":"' + b"a" * 1100 + b'"}')[0], 400)
        # The long-poll counts against the token's slots.
        first = threading.Thread(target=self.call, args=("GET", f"{path}?wait=2", None, PHONE))
        first.start()
        threading.Event().wait(0.3)
        self.assertEqual(self.call("GET", f"{path}?wait=2", token=PHONE)[0], 429)
        status, _, body = self.call("POST", path, token=AGENT, body={"signer": SIGNER, "nonce": "N" * 43})
        self.assertEqual((status, json.loads(body)), (200, {"state": "revealed"}))
        first.join(5)
        status, _, body = self.call("GET", f"{path}?wait=1", token=PHONE)
        self.assertEqual((status, json.loads(body)), (200, {"nonce": "N" * 43}))

    def test_without_the_page_only_the_api_and_health_answer(self):
        self.start(serve_web=False)
        self.assertEqual(self.call("GET", "/")[0], 404)
        self.assertEqual(self.call("GET", "/index.html")[0], 404)
        self.assertEqual(self.call("GET", "/favicon.ico")[0], 404)
        self.assertEqual(json.loads(self.call("GET", "/healthz")[2]), {"ok": True})
        self.assertEqual(self.create()[2], {"state": "created"})
        self.start(serve_web=True)
        self.assertEqual(self.call("GET", "/")[0], 200)
        self.assertEqual(json.loads(self.call("GET", "/healthz")[2]), {"ok": True})

    def test_a_silent_client_is_dropped(self):
        self.start(socket_timeout=1)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"POST /api/channels HTTP/1.1\r\nContent-Length: 100\r\n\r\n{")
            started = time.monotonic()
            self.assertEqual(s.recv(100), b"")   # closed by the server
            self.assertLess(time.monotonic() - started, 4)

    def test_connections_are_capped(self):
        self.start(max_connections=1, socket_timeout=5)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as idle:
            idle.sendall(b"GET /healthz HTTP/1.1\r\n")   # holds the only slot
            threading.Event().wait(0.2)
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
                self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 503"))
        for _ in range(50):   # the slot comes back once the first one is gone
            try:
                if self.call("GET", "/healthz")[0] == 200:
                    break
            except OSError:
                pass
            threading.Event().wait(0.1)
        self.assertEqual(self.call("GET", "/healthz")[0], 200)


if __name__ == "__main__":
    unittest.main()
