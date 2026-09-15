"""Team sync transport: handshake mutual authentication, framing, and both
transport implementations (docs/team-sync.md sections 6.1-6.2, stage 2 test
list in section 13).
"""

from __future__ import annotations

import socket
import threading
import time
import unittest

from zeropw.crypto import chacha20poly1305 as aead
from zeropw.errors import InvalidInput
from zeropw.team import commit as C
from zeropw.team.identity import DeviceKey
from zeropw.team import transport as T


def _membership_of(*devices: DeviceKey, env_id: str | None = None):
    """A membership callback scoped to one environment id (``None`` = accept for every env id,
    used only where the test does not care -- section 6.2's real check is always per-env)."""
    records = {d.fingerprint: d.record for d in devices}

    def membership(candidate_env_id: str, fingerprint: str):
        if env_id is not None and candidate_env_id != env_id:
            return None
        return records.get(fingerprint)

    return membership


class _OneShotChannel:
    """A test-only channel that hands back one canned response, then nothing."""

    def __init__(self, response: bytes | None) -> None:
        self.sent: list[bytes] = []
        self._pending = response

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, timeout: float) -> bytes | None:
        response, self._pending = self._pending, None
        return response

    def close(self) -> None:
        pass


class InProcessHandshakeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.a = DeviceKey.generate()
        self.b = DeviceKey.generate()
        self.env_id = C.new_env_id(self.a.fingerprint)
        self.membership = _membership_of(self.a, self.b, env_id=self.env_id)

    def test_mutual_handshake_and_message_exchange(self) -> None:
        ta = T.InProcessTransport(self.a, self.membership)
        tb = T.InProcessTransport(self.b, self.membership)
        accepted: list[T.Session] = []
        tb.listen("addr-b", accepted.append)

        session = ta.dial("addr-b", self.env_id)
        self.assertEqual(session.peer.fingerprint, self.b.fingerprint)
        self.assertEqual(session.env_id, self.env_id)
        deadline = time.monotonic() + 5
        while not accepted and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(accepted), 1)
        responder_session = accepted[0]
        self.assertEqual(responder_session.peer.fingerprint, self.a.fingerprint)

        session.send({"type": "PING", "n": 1})
        self.assertEqual(responder_session.recv(2.0), {"type": "PING", "n": 1})
        responder_session.send({"type": "PONG"})
        self.assertEqual(session.recv(2.0), {"type": "PONG"})

        session.close()
        responder_session.close()

    def test_non_member_refused_no_bytes(self) -> None:
        mallory = DeviceKey.generate()
        failures = []
        tb = T.InProcessTransport(self.b, self.membership, on_handshake_failed=lambda r, fp: failures.append((r, fp)))
        tb.listen("addr-b2", lambda s: self.fail("responder must not accept a non-member"))
        tm = T.InProcessTransport(mallory, self.membership)
        with self.assertRaises(T.SessionClosed):
            tm.dial("addr-b2", self.env_id)
        self.assertEqual(failures, [("not_member", mallory.fingerprint)])

    def test_removed_member_refused(self) -> None:
        """A membership callback that no longer names a fingerprint acts exactly like non-membership."""
        removed = DeviceKey.generate()
        live_membership = _membership_of(self.a, self.b, env_id=self.env_id)  # `removed` is deliberately absent
        failures = []
        tb = T.InProcessTransport(self.b, live_membership, on_handshake_failed=lambda r, fp: failures.append((r, fp)))
        tb.listen("addr-b3", lambda s: self.fail("responder must not accept a removed member"))
        tr = T.InProcessTransport(removed, live_membership)
        with self.assertRaises(T.SessionClosed):
            tr.dial("addr-b3", self.env_id)
        self.assertEqual(failures, [("not_member", removed.fingerprint)])


class WhiteBoxHandshakeTestCase(unittest.TestCase):
    """Exercises ``_respond``/``_initiate`` directly to control exactly what bytes are on the wire."""

    def setUp(self) -> None:
        self.a = DeviceKey.generate()
        self.b = DeviceKey.generate()
        self.env_id = C.new_env_id(self.a.fingerprint)
        self.membership = _membership_of(self.a, self.b, env_id=self.env_id)

    def _msg1_bytes(self, device: DeviceKey, env_id: str, ea_pub: bytes, nonce: bytes | None = None) -> bytes:
        import secrets as _secrets

        nonce = nonce or _secrets.token_bytes(32)
        return T._canon({"version": T.PROTOCOL_VERSION, "env_id": env_id, "ea": T._b64e(ea_pub),
                         "device": device.record.to_dict(), "nonce": T._b64e(nonce)})

    def test_env_id_mismatch_refused(self) -> None:
        other_env = C.new_env_id(self.a.fingerprint)  # a validly-shaped but different environment
        from zeropw.crypto import x25519

        ea_priv = x25519.generate_private()
        msg1 = self._msg1_bytes(self.a, other_env, x25519.public_key(ea_priv))
        channel = _OneShotChannel(msg1)
        with self.assertRaises(T.HandshakeFailed) as cm:
            T._respond(channel, self.b, self.membership, None)
        self.assertEqual(cm.exception.reason, "not_member")
        self.assertEqual(channel.sent, [])

    def test_invalid_env_id_format_refused(self) -> None:
        from zeropw.crypto import x25519

        ea_priv = x25519.generate_private()
        msg1 = self._msg1_bytes(self.a, "not-a-valid-env-id", x25519.public_key(ea_priv))
        channel = _OneShotChannel(msg1)
        with self.assertRaises(T.HandshakeFailed) as cm:
            T._respond(channel, self.b, self.membership, None)
        self.assertEqual(cm.exception.reason, "invalid_env_id")
        self.assertEqual(channel.sent, [])

    def test_low_order_ephemeral_point_refused(self) -> None:
        msg1 = self._msg1_bytes(self.a, self.env_id, b"\x00" * 32)
        channel = _OneShotChannel(msg1)
        with self.assertRaises(T.HandshakeFailed) as cm:
            T._respond(channel, self.b, self.membership, None)
        self.assertEqual(cm.exception.reason, "low_order_point")
        self.assertEqual(channel.sent, [])

    def test_replayed_msg2_from_previous_session_refused(self) -> None:
        import queue

        recorded: list[bytes] = []

        class _RecordingChannel:
            def __init__(self, inner) -> None:
                self._inner = inner

            def send(self, data: bytes) -> None:
                recorded.append(data)
                self._inner.send(data)

            def recv(self, timeout: float):
                return self._inner.recv(timeout)

            def close(self) -> None:
                self._inner.close()

        to_b: "queue.Queue" = queue.Queue()
        to_a: "queue.Queue" = queue.Queue()
        initiator_channel = T._QueueChannel(inbox=to_a, outbox=to_b)
        responder_channel = _RecordingChannel(T._QueueChannel(inbox=to_b, outbox=to_a))

        responder_result: dict = {}

        def run_responder() -> None:
            responder_result["session"] = T._respond(responder_channel, self.b, self.membership, None)

        thread = threading.Thread(target=run_responder, daemon=True)
        thread.start()
        first_session = T._initiate(initiator_channel, self.a, self.env_id, self.membership)
        thread.join(timeout=5)
        self.assertIn("session", responder_result)
        self.assertEqual(len(recorded), 1)
        old_msg2 = recorded[0]
        first_session.close()
        responder_result["session"].close()

        # A brand new handshake attempt: the "responder" hands back the OLD msg2 verbatim.  The
        # new attempt's own msg1 (fresh Ea/nonce) makes the transcript differ, so the signature
        # inside the replayed msg2 must fail verification.
        replay_channel = _OneShotChannel(None)

        class _ReplayChannel:
            def __init__(self, canned: bytes) -> None:
                self.sent: list[bytes] = []
                self._canned = canned

            def send(self, data: bytes) -> None:
                self.sent.append(data)

            def recv(self, timeout: float):
                canned, self._canned = self._canned, None
                return canned

            def close(self) -> None:
                pass

        channel = _ReplayChannel(old_msg2)
        with self.assertRaises(T.HandshakeFailed) as cm:
            T._initiate(channel, self.a, self.env_id, self.membership)
        self.assertEqual(cm.exception.reason, "signature_invalid")

    def test_responder_signature_presented_as_initiator_signature_refused(self) -> None:
        """G2 regression: msg2/msg3 signatures carry disjoint role prefixes, so the SAME device
        signing the SAME transcript bytes with the wrong role's context must not verify."""
        import json
        import queue

        from zeropw.crypto import x25519
        from zeropw.team.identity import DeviceRecord

        ea_priv = x25519.generate_private()
        ea_pub = x25519.public_key(ea_priv)
        msg1_raw = self._msg1_bytes(self.a, self.env_id, ea_pub)

        inbox: "queue.Queue" = queue.Queue()
        inbox.put(msg1_raw)

        class _QueueLikeChannel:
            def __init__(self, q: "queue.Queue") -> None:
                self._q = q
                self.sent: list[bytes] = []

            def send(self, data: bytes) -> None:
                self.sent.append(data)

            def recv(self, timeout: float):
                try:
                    return self._q.get(timeout=timeout)
                except queue.Empty:
                    return None

            def close(self) -> None:
                pass

        channel = _QueueLikeChannel(inbox)
        result: dict = {}

        def run_responder() -> None:
            try:
                result["session"] = T._respond(channel, self.b, self.membership, None)
            except T.HandshakeFailed as exc:
                result["error"] = exc

        thread = threading.Thread(target=run_responder, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while not channel.sent and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(channel.sent, "responder never sent msg2")
        msg2 = json.loads(channel.sent[0].decode("utf-8"))
        eb_pub = T._b64d(msg2["eb"])
        responder_record = DeviceRecord.from_dict(msg2["device"])
        transcript = T._transcript(msg1_raw, eb_pub, responder_record)

        # A genuine RESPONDER-role signature by the initiator's own key over this exact
        # transcript, submitted where an INITIATOR-role signature (msg3) is expected.
        forged_sig = self.a.sign(T.HANDSHAKE_RESPONDER_CONTEXT + transcript)
        inbox.put(T._canon({"sig": T._b64e(forged_sig)}))
        thread.join(timeout=5)
        self.assertIn("error", result, "the mis-rolled signature was wrongly accepted")
        self.assertEqual(result["error"].reason, "signature_invalid")
        self.assertNotIn("session", result)
        # The initiator never got far enough to send a (useless) msg3.
        self.assertEqual(len(channel.sent), 1)  # only its own msg1


class TcpTransportTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.a = DeviceKey.generate()
        self.b = DeviceKey.generate()
        self.env_id = C.new_env_id(self.a.fingerprint)
        self.membership = _membership_of(self.a, self.b, env_id=self.env_id)
        self._transports: list[T.TcpTransport] = []

    def tearDown(self) -> None:
        for transport in self._transports:
            transport.close()

    def _listener(self, device: DeviceKey, on_session, membership=None) -> T.TcpTransport:
        transport = T.TcpTransport(device, membership or self.membership)
        transport.listen("127.0.0.1:0", on_session)
        self._transports.append(transport)
        deadline = time.monotonic() + 5
        while transport.bound_address is None and time.monotonic() < deadline:
            time.sleep(0.01)
        return transport

    def test_mutual_handshake_over_real_socket(self) -> None:
        accepted: list[T.Session] = []
        tb = self._listener(self.b, accepted.append)
        ta = T.TcpTransport(self.a, self.membership)
        self._transports.append(ta)
        session = ta.dial(tb.bound_address, self.env_id)
        self.assertEqual(session.peer.fingerprint, self.b.fingerprint)
        deadline = time.monotonic() + 5
        while not accepted and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(accepted), 1)
        session.send({"hello": "world"})
        self.assertEqual(accepted[0].recv(2.0), {"hello": "world"})
        session.close()
        accepted[0].close()

    def test_non_member_refused_socket_eof(self) -> None:
        """A raw socket connecting to a non-member address gets zero bytes back, then EOF."""
        mallory = DeviceKey.generate()
        accepted: list[T.Session] = []
        tb = self._listener(self.b, accepted.append)

        from zeropw.crypto import x25519

        ea_priv = x25519.generate_private()
        msg1 = T._canon({"version": T.PROTOCOL_VERSION, "env_id": self.env_id, "ea": T._b64e(x25519.public_key(ea_priv)),
                         "device": mallory.record.to_dict(), "nonce": T._b64e(b"\x00" * 32)})
        host, port = tb.bound_address.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, int(port)))
        sock.sendall(len(msg1).to_bytes(4, "big") + msg1)
        received = sock.recv(4096)
        self.assertEqual(received, b"")  # EOF: the responder closed without sending anything
        sock.close()
        self.assertEqual(accepted, [])

    def test_frame_tampering_closes_session(self) -> None:
        accepted: list[T.Session] = []
        tb = self._listener(self.b, accepted.append)
        ta = T.TcpTransport(self.a, self.membership)
        self._transports.append(ta)
        session = ta.dial(tb.bound_address, self.env_id)
        deadline = time.monotonic() + 5
        while not accepted and time.monotonic() < deadline:
            time.sleep(0.01)
        responder_session = accepted[0]

        # Legitimate traffic first, to prove the channel really works before we break it.
        session.send({"ok": True})
        self.assertEqual(responder_session.recv(2.0), {"ok": True})

        # Craft the NEXT frame with the correct key/nonce sequence, then flip one ciphertext byte
        # (this lands inside the Poly1305 tag on a small payload, which is exactly the case the
        # AEAD tag exists to catch).
        payload = T._canon({"tampered": True})
        nonce = session._tag_out + session._send_counter.to_bytes(8, "big")
        session._send_counter += 1
        ciphertext = bytearray(aead.encrypt(session._send_key, nonce, payload, b""))
        ciphertext[-1] ^= 0xFF
        frame = bytes(ciphertext)
        session._channel._sock.sendall(len(frame).to_bytes(4, "big") + frame)

        with self.assertRaises(T.SessionClosed):
            responder_session.recv(5.0)
        self.assertTrue(responder_session.closed)
        session.close()

    def test_max_connections_enforced(self) -> None:
        accepted: list[T.Session] = []
        tb = self._listener(self.b, accepted.append)
        tb.max_connections = 1
        tb._connection_semaphore = threading.Semaphore(1)
        ta1 = T.TcpTransport(self.a, self.membership)
        self._transports.append(ta1)
        session1 = ta1.dial(tb.bound_address, self.env_id)
        deadline = time.monotonic() + 5
        while not accepted and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(accepted), 1)

        other = DeviceKey.generate()
        # `other` is not even a member, but the point here is the connection is refused before
        # the handshake has a chance to run at all, because the concurrency cap is already spent.
        ta2 = T.TcpTransport(other, self.membership)
        self._transports.append(ta2)
        host, port = tb.bound_address.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((host, int(port)))
        received = sock.recv(4096)
        self.assertEqual(received, b"")
        sock.close()
        session1.close()
        accepted[0].close()


class ConfigOptionalMembershipTestCase(unittest.TestCase):
    """``membership`` may be omitted at construction; ``TeamSync`` rebinds it before use."""

    def test_inprocess_defaults_to_refuse_all(self) -> None:
        transport = T.InProcessTransport(DeviceKey.generate())
        self.assertIsNone(transport.membership("any-env", "any-fp"))

    def test_tcp_defaults_to_refuse_all(self) -> None:
        transport = T.TcpTransport(DeviceKey.generate())
        try:
            self.assertIsNone(transport.membership("any-env", "any-fp"))
        finally:
            transport.close()


if __name__ == "__main__":
    unittest.main()
