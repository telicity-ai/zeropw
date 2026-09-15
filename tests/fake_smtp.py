"""Minimal test-only SMTP receiver (Python 3.12 dropped the ``smtpd`` module).

Speaks just enough SMTP, in the clear on 127.0.0.1, for ``smtplib.SMTP`` in ``plain`` mode to
complete a full send: a 220 banner, EHLO/HELO (advertising ``AUTH PLAIN LOGIN``, no STARTTLS),
``AUTH PLAIN`` and ``AUTH LOGIN`` (both record the decoded username/password a test can assert
against), MAIL FROM, RCPT TO, DATA up to the ``\\r\\n.\\r\\n`` terminator, QUIT, RSET and NOOP.
Collected messages are ``{"sender", "recipients", "data"}`` dicts.

Like ``zeropw/fake_upstream.py``, this is a test fixture only: no TLS, no real authentication,
127.0.0.1 ephemeral port only, and it must never see a real credential.
"""

from __future__ import annotations

import base64
import binascii
import socket
import threading
from typing import Any


def _b64decode(text: str) -> str:
    try:
        return base64.b64decode(text).decode("utf-8", "replace")
    except (ValueError, TypeError, binascii.Error):
        return ""


class FakeSmtp:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.auth_attempts: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        self._server: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._port = 0  # remembered across stop()/start() so a test can restart on the same address

    # ------------------------------------------------------------ lifecycle
    def start(self) -> "FakeSmtp":
        if self._server is not None:
            return self
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self._port))
        sock.listen(16)
        sock.settimeout(0.2)
        self._port = int(sock.getsockname()[1])
        self._server = sock
        self._stop.clear()
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread = thread
        thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        server, thread = self._server, self._accept_thread
        self._server, self._accept_thread = None, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        if thread is not None:
            thread.join(timeout=5)

    def __enter__(self) -> "FakeSmtp":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        if self._port == 0:
            raise RuntimeError("fake smtp never started")
        return self._port

    def reset(self) -> None:
        with self._lock:
            self.messages.clear()
            self.auth_attempts.clear()

    # ------------------------------------------------------------- serving
    def _accept_loop(self) -> None:
        server = self._server
        while server is not None and not self._stop.is_set():
            try:
                client, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._serve, args=(client,), daemon=True)
            thread.start()

    @staticmethod
    def _send(client: socket.socket, text: str) -> None:
        client.sendall(text.encode("ascii"))

    def _record_auth(self, username: str, password: str) -> None:
        with self._lock:
            self.auth_attempts.append((username, password))

    def _decode_plain(self, blob: str) -> None:
        try:
            raw = base64.b64decode(blob)
            _authzid, username, password = raw.split(b"\x00")
        except (ValueError, TypeError):
            return
        self._record_auth(username.decode("utf-8", "replace"), password.decode("utf-8", "replace"))

    def _serve(self, client: socket.socket) -> None:
        client.settimeout(10)
        rfile = client.makefile("rb")
        try:
            self._send(client, "220 fake-smtp ready\r\n")
            mail_from: str | None = None
            rcpt_to: list[str] = []
            while True:
                line = rfile.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                upper = text.upper()
                if upper.startswith("EHLO") or upper.startswith("HELO"):
                    self._send(client, "250-fake-smtp\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
                elif upper.startswith("AUTH PLAIN"):
                    parts = text.split(" ", 2)
                    if len(parts) == 3:
                        self._decode_plain(parts[2])
                        self._send(client, "235 authenticated\r\n")
                    else:
                        self._send(client, "334 \r\n")
                        blob = rfile.readline().decode("utf-8", "replace").rstrip("\r\n")
                        self._decode_plain(blob)
                        self._send(client, "235 authenticated\r\n")
                elif upper.startswith("AUTH LOGIN"):
                    # smtplib sends the username as the AUTH LOGIN initial response (base64,
                    # inline); fall back to prompting for it if a client omits that.
                    parts = text.split(" ", 2)
                    if len(parts) >= 3:
                        username = _b64decode(parts[2])
                    else:
                        self._send(client, "334 VXNlcm5hbWU6\r\n")  # "Username:"
                        line2 = rfile.readline().decode("utf-8", "replace").rstrip("\r\n")
                        username = _b64decode(line2)
                    self._send(client, "334 UGFzc3dvcmQ6\r\n")  # "Password:"
                    line3 = rfile.readline().decode("utf-8", "replace").rstrip("\r\n")
                    password = _b64decode(line3)
                    self._record_auth(username, password)
                    self._send(client, "235 authenticated\r\n")
                elif upper.startswith("MAIL FROM"):
                    mail_from = text.split(":", 1)[1].strip()
                    self._send(client, "250 OK\r\n")
                elif upper.startswith("RCPT TO"):
                    rcpt_to.append(text.split(":", 1)[1].strip())
                    self._send(client, "250 OK\r\n")
                elif upper.startswith("DATA"):
                    self._send(client, "354 end with <CRLF>.<CRLF>\r\n")
                    raw = bytearray()
                    while True:
                        data_line = rfile.readline()
                        if not data_line or data_line in (b".\r\n", b".\n"):
                            break
                        if data_line.startswith(b".."):  # dot-stuffing (RFC 5321 §4.5.2)
                            data_line = data_line[1:]
                        raw.extend(data_line)
                    with self._lock:
                        self.messages.append({"sender": mail_from, "recipients": list(rcpt_to), "data": bytes(raw)})
                    mail_from, rcpt_to = None, []
                    self._send(client, "250 OK\r\n")
                elif upper.startswith("RSET"):
                    mail_from, rcpt_to = None, []
                    self._send(client, "250 OK\r\n")
                elif upper.startswith("NOOP"):
                    self._send(client, "250 OK\r\n")
                elif upper.startswith("QUIT"):
                    self._send(client, "221 bye\r\n")
                    break
                else:
                    self._send(client, "500 unrecognized command\r\n")
        except OSError:
            pass
        finally:
            try:
                rfile.close()
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
