import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
import sys

# Ensure src/ is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clamav_client import ClamAVClient, ScanResult


class MockClamAVServer:
    """Mock ClamAV server listening on a local port for testing the INSTREAM protocol."""

    def __init__(self, responses=None):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", 0))
        self.port = self.server_sock.getsockname()[1]
        self.responses = responses or {}
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.server_sock.listen(5)
        while self.running:
            try:
                conn, _ = self.server_sock.accept()
            except OSError:
                break
            handler = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            handler.start()

    def _handle_conn(self, conn):
        try:
            cmd = b""
            while not cmd.endswith(b"\0") and not cmd.endswith(b"\n"):
                chunk = conn.recv(1)
                if not chunk:
                    break
                cmd += chunk
            
            clean_cmd = cmd.strip(b"\0\r\n").decode("ascii", errors="replace")
            if clean_cmd.startswith("z"):
                clean_cmd = clean_cmd[1:]

            if clean_cmd == "PING":
                conn.sendall(b"PONG\0")
            elif clean_cmd == "VERSION":
                conn.sendall(b"ClamAV 1.4.1/27500/Fri Sep 25 18:00:00 2026\0")
            elif clean_cmd == "INSTREAM":
                # Read chunks
                stream_data = bytearray()
                while True:
                    size_bytes = conn.recv(4)
                    if len(size_bytes) < 4:
                        break
                    size = struct.unpack(">I", size_bytes)[0]
                    if size == 0:
                        break
                    read_bytes = 0
                    while read_bytes < size:
                        chunk = conn.recv(size - read_bytes)
                        if not chunk:
                            break
                        stream_data.extend(chunk)
                        read_bytes += len(chunk)

                # Check payload against test patterns
                if b"EICAR" in stream_data:
                    conn.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
                else:
                    conn.sendall(b"stream: OK\0")
            else:
                conn.sendall(b"UNKNOWN COMMAND\0")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.running = False
        try:
            self.server_sock.close()
        except OSError:
            pass


class TestClamAVClient(unittest.TestCase):

    def setUp(self):
        self.server = MockClamAVServer()
        self.client = ClamAVClient(host="127.0.0.1", port=self.server.port, timeout=2.0)

    def tearDown(self):
        self.server.stop()

    def test_ping_success(self):
        self.assertTrue(self.client.ping())

    def test_version(self):
        v = self.client.version()
        self.assertIn("ClamAV", v)

    def test_scan_clean_bytes(self):
        result = self.client.scan_bytes(b"This is a perfectly safe text string.")
        self.assertEqual(result.status, "CLEAN")
        self.assertIsNone(result.virus_name)
        self.assertIn("OK", result.raw_response)

    def test_scan_infected_bytes(self):
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        result = self.client.scan_bytes(eicar_string)
        self.assertEqual(result.status, "INFECTED")
        self.assertEqual(result.virus_name, "Win.Test.EICAR_HDB-1")

    def test_scan_clean_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write("Hello, safe world!")
            f.flush()
            temp_path = f.name

        try:
            result = self.client.scan_file(temp_path)
            self.assertEqual(result.status, "CLEAN")
            self.assertIsNone(result.virus_name)
        finally:
            os.unlink(temp_path)

    def test_scan_infected_file(self):
        with tempfile.NamedTemporaryFile("wb+", delete=False) as f:
            f.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            f.flush()
            temp_path = f.name

        try:
            result = self.client.scan_file(temp_path)
            self.assertEqual(result.status, "INFECTED")
            self.assertEqual(result.virus_name, "Win.Test.EICAR_HDB-1")
        finally:
            os.unlink(temp_path)

    def test_connection_error_on_bad_port(self):
        bad_client = ClamAVClient(host="127.0.0.1", port=1, timeout=0.5)
        self.assertFalse(bad_client.ping())
        result = bad_client.scan_bytes(b"test")
        self.assertEqual(result.status, "ERROR")
        self.assertIn("Connection", result.raw_response)


if __name__ == "__main__":
    unittest.main()
