"""Pure-Python ClamAV TCP Client implementing INSTREAM protocol.

Zero external dependencies - communicates directly with clamd on port 3310.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import struct
import time
from typing import Optional, Union


@dataclass
class ScanResult:
    """Represents the outcome of a ClamAV file or stream scan."""

    status: str  # "CLEAN", "INFECTED", "ERROR"
    virus_name: Optional[str] = None
    raw_response: str = ""
    latency_ms: float = 0.0

    @property
    def is_clean(self) -> bool:
        return self.status == "CLEAN"

    @property
    def is_infected(self) -> bool:
        return self.status == "INFECTED"


class ClamAVClient:
    """TCP socket client for ClamAV daemon (clamd)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 3310, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            return sock
        except Exception:
            sock.close()
            raise

    def ping(self) -> bool:
        """Send PING command to clamd; expect PONG."""
        try:
            with self._connect() as sock:
                sock.sendall(b"zPING\0")
                response = self._read_response(sock)
                return "PONG" in response
        except (socket.error, OSError):
            return False

    def version(self) -> str:
        """Retrieve ClamAV engine and signature version string."""
        try:
            with self._connect() as sock:
                sock.sendall(b"zVERSION\0")
                return self._read_response(sock)
        except (socket.error, OSError) as e:
            return f"ERROR: {e}"

    def scan_bytes(self, data: bytes, chunk_size: int = 65536) -> ScanResult:
        """Scan raw byte content via the INSTREAM protocol."""
        start_time = time.perf_counter()
        try:
            with self._connect() as sock:
                sock.sendall(b"zINSTREAM\0")

                offset = 0
                total_len = len(data)
                while offset < total_len:
                    chunk = data[offset : offset + chunk_size]
                    sock.sendall(struct.pack(">I", len(chunk)) + chunk)
                    offset += len(chunk)

                # Send 0-length chunk to terminate stream
                sock.sendall(struct.pack(">I", 0))

                raw_resp = self._read_response(sock)
                latency = (time.perf_counter() - start_time) * 1000.0
                return self._parse_scan_response(raw_resp, latency)
        except (socket.error, OSError) as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                status="ERROR",
                virus_name=None,
                raw_response=f"Connection/Socket Error: {e}",
                latency_ms=latency,
            )

    def scan_file(self, file_path: Union[str, Path], chunk_size: int = 65536) -> ScanResult:
        """Stream a file from disk to clamd via INSTREAM protocol."""
        path = Path(file_path)
        if not path.is_file():
            return ScanResult(
                status="ERROR",
                virus_name=None,
                raw_response=f"File not found or not regular file: {path}",
                latency_ms=0.0,
            )

        start_time = time.perf_counter()
        try:
            with self._connect() as sock:
                sock.sendall(b"zINSTREAM\0")

                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        sock.sendall(struct.pack(">I", len(chunk)) + chunk)

                # Send 0-length chunk to terminate stream
                sock.sendall(struct.pack(">I", 0))

                raw_resp = self._read_response(sock)
                latency = (time.perf_counter() - start_time) * 1000.0
                return self._parse_scan_response(raw_resp, latency)
        except (socket.error, OSError) as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                status="ERROR",
                virus_name=None,
                raw_response=f"Scan error: {e}",
                latency_ms=latency,
            )

    def _read_response(self, sock: socket.socket) -> str:
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if data.endswith(b"\0") or data.endswith(b"\n"):
                    break
            except socket.timeout:
                break
        return b"".join(chunks).decode("utf-8", errors="replace").strip("\0\r\n ")

    def _parse_scan_response(self, raw_resp: str, latency: float) -> ScanResult:
        # Expected formats:
        # "stream: OK"
        # "stream: <VirusName> FOUND"
        # "stream: <Reason> ERROR"
        if "FOUND" in raw_resp:
            # Extract virus name: stream: <virus> FOUND
            parts = raw_resp.split(":")
            if len(parts) >= 2:
                detail = parts[1].replace("FOUND", "").strip()
                return ScanResult(
                    status="INFECTED",
                    virus_name=detail,
                    raw_response=raw_resp,
                    latency_ms=latency,
                )
            return ScanResult(
                status="INFECTED",
                virus_name="Unknown",
                raw_response=raw_resp,
                latency_ms=latency,
            )
        elif "OK" in raw_resp:
            return ScanResult(
                status="CLEAN",
                virus_name=None,
                raw_response=raw_resp,
                latency_ms=latency,
            )
        else:
            return ScanResult(
                status="ERROR",
                virus_name=None,
                raw_response=raw_resp,
                latency_ms=latency,
            )
