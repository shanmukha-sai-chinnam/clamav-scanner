import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from clamav_client import ClamAVClient
from sentinel import Sentinel
from test_clamav_client import MockClamAVServer


class TestSentinel(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.watch_dir = Path(self.temp_dir.name) / "watch"
        self.quarantine_dir = Path(self.temp_dir.name) / "quarantine"
        self.audit_log = Path(self.temp_dir.name) / "audit.jsonl"
        self.watch_dir.mkdir(parents=True, exist_ok=True)

        self.mock_server = MockClamAVServer()
        self.client = ClamAVClient(host="127.0.0.1", port=self.mock_server.port, timeout=2.0)

        self.sentinel = Sentinel(
            watch_dir=self.watch_dir,
            client=self.client,
            quarantine_dir=self.quarantine_dir,
            audit_log=self.audit_log,
            recursive=True,
            auto_quarantine=True,
        )

    def tearDown(self):
        self.sentinel.watcher.close()
        self.mock_server.stop()
        self.temp_dir.cleanup()

    def test_should_ignore(self):
        self.assertTrue(self.sentinel.should_ignore(self.watch_dir / ".git" / "HEAD"))
        self.assertTrue(self.sentinel.should_ignore(self.watch_dir / ".direnv" / "bin"))
        self.assertTrue(self.sentinel.should_ignore(self.watch_dir / "foo" / ".quarantine" / "file"))
        self.assertTrue(self.sentinel.should_ignore(self.watch_dir / "file.tmp"))
        self.assertTrue(self.sentinel.should_ignore(self.watch_dir / "file.swp"))
        self.assertTrue(self.sentinel.should_ignore(self.watch_dir / ".hidden_file"))
        self.assertFalse(self.sentinel.should_ignore(self.watch_dir / "clean_code.py"))
        self.assertFalse(self.sentinel.should_ignore(self.watch_dir / "sub" / "data.csv"))

    def test_compute_sha256(self):
        test_file = self.watch_dir / "test.txt"
        test_file.write_text("Hello, world!")
        expected_hash = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        self.assertEqual(self.sentinel.compute_sha256(test_file), expected_hash)

    def test_handle_file_clean(self):
        clean_file = self.watch_dir / "document.pdf"
        clean_file.write_text("Benign document content.")

        self.sentinel.handle_file(clean_file)

        # File should still exist at original path
        self.assertTrue(clean_file.exists())

        # Audit log should record clean status
        self.assertTrue(self.audit_log.exists())
        with open(self.audit_log, "r") as f:
            entry = json.loads(f.readline())
            self.assertEqual(entry["status"], "CLEAN")
            self.assertEqual(entry["file"], str(clean_file))
            self.assertIsNone(entry["virus_name"])

    def test_handle_file_infected_quarantine(self):
        infected_file = self.watch_dir / "payload.bin"
        infected_file.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

        self.sentinel.handle_file(infected_file)

        # Original file must no longer exist in watch directory
        self.assertFalse(infected_file.exists())

        # Quarantined file must exist in quarantine directory
        quarantined_files = list(self.quarantine_dir.glob("*_payload.bin"))
        self.assertEqual(len(quarantined_files), 1)
        q_file = quarantined_files[0]

        # Permissions must be 000 (no read/write/execute)
        file_mode = stat.S_IMODE(q_file.stat().st_mode)
        self.assertEqual(file_mode, 0)

        # Restore permissions so cleanup doesn't fail
        os.chmod(q_file, 0o600)

        # Audit log must record INFECTED and quarantine path
        with open(self.audit_log, "r") as f:
            lines = [json.loads(line) for line in f]
            self.assertEqual(lines[-1]["status"], "INFECTED")
            self.assertEqual(lines[-1]["virus_name"], "Win.Test.EICAR_HDB-1")
            self.assertEqual(lines[-1]["quarantined_to"], str(q_file))


if __name__ == "__main__":
    unittest.main()
