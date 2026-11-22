"""Exercise the backup CLI using a synthetic configuration."""

import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


class BackupCLI(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        script = Path(__file__).resolve().with_name("miwifi_backup.py")
        router = ["--sn", "TEST1synthetic", "--lan-mac", "02:00:00:00:00:01"]
        backup = {
            "description": ["mi_wifi_info"],
            "config": {"mi_wifi_info": {"ssid": "测试网络", "enabled": True}},
        }
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            archive = Path(directory) / "backup.tar.gz"
            restored = Path(directory) / "restored.json"
            source.write_text(json.dumps(backup, ensure_ascii=False), encoding="utf-8")

            subprocess.run([sys.executable, script, "encrypt", source, archive, *router], check=True)
            with tarfile.open(archive, "r:gz") as contents:
                self.assertCountEqual(contents.getnames(), ["cfg_backup.des", "cfg_backup.mbu"])

            subprocess.run([sys.executable, script, "decrypt", archive, restored, *router], check=True)
            self.assertEqual(json.loads(restored.read_text(encoding="utf-8")), backup)


if __name__ == "__main__":
    unittest.main()
