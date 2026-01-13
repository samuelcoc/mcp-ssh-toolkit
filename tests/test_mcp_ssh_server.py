import json
import tempfile
import unittest
from pathlib import Path

import mcp_ssh_server


class TestConfigParsing(unittest.TestCase):
    def _write_config(self, obj):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        path = Path(tmp.name)
        path.write_text(json.dumps(obj), encoding="utf-8")
        return str(path)

    def test_load_config_merges_defaults(self):
        cfg_path = self._write_config(
            {
                "version": 1,
                "defaults": {"user": "ubuntu", "port": 2222, "strictHostKeyChecking": "accept-new"},
                "servers": {"a": {"host": "1.2.3.4"}},
                "groups": {"g": ["a"]},
                "defaultServer": "a",
            }
        )
        cfg = mcp_ssh_server.load_config(cfg_path)
        self.assertEqual(cfg.default_server, "a")
        self.assertIn("a", cfg.servers)
        self.assertEqual(cfg.servers["a"].user, "ubuntu")
        self.assertEqual(cfg.servers["a"].port, 2222)
        self.assertEqual(cfg.servers["a"].strict_host_key_checking, "accept-new")

    def test_invalid_group_reference_fails(self):
        cfg_path = self._write_config(
            {
                "version": 1,
                "servers": {"a": {"host": "1.2.3.4"}},
                "groups": {"g": ["missing"]},
            }
        )
        with self.assertRaises(mcp_ssh_server.MCPError):
            mcp_ssh_server.load_config(cfg_path)

    def test_policy_allowlist_blocks(self):
        cfg_path = self._write_config(
            {
                "version": 1,
                "policy": {"allow": ["^uptime$"]},
                "servers": {"a": {"host": "1.2.3.4"}},
            }
        )
        cfg = mcp_ssh_server.load_config(cfg_path)
        server = cfg.servers["a"]
        with self.assertRaises(mcp_ssh_server.MCPError):
            server.policy.validate("whoami")

    def test_password_command_list_parses(self):
        cfg_path = self._write_config(
            {
                "version": 1,
                "servers": {
                    "a": {"host": "1.2.3.4", "passwordCommand": ["cmd", "/c", "echo", "x"]}
                },
            }
        )
        cfg = mcp_ssh_server.load_config(cfg_path)
        self.assertEqual(cfg.servers["a"].password_command, ("cmd", "/c", "echo", "x"))


if __name__ == "__main__":
    unittest.main()
