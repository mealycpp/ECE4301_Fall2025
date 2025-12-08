#!/usr/bin/env python3
"""
Integration tests for PQC Chat System.

These tests verify the Rust components can be built and basic functionality works.
Run with: python3 tests/test_integration.py
"""

import subprocess
import sys
import os
import time
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRustBuild(unittest.TestCase):
    """Tests that verify the Rust project builds correctly."""
    
    @classmethod
    def setUpClass(cls):
        """Build the project once before running tests."""
        os.chdir(PROJECT_DIR)
        
    def test_cargo_check(self):
        """Test that cargo check passes."""
        result = subprocess.run(
            ["cargo", "check", "--all-features"],
            capture_output=True,
            text=True,
            cwd=PROJECT_DIR
        )
        self.assertEqual(result.returncode, 0, f"cargo check failed: {result.stderr}")
        
    def test_cargo_test(self):
        """Test that Rust unit tests pass."""
        result = subprocess.run(
            ["cargo", "test", "--lib"],
            capture_output=True,
            text=True,
            cwd=PROJECT_DIR
        )
        self.assertEqual(result.returncode, 0, f"cargo test failed: {result.stderr}")


class TestProjectStructure(unittest.TestCase):
    """Tests that verify the project structure is correct."""
    
    def test_cargo_toml_exists(self):
        """Test that Cargo.toml exists."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "Cargo.toml")))
        
    def test_src_directory_exists(self):
        """Test that src directory exists."""
        self.assertTrue(os.path.isdir(os.path.join(PROJECT_DIR, "src")))
        
    def test_server_main_exists(self):
        """Test that server main.rs exists."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "src/server/main.rs")))
        
    def test_client_main_exists(self):
        """Test that client main.rs exists."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "src/client/main.rs")))
        
    def test_gui_main_exists(self):
        """Test that GUI main.rs exists."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "src/gui/main.rs")))
        
    def test_crypto_kyber_exists(self):
        """Test that kyber module exists."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "src/crypto/kyber.rs")))
        
    def test_config_files_exist(self):
        """Test that configuration files exist."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "config/server.toml")))
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "config/client.toml")))
        
    def test_scripts_exist(self):
        """Test that installation scripts exist."""
        scripts = [
            "scripts/install_server.sh",
            "scripts/install_client.sh",
            "scripts/generate_certs.sh",
            "scripts/run_server.sh",
            "scripts/run_client.sh",
        ]
        for script in scripts:
            self.assertTrue(
                os.path.exists(os.path.join(PROJECT_DIR, script)),
                f"Script {script} not found"
            )
            
    def test_systemd_files_exist(self):
        """Test that systemd service files exist."""
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "systemd/pqc-chat-server.service")))
        self.assertTrue(os.path.exists(os.path.join(PROJECT_DIR, "systemd/pqc-chat-client@.service")))


class TestConfigFormat(unittest.TestCase):
    """Tests that verify configuration files are valid."""
    
    def test_server_config_is_valid_toml(self):
        """Test that server config is valid TOML."""
        try:
            import tomllib
            with open(os.path.join(PROJECT_DIR, "config/server.toml"), "rb") as f:
                config = tomllib.load(f)
                self.assertIn("signaling_port", config)
        except ImportError:
            # Python < 3.11, skip test
            self.skipTest("tomllib not available (Python < 3.11)")
            
    def test_client_config_is_valid_toml(self):
        """Test that client config is valid TOML."""
        try:
            import tomllib
            with open(os.path.join(PROJECT_DIR, "config/client.toml"), "rb") as f:
                config = tomllib.load(f)
                self.assertIn("server_host", config)
        except ImportError:
            # Python < 3.11, skip test
            self.skipTest("tomllib not available (Python < 3.11)")


if __name__ == "__main__":
    unittest.main()
