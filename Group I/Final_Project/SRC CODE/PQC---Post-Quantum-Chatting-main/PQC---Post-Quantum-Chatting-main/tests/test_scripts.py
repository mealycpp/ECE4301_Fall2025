#!/usr/bin/env python3
"""
Script validation tests.

Tests that verify the shell scripts are valid and have proper permissions.
"""

import subprocess
import os
import stat
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "scripts")


class TestScripts(unittest.TestCase):
    """Tests for shell scripts."""
    
    def test_scripts_are_executable(self):
        """Test that all scripts have executable permission."""
        scripts = [
            "install_server.sh",
            "install_client.sh",
            "generate_certs.sh",
            "run_server.sh",
            "run_client.sh",
        ]
        for script in scripts:
            path = os.path.join(SCRIPTS_DIR, script)
            mode = os.stat(path).st_mode
            self.assertTrue(
                mode & stat.S_IXUSR,
                f"{script} is not executable"
            )
            
    def test_scripts_have_shebang(self):
        """Test that all scripts have proper shebang."""
        scripts = [
            "install_server.sh",
            "install_client.sh", 
            "generate_certs.sh",
            "run_server.sh",
            "run_client.sh",
        ]
        for script in scripts:
            path = os.path.join(SCRIPTS_DIR, script)
            with open(path, "r") as f:
                first_line = f.readline()
            self.assertTrue(
                first_line.startswith("#!/bin/bash"),
                f"{script} missing bash shebang"
            )
            
    def test_generate_certs_syntax(self):
        """Test that generate_certs.sh has valid bash syntax."""
        script = os.path.join(SCRIPTS_DIR, "generate_certs.sh")
        result = subprocess.run(
            ["bash", "-n", script],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0, f"Syntax error in generate_certs.sh: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
