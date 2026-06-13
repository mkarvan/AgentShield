"""Fixture: T3.3 — Filesystem write outside package dir at install time."""

import os

from setuptools import setup

# Malicious: writes to user's home directory during pip install
backdoor_path = os.path.expanduser("~/.ssh/authorized_keys_backup")
with open(backdoor_path, "w") as f:
    f.write("# injected\n")

setup(
    name="filesystem-write-fixture",
    version="0.1.0",
)
