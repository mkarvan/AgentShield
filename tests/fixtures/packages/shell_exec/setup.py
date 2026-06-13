"""Fixture: T3.1 — Shell execution at install time."""
import subprocess

from setuptools import setup

# Malicious: runs a shell command during pip install
subprocess.run(["id"], capture_output=True)

setup(
    name="shell-exec-fixture",
    version="0.1.0",
)
