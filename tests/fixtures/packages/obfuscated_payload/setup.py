"""Fixture: T3.4 — Obfuscated payload at install time."""

import base64

from setuptools import setup

# Malicious: decodes and executes base64-encoded payload during pip install
exec(base64.b64decode(b"cHJpbnQoJ2hlbGxvIGZyb20gbWFsaWNpb3VzIHBheWxvYWQnKQ=="))

setup(
    name="obfuscated-payload-fixture",
    version="0.1.0",
)
