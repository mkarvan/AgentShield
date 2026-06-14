"""Container / Docker scanning — extract and scan packages from Dockerfiles.

Parses ``RUN pip install``, ``RUN npm install``, and ``RUN cargo install``/
``RUN cargo add`` commands from a Dockerfile and returns ScanRequests for
all detected packages.

Both shell form (``RUN pip install foo``) and exec form
(``RUN ["pip", "install", "foo"]``) are supported.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentshield.core.models import Ecosystem, ScanRequest
from agentshield.integrations.hermes.plugin import _INSTALL_PATTERNS, _tokenize_packages

# Match a RUN instruction, capturing everything after "RUN "
_RUN_RE = re.compile(
    r"^\s*RUN\s+(.*)",
    re.MULTILINE | re.IGNORECASE,
)

# Collapse backslash-newline continuations before parsing
_CONTINUATION_RE = re.compile(r"\\\n\s*")


def parse_dockerfile(path: Path) -> list[ScanRequest]:
    """Extract package install commands from *path* and return ScanRequests.

    Packages are deduplicated by (name, ecosystem); exec-form JSON arrays are
    decoded into a shell-command string before pattern matching.
    """
    content = _CONTINUATION_RE.sub(" ", path.read_text())

    seen: set[tuple[str, Ecosystem]] = set()
    requests: list[ScanRequest] = []

    for run_match in _RUN_RE.finditer(content):
        command = run_match.group(1).strip()
        if command.startswith("["):
            command = _exec_form_to_shell(command)

        for pattern, ecosystem in _INSTALL_PATTERNS:
            for m in pattern.finditer(command):
                for pkg_name in _tokenize_packages(m.group(1)):
                    key = (pkg_name.lower(), ecosystem)
                    if key in seen:
                        continue
                    seen.add(key)
                    requests.append(
                        ScanRequest(
                            package=pkg_name,
                            version=None,
                            ecosystem=ecosystem,
                            source="dockerfile",
                        )
                    )

    return requests


def _exec_form_to_shell(json_array: str) -> str:
    """Convert a Dockerfile exec-form JSON array to a space-joined shell string."""
    try:
        tokens = json.loads(json_array)
        if isinstance(tokens, list):
            return " ".join(str(t) for t in tokens)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return json_array
