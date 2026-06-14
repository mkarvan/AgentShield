"""T4.1 heuristic: detect prompt-injected package install requests.

Fires when ``context_hint`` contains the package name in patterns consistent
with retrieved external content (quoted strings, code blocks, markdown links)
rather than agent-generated reasoning.

Severity: MEDIUM, default response: warn_confirm.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from agentshield.core.models import Finding, ScanRequest, Severity

# Each factory takes an escaped package name and returns a compiled pattern.
_PATTERN_FACTORIES: list[Callable[[str], re.Pattern[str]]] = [
    # Quoted strings: "requests" or 'requests'
    lambda pkg: re.compile(rf"""['"]{pkg}['"]""", re.IGNORECASE),
    # Backtick inline code: `requests` or `pip install requests`
    lambda pkg: re.compile(rf"`[^`\n]*{pkg}[^`\n]*`", re.IGNORECASE),
    # Fenced code block line: ```pip install requests
    lambda pkg: re.compile(rf"```[^\n]*{pkg}", re.IGNORECASE | re.MULTILINE),
    # Markdown link: [requests](https://...)
    lambda pkg: re.compile(rf"\[{pkg}\]\s*\(", re.IGNORECASE),
    # Install commands appearing in text (copy-pasted from docs / web pages)
    lambda pkg: re.compile(rf"pip\s+install\s+[^\n]*{pkg}", re.IGNORECASE),
    lambda pkg: re.compile(rf"npm\s+i(?:nstall)?\s+[^\n]*{pkg}", re.IGNORECASE),
    lambda pkg: re.compile(rf"cargo\s+add\s+[^\n]*{pkg}", re.IGNORECASE),
]


async def check_prompt_injection(request: ScanRequest) -> list[Finding]:
    """Return a T4.1 Finding if context_hint suggests a prompt-injected install.

    Returns an empty list when context_hint is absent or no pattern matches.
    The first matching pattern short-circuits — at most one finding is returned.
    """
    if not request.context_hint or not request.package:
        return []

    pkg = re.escape(request.package)
    hint = request.context_hint

    for factory in _PATTERN_FACTORIES:
        pattern = factory(pkg)
        if pattern.search(hint):
            return [
                Finding(
                    rule_id="T4.1",
                    title="Possible prompt-injected install request",
                    description=(
                        f"The package name '{request.package}' appears in the context hint "
                        "in a pattern consistent with retrieved external content "
                        "(quoted string, code block, or markdown link). "
                        "This may indicate the install was triggered by a prompt injection "
                        "rather than the agent's own reasoning."
                    ),
                    severity=Severity.MEDIUM,
                    source="prompt_injection",
                    references=[
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    ],
                    remediation=(
                        "Verify that this install was explicitly requested by the user "
                        "and not triggered by injected content from an external source."
                    ),
                    metadata={"heuristic": "context_hint_pattern_match"},
                )
            ]

    return []
