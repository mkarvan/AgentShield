"""AgentShield drop-in Hermes plugin.

A directory plugin under ``~/.hermes/plugins/agentshield/`` only needs to expose
``register(ctx)``. The real implementation lives in the installed ``agentshield``
package, so this is a one-line re-export — keep the package installed in the same
interpreter Hermes runs from.
"""

from agentshield.integrations.hermes import register

__all__ = ["register"]
