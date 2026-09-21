"""
Boveda Backend Application Package
"""

# Register audit protection for every process that imports application services,
# including workers and one-off maintenance commands.
import app.services.audit_chain  # noqa: F401
