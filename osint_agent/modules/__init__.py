"""Module registry: which collection modules run for which seed type."""

from osint_agent.core.models import SeedType
from osint_agent.modules import email, phone, username

REGISTRY: dict[SeedType, list] = {
    SeedType.email: [email],
    SeedType.username: [username],
    SeedType.phone: [phone],
}

__all__ = ["REGISTRY"]
