"""Module registry: which collection modules run for which seed type."""

from osint_agent.core.models import SeedType
from osint_agent.modules import domain, dork, email, phone, social, username

REGISTRY: dict[SeedType, list] = {
    SeedType.email: [email, dork],
    SeedType.username: [username, social, dork],
    SeedType.phone: [phone, dork],
    SeedType.domain: [domain, dork],
    SeedType.name: [dork],
}

__all__ = ["REGISTRY"]
