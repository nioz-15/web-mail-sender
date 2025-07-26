from dataclasses import dataclass, field
from typing import Dict
from file_generators.base.base_data_factory import BaseDataFactory


def spam_data_factory() -> Dict[str, str]:
    """Factory function for spam data."""
    return {
        'avanan_link': 'https://this-is-spam.com/login.php',
        'unified_quarantine_link': "https://www.eicar.com"
    }


@dataclass
class SpamFactory(BaseDataFactory):
    """Factory for generating spam test data."""

    data: Dict[str, str] = field(default_factory=spam_data_factory)

    def get_data(self) -> Dict[str, str]:
        """Return spam data dictionary."""
        return self.data
