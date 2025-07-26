from dataclasses import dataclass, field
from typing import Dict, List
from file_generators.base.base_data_factory import BaseDataFactory


def phishing_data_factory() -> Dict[str, List[str]]:
    """Factory function for phishing data."""
    return {
        "dummy": ["https://this-is-confident.com/login.php"],
        "real_phish": ["https://lockerselections.com/index.php"],
        "link": [
            "https://corporativoentornomedico.com/natwes/natwest3/security_files/security_retry.php/",
            "https://corporativoentornomedico.com/natwes/natwest3/security_files/details.php?&sessionid=90b6d23d491ec570b9b691d7d4764d76&securessl=true",
            "http://pub-98641a3a3db54774a4342a5d06a1bafb.r2.dev/jjsp.html?kfedisbroke=",
            "http://pub-39dc9c15dc504372b0062e04f1b85995.r2.dev/gpoy.html?faxservice=",
            "http://mnetmasklogio.gitbook.io/", "http://mars.773670658.workers.dev/", "http://car-taupe.vercel.app/"
        ],
        "graymail": ["https://this-is-graymail.com"],
        "hexadecimal": ["687474703a2f2f746869732d69732d636f6e666964656e742e636f6d2f6c6f67696e2e706870"],
        "unified_quarantine_link":"www.babaisyou.com"
    }


@dataclass
class PhishingFactory(BaseDataFactory):
    """Factory for generating phishing test data."""

    data: Dict[str, List[str]] = field(default_factory=phishing_data_factory)

    def get_data(self) -> Dict[str, List[str]]:
        """Return phishing data dictionary."""
        return self.data
