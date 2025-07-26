import random
from file_generators.data_factories import DataLeakFactory, PhishingFactory, UnicodeFactory


class SubjectDataGenerator:
    """Generator for creating email subject lines."""

    @staticmethod
    def generate_subject(subject_type: str) -> str:
        """
        Generate subject line based on body type.

        Args:
            subject_type: Type of content to generate subject for

        Returns:
            Generated subject line string
        """
        verdict = subject_type.split(":")[-1].split('_')[1]

        if "dlp" in subject_type:
            data_leak = DataLeakFactory().get_data()
            data = data_leak.get("pci" if not verdict else verdict, [""])

        elif "phishing" in subject_type:
            phishing_data = PhishingFactory().get_data()
            data = phishing_data.get(verdict, [""])

        elif "unicode" in subject_type:
            unicode_data = UnicodeFactory().get_data()
            data = random.choice(unicode_data[verdict])

        else:
            return ""

        return random.choice(data) if isinstance(data, list) else data
