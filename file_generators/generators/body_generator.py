import random
from typing import Union, List, Tuple
from file_generators.data_factories import CleanFactory, MalwareFactory, PhishingFactory, DataLeakFactory, CTPFactory,SpamFactory, UnicodeFactory


class BodyDataGenerator:
    """Generator for creating email body content."""

    @staticmethod
    def generate_body(body_type: str) -> Union[str, List[Tuple[str, str]]]:
        """
        Generate body content based on body type.

        Args:
            body_type: Type of body content to generate

        Returns:
            Generated body content (string or list of tuples for CTP)
        """
        verdict = body_type.split(":")[-1]

        if "ctp" in body_type.lower():
            ctp_factory = CTPFactory()
            return ctp_factory.handle_data(verdict)

        elif "clean" in body_type:
            data = CleanFactory().get_data()

        elif "malware" in body_type and verdict:
            malware_data = MalwareFactory().get_data()
            data = malware_data.get(verdict, [""])

        elif "phishing" in body_type:
            phishing_data = PhishingFactory().get_data()
            data = phishing_data.get(verdict, [""])

        elif "unicode" in body_type:
            unicode_data = UnicodeFactory().get_data()
            data = random.choice(unicode_data[verdict])

        elif "dlp" in body_type:
            if 's3' in verdict:
                verdict = verdict.split(';', 1)[1]
                data_leak = DataLeakFactory.load_s3_data()
            else:
                data_leak = DataLeakFactory().get_data()
            data = data_leak.get("pci" if not verdict else verdict, [""])

        elif "spam" in body_type:
            spam_data = SpamFactory().get_data()
            data = spam_data.get(verdict, "")
            if not isinstance(data, list):
                return data

        else:
            # Handle comma-separated verdicts for DLP
            if "," in verdict:
                data_leak = DataLeakFactory().get_data()
                result_data = []
                for single_verdict in verdict.split(","):
                    verdict_data = data_leak.get(single_verdict, [""])
                    result_data.append(random.choice(verdict_data) if verdict_data else "")
                return "\n".join(result_data)
            else:
                data_leak = DataLeakFactory().get_data()
                data = data_leak.get(verdict, [""])

        return random.choice(data) if isinstance(data, list) else data
