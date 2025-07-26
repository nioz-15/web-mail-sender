import base64
from io import BytesIO
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Union
from file_generators.base.base_data_factory import BaseDataFactory


def ctp_data_factory() -> Dict[str, List[str]]:
    """Factory function for CTP data."""
    return {
        'clean': ['www.google.com/', "www.w3schools.com/"],
        'ignore': ['www.wikipedia.org/', 'autoboom.co.il/'],
        'allow': ['edition.cnn.com/'],
        'added_to_block_list': [],
        'added_to_allow_list': [],
        'added_to_ignore_list': [],
        'block': ['www.foxnews.com/', "api.shopify.com/v2/products/"],
        'malicious': ['www.xvira-malwareavrad.com/', 'www.zvire-malwareavrad.com/'],
        'phishing': ['corporativoentornomedico.com/natwes/natwest3/security_files/security_retry.php'],
        'ip_address': ['http://172.186.52.15', 'http://169.254.0.1', 'http://10.0.0.1']
    }


@dataclass
class CTPFactory(BaseDataFactory):
    """Factory for generating CTP (Click Time Protection) test data."""

    data: Dict[str, List[str]] = field(default_factory=ctp_data_factory)

    def get_data(self) -> Dict[str, List[str]]:
        """Return CTP data dictionary."""
        return self.data

    @staticmethod
    def update_factory_with_s3_data() -> Dict[str, List[str]]:
        """
        Updates the ctp factory data with data fetched from an S3 bucket.

        Returns:
            Updated factory data where keys matching those from the S3 data
            are replaced with the corresponding values from the S3 file.
        """
        try:
            from utils.aws_manager import AwsS3Manager
            s3_data = AwsS3Manager().fetch_s3_file(
                bucket_name='automation-click-time-config',
                file_name='urls_list.json'
            )
            updated_factory = ctp_data_factory()
            for s3_key, s3_values in s3_data.items():
                if s3_key in updated_factory:
                    updated_factory[s3_key] = s3_values
            return updated_factory
        except ImportError:
            return ctp_data_factory()

    def handle_data(self, verdict: str) -> Union[List[Tuple[str, str]], Tuple[str, str]]:
        """
        Process verdict data and retrieve URLs from either local or S3 storage

        Args:
            verdict: String containing verdict types and optional s3 flag

        Returns:
            List of tuples containing (verdict_key, [url]) or tuple for QR code
        """
        data = []
        s3_bucket_data = None

        if verdict.startswith("url_in_qr_code"):
            url_to_insert = verdict.split("<")[-1].split(">")[0].strip()
            return "base64_qr_code", self.generate_qr(url=url_to_insert)

        if verdict.startswith("added_to_"):
            verdict_parts = verdict.split(";")
            verdict_key = verdict_parts[0]
            url = verdict_parts[1].split('=')[1]
            if hasattr(self, 'data') and verdict_key in self.data:
                data.append((verdict_key, url))
                return data

        if 's3' in verdict:
            s3_bucket_data = self.update_factory_with_s3_data()

        for verdict_key in verdict.split(";"):
            if 's3' in verdict_key:
                verdict_key = verdict_key.split('-')[-1]
                urls = s3_bucket_data.get(verdict_key)
            else:
                urls = self.data.get(verdict_key)

            # Handle both single URLs and lists
            if not isinstance(urls, list):
                urls = [urls]

            # Add each URL with its verdict key
            for url in urls:
                data.append((verdict_key, url))

        return data
