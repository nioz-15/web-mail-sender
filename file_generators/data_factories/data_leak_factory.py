from dataclasses import dataclass, field
from typing import Dict, List
from file_generators.base.base_data_factory import BaseDataFactory



def data_leak_data_factory() -> Dict[str, List[str]]:
    """Factory function for data leak data."""
    return {
        "pii": ['Name: Jane Smith, Account Number: 9876543210, Driver"s License: A1234567'],
        "financial": ['Bank Account Number: 9876543210, Routing Number: 111000025'],
        "pci": [
            'Credit Card Number: 4111 1111 1111 1111, Expiry: 12/24, CVV: 123',
            'Visa Credit Card Number: 4917 6100 0000 0000, Expiry: 03/30, CVV:7373',
            'MC Credit Card Number: 3714 4963 5398 431, Expiry:03/30, CVV: 7373'
        ],
        "phi": [
            'Patient: John Doe, Diagnosis: Hypertension, Medications: Lisinopril'
            'Jane Smith, Health Record: Diabetic, Prescriptions: Metformin',
            'Allergy, Prescription, Lab Results, Diagnosis, SSN, Medical Record Number, Patient Name: John Doe'
        ],
        "sox": [
            "SOX Compliance: Financial records for Q1 2024",
            "Audit Report: SOX Compliance for fiscal year 2023",
            "The internal audit team completed the SOX Compliance review for fiscal year 2023. The audit report highlighted deficiencies in accounting controls and recommended immediate remediation.",
            "Subject: SOX Compliance - Q1 2024. Please find attached the audit report and financial records. These documents are confidential and must align with Sarbanes-Oxley Act internal audit standards.",
            "The quarterly review of internal controls identified a material weakness related to revenue recognition policies. This needs to be addressed before the next SOX filing."
        ],
        "access_control": [
            'Password: 12345678, MD5 Hash: 5f4dcc3b5aa765d61d8327deb882cf99'
            'Password: 12345678, MD5 Hash: 25d55ad283aa400af464c76d713c07ad'
        ],
        "resume": [
            "Confidential: Access Control Information for project ABC"
            "Admin Access: Username: admin123@gmail.com, Password: P@ssw0rd!",
            "Date of Birth: January 15, 1990, \nAddress: 1234 Maple Street, Apt 7B, Brooklyn, NY 11215, \nPhone: (123) 456-7890, \nEmail: john.doe@example.com, \nLinkedIn: linkedin.com/in/testdlpresumecategor"
        ],
        "hipaa": ["USA DEA NUMBER: AM1234563 \nFA2948375\n,MM5129346"],
        "intellectual_property": [
            'Our patented water filtration system uses a novel 3 layer nano fiber membrane, Confidential blueprint of the wearable health monitor design, Design schematics for the AI powered drone are intellectual property of AeroTech Ltd, \n'
            'The source code for our quantum encryption module is proprietary and stored in a secure vault'
        ],
        "encrypted_content": [
            'Secure Key: 3F2504E0-4F89-41D3-9A0C-0305E82C3301',
            'Encrypted Data: U2FsdGVkX1+1qwo/h4wdsdwerw=='
        ],
        "data_type_custom_dict": ['EmailForTestingCustomDictionaryDLPDataType'],
        "data_type_custom_regex": ["ThisIsForDLPRegexDataType"],
        "unified_quarantine": ["ThisIsDLPTestForUnifiedQuarantine"]
    }


@dataclass
class DataLeakFactory(BaseDataFactory):
    """Factory for generating data leak test data."""

    data: Dict[str, List[str]] = field(default_factory=data_leak_data_factory)

    def get_data(self) -> Dict[str, List[str]]:
        """Return data leak data dictionary."""
        return self.data
