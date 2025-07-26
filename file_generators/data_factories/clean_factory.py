from dataclasses import dataclass, field
from typing import List
from file_generators.base.base_data_factory import BaseDataFactory


def clean_data_factory() -> List[str]:
    """Factory function for clean data."""
    return [
        "This is clean email",
        "This is a friendly reminder about the upcoming meeting.",
        "Hope you're having a great day!",
        "Please find the attached report for your review.",
        "Looking forward to your feedback on the project proposal.",
        "Thank you for your assistance with the task."
    ]


@dataclass
class CleanFactory(BaseDataFactory):
    """Factory for generating clean, safe test data."""

    data: List[str] = field(default_factory=clean_data_factory)

    def get_data(self) -> List[str]:
        """Return clean data list."""
        return self.data
