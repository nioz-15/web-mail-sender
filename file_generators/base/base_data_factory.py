from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class BaseDataFactory(ABC):
    """Base class for data factories."""

    def __repr__(self):
        return f"<{self.__class__.__name__} {asdict(self)}>"

    @abstractmethod
    def get_data(self) -> Dict[str, Any]:
        """Return the factory data."""
        pass
