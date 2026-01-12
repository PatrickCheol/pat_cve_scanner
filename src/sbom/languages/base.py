from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class Dependency:
    name: str
    version: Optional[str]
    type: str  # e.g., "maven", "pypi", "composer"
    # Additional metadata if needed
    source: str = "manifest" # "manifest" (build file) or "code" (import analysis)

class BaseLanguageScanner(ABC):
    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    @abstractmethod
    def scan(self) -> List[Dependency]:
        """
        Scans the target directory and returns a list of found dependencies.
        """
        pass
