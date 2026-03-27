from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class RiskRecord:
    rule_id: str
    category: str
    title: str
    severity: Severity
    file_path: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
