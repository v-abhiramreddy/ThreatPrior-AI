from enum import Enum


class SourceStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    NOT_LISTED = "NOT_LISTED"
    LISTED = "LISTED"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class OverallStatus(str, Enum):
    OK = "OK"
    PARTIAL = "PARTIAL"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"
