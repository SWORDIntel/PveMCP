from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class RedactionRule:
    pattern: re.Pattern[str]
    replacement: str = "[REDACTED]"


class SecretRedactor:
    def __init__(self) -> None:
        self._rules = [
            RedactionRule(re.compile(r"(?i)(?:password|token|secret|auth|apikey|api_key|access_token)\s*[=:]\s*[^\s\n]+")),
            RedactionRule(re.compile(r"(?i)bearer\s+[a-zA-Z0-9._-]+")),
            RedactionRule(re.compile(r"(?i)(?:--password|--token|--secret|--api-token|--auth)\s+\S+")),
            RedactionRule(re.compile(r"(?i)(?:\s-p\s+)\S+")),
        ]

    def redact(self, text: str) -> str:
        value = text
        for rule in self._rules:
            value = rule.pattern.sub(rule.replacement, value)
        return value
