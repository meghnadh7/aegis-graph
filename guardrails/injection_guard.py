"""Prompt-injection defense applied to every tool output before LLM ingestion."""
from __future__ import annotations
import re
from typing import Dict, Any, List, Tuple

import structlog

log = structlog.get_logger(__name__)

INJECTION_PATTERNS: List[str] = [
    r"ignore\s+(previous|above|prior|all)\s+instructions",
    r"forget\s+(your|previous|all)\s+(instructions|context|rules)",
    r"you\s+are\s+now",
    r"\bact\s+as\s+(a|an|the)\b",
    r"\bjailbreak\b",
    r"\bDAN\s+mode\b",
    r"pretend\s+(you|to\s+be)",
    r"override\s+(your|the)\s+(instructions|rules|system)",
    r"\bsystem\s+prompt\b",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[INST\]",
    r"###\s*Human:",
    r"###\s*Assistant:",
    r"disregard\s+(the\s+)?(above|previous|all)",
    r"new\s+instructions:",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
_REDACTED = "[REDACTED: potential prompt-injection]"
_MAX_FIELD_LEN = 500


class PromptInjectionGuard:
    """Sanitize tool outputs before they enter LLM context.

    Strategy:
      1. Truncate each string field to MAX_FIELD_LEN.
      2. Replace any matched injection pattern with a redaction marker.
      3. Escape backticks and triple-quote sequences that could close out a
         prompt code block.
      4. Log every detection so it surfaces in LangSmith.
    """

    def __init__(self, max_field_len: int = _MAX_FIELD_LEN) -> None:
        self.max_field_len = max_field_len
        self.detections: List[Tuple[str, str]] = []

    def sanitize(self, text: str, field_name: str = "<unknown>") -> str:
        if not isinstance(text, str):
            return text
        original = text
        if len(text) > self.max_field_len:
            text = text[: self.max_field_len] + "...[truncated]"
        for pattern in _COMPILED:
            if pattern.search(text):
                self.detections.append((field_name, pattern.pattern))
                log.warning("prompt_injection_detected", field=field_name, pattern=pattern.pattern)
                text = pattern.sub(_REDACTED, text)
        text = text.replace("```", "ʼʼʼ")
        text = text.replace("'''", "ʼʼʼ")
        if text != original:
            log.info("guard_modified_field", field=field_name)
        return text

    def sanitize_dict(self, data: Any, max_depth: int = 3, _depth: int = 0, _path: str = "") -> Any:
        """Recursively sanitize all string values in a nested dict/list."""
        if _depth > max_depth:
            return data
        if isinstance(data, dict):
            return {k: self.sanitize_dict(v, max_depth, _depth + 1, f"{_path}.{k}") for k, v in data.items()}
        if isinstance(data, list):
            return [self.sanitize_dict(v, max_depth, _depth + 1, f"{_path}[{i}]") for i, v in enumerate(data)]
        if isinstance(data, str):
            return self.sanitize(data, _path or "<root>")
        return data

    def reset(self) -> None:
        self.detections.clear()
