"""Target type auto-detection module.

Detects target type from user input using URL patterns, file extensions,
and content inspection. Returns detected type and recommended control sets.
"""

import re
import os


TARGET_TYPES = {
    "website": {
        "label": "Website detected",
        "icon": "world",
        "control_sets": ["website_agent"],
        "description": "URL detected. Website & agent controls recommended.",
    },
    "api": {
        "label": "API spec detected",
        "icon": "api",
        "control_sets": ["api"],
        "description": "OpenAPI/Swagger spec detected.",
    },
    "code": {
        "label": "Source code detected",
        "icon": "code",
        "control_sets": ["code_review"],
        "description": "Source code files detected.",
    },
    "agent": {
        "label": "AI agent detected",
        "icon": "robot",
        "control_sets": ["website_agent"],
        "description": "Agent configuration recognized.",
    },
    "stig": {
        "label": "STIG XML detected",
        "icon": "shield-check",
        "control_sets": [],
        "description": "DISA STIG will be parsed and imported.",
    },
    "os": {
        "label": "OS/Software scan",
        "icon": "monitor",
        "control_sets": ["os_software"],
        "description": "Local machine OS and software vulnerability scan.",
    },
    "unknown": {
        "label": "Enter a target",
        "icon": "help-circle",
        "control_sets": [],
        "description": "Paste a URL, file path, API spec, or STIG XML.",
    },
}

WEBSITE_PATTERN = re.compile(r'^https?://', re.IGNORECASE)
API_SPEC_EXTENSIONS = {'.yaml', '.yml', '.json'}
CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.rs',
    '.java', '.go', '.php', '.cs', '.cpp', '.c', '.h', '.hpp',
}
AGENT_PATTERNS = re.compile(
    r'SKILL\.md|\.gpt|copilot|langchain|crewai|autogen|mcp|bedrock|vertex',
    re.IGNORECASE
)
STIG_PATTERNS = re.compile(r'xccdf|stig.*\.xml', re.IGNORECASE)
OS_SCAN_KEYWORDS = {'localhost', '127.0.0.1', '::1', 'this machine', 'local machine', 'this host'}


def detect_target(user_input: str) -> dict:
    """Detect target type from user input string.

    Returns dict with keys: type, label, icon, control_sets, description
    """
    text = user_input.strip()
    if not text:
        return _result("unknown")

    if text.lower() in OS_SCAN_KEYWORDS:
        return _result("os")

    if WEBSITE_PATTERN.match(text):
        return _result("website")

    if STIG_PATTERNS.search(text):
        return _result("stig")

    if AGENT_PATTERNS.search(text):
        return _result("agent")

    if os.path.exists(text):
        ext = os.path.splitext(text)[1].lower()
        if ext in CODE_EXTENSIONS:
            return _result("code")
        if ext in API_SPEC_EXTENSIONS:
            return _result("api")
        if ext == '.xml':
            try:
                with open(text, 'r', encoding='utf-8', errors='ignore') as f:
                    head = f.read(2000)
                if 'xccdf' in head.lower() or 'Benchmark' in head:
                    return _result("stig")
            except (IOError, OSError):
                pass
        if ext == '.md':
            basename = os.path.basename(text).upper()
            if 'SKILL' in basename:
                return _result("agent")

    ext = os.path.splitext(text)[1].lower() if '.' in text else ''
    if ext in CODE_EXTENSIONS:
        return _result("code")
    if ext in API_SPEC_EXTENSIONS:
        return _result("api")

    if any(kw in text.lower() for kw in ['swagger', 'openapi', 'api-spec', 'postman']):
        return _result("api")

    return _result("unknown")




def extract_hostname(target: str) -> str:
    """Extract hostname from a URL for display and system keying."""
    match = re.match(r'https?://([^/:]+)', target)
    return match.group(1) if match else target


def _result(target_type: str) -> dict:
    info = TARGET_TYPES[target_type]
    return {
        "type": target_type,
        "label": info["label"],
        "icon": info["icon"],
        "control_sets": info["control_sets"],
        "description": info["description"],
    }
