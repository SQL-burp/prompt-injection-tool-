#!/usr/bin/env python3
"""
Prompt Injection Detector
A simple educational and defensive tool for detecting common LLM prompt injection attacks.

Supports:
- Direct injection patterns (ignore instructions, role override, system prompt extraction, etc.)
- Basic indirect indicators (hidden text, suspicious external content markers)

This is heuristic-based. It raises the bar but is not a complete defense.
Always combine with architectural controls: least privilege, human-in-the-loop, etc.
"""

import re
import sys
import argparse
import json
from typing import List, Dict, Tuple

# Common direct injection patterns
DIRECT_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)", "Instruction override"),
    (r"(?i)forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|guidelines)", "Instruction override"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|the\s+above)", "Instruction override"),
    (r"(?i)you\s+are\s+now\s+(in\s+)?(developer|admin|debug|unrestricted|DAN|do\s+anything)", "Role override / Jailbreak"),
    (r"(?i)act\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|DAN)", "Role override / Jailbreak"),
    (r"(?i)system\s*:\s*", "Fake system message"),
    (r"(?i)reveal\s+(your\s+)?(system\s+)?(prompt|instructions|rules)", "System prompt extraction"),
    (r"(?i)print\s+(your\s+)?(full\s+)?(system\s+prompt|instructions)", "System prompt extraction"),
    (r"(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions)", "System prompt extraction"),
    (r"(?i)new\s+instructions?\s*:", "New instructions injection"),
    (r"(?i)override\s+(previous|system)", "Override attempt"),
]

# Suspicious patterns that may indicate indirect injection carriers
INDIRECT_INDICATORS = [
    (r"(?i)(white\s+text|hidden\s+text|display:\s*none|visibility:\s*hidden|color:\s*white)", "Potential hidden content"),
    (r"(?i)<!--.*ignore.*-->", "HTML comment injection"),
    (r"(?i)\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]", "Bracketed override markers"),
    (r"(?i)base64|rot13|hex\s+encoded", "Possible encoding obfuscation"),
]

def scan_text(text: str) -> Dict:
    """Scan text for prompt injection indicators."""
    findings = []
    severity = "none"
    
    # Check direct patterns
    for pattern, label in DIRECT_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            findings.append({
                "type": "direct",
                "label": label,
                "pattern": pattern,
                "matches": len(matches)
            })
            severity = "high"
    
    # Check indirect indicators
    for pattern, label in INDIRECT_INDICATORS:
        matches = re.findall(pattern, text)
        if matches:
            findings.append({
                "type": "indirect_indicator",
                "label": label,
                "pattern": pattern,
                "matches": len(matches)
            })
            if severity == "none":
                severity = "medium"
    
    # Simple length / density heuristics
    if len(text) > 10000:
        findings.append({
            "type": "heuristic",
            "label": "Unusually long input",
            "matches": 1
        })
    
    return {
        "severity": severity,
        "findings_count": len(findings),
        "findings": findings,
        "recommendation": get_recommendation(severity)
    }

def get_recommendation(severity: str) -> str:
    if severity == "high":
        return "BLOCK or require human review. High likelihood of direct prompt injection."
    elif severity == "medium":
        return "REVIEW. Possible indicators of injection or obfuscation. Treat as untrusted data."
    else:
        return "PASS. No common patterns detected. Still treat all external content as untrusted."

def main():
    parser = argparse.ArgumentParser(
        description="Detect common LLM prompt injection patterns (direct & basic indirect indicators)."
    )
    parser.add_argument("--text", type=str, help="Text to scan")
    parser.add_argument("--file", type=str, help="File containing text to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()
    
    if args.text:
        content = args.text
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Read from stdin
        content = sys.stdin.read()
    
    if not content.strip():
        print("No content provided.", file=sys.stderr)
        sys.exit(1)
    
    result = scan_text(content)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Severity: {result['severity'].upper()}")
        print(f"Findings: {result['findings_count']}")
        print(f"Recommendation: {result['recommendation']}")
        if result["findings"]:
            print("\nDetails:")
            for f in result["findings"]:
                print(f"  - [{f['type']}] {f['label']} (matches: {f['matches']})")
    
    # Exit code: 0 = clean, 1 = medium, 2 = high
    if result["severity"] == "high":
        sys.exit(2)
    elif result["severity"] == "medium":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
