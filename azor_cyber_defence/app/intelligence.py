from urllib.parse import urlparse
import re

TELEGRAM_HOSTS = {"t.me", "telegram.me", "www.t.me", "www.telegram.me"}

def validate_public_telegram_link(value: str) -> bool:
    if not value:
        return True
    candidate = value.strip()
    if candidate.startswith("t.me/"):
        candidate = "https://" + candidate
    try:
        parsed = urlparse(candidate)
        return parsed.scheme in {"http", "https"} and parsed.hostname in TELEGRAM_HOSTS and bool(parsed.path.strip("/"))
    except Exception:
        return False

def triage_hints(category: str, description: str) -> list[str]:
    """Return conservative review reminders; do not infer guilt or classify media."""
    text = f"{category} {description}".lower()
    hints = []
    if any(term in text for term in ("deepfake", "ai-generated", "face swap", "synthetic")):
        hints.append("Possible synthetic intimate imagery: request context and verify without requesting or storing the image.")
    if any(term in text for term in ("minor", "underage", "child", "school student")):
        hints.append("URGENT SAFEGUARDING: do not download, forward, screenshot, or preserve suspected child sexual abuse material. Escalate via appropriate child-protection authorities.")
    if any(term in text for term in ("sell", "selling", "payment", "crypto", "price", "subscription")):
        hints.append("Possible commercial distribution: record only the public listing URL and visible text; do not purchase or engage.")
    if not hints:
        hints.append("Human verification required. A report is an allegation, not a finding.")
    return hints

import hashlib
import re
from urllib.parse import urlparse, urlunparse, unquote

def normalize_telegram_indicator(value: str):
    """Normalize public Telegram links or public @usernames; reject private invite links."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Indicator cannot be empty")
    if raw.startswith("@"):
        username = raw[1:]
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
            raise ValueError("Invalid public Telegram username")
        return "public_username", "@" + username.lower(), "@" + username
    candidate = "https://" + raw if raw.startswith("t.me/") else raw
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in TELEGRAM_HOSTS:
        raise ValueError("Only public t.me links or @usernames are accepted")
    path = unquote(parsed.path).strip("/")
    if not path or path.startswith(("+", "joinchat/")):
        raise ValueError("Private invite links are not accepted")
    # Reject invite/hash-like paths; retain only public handles and message paths.
    parts = path.split("/")
    if parts[0].startswith("+") or parts[0] == "joinchat":
        raise ValueError("Private invite links are not accepted")
    normalized = "https://t.me/" + "/".join(parts)
    return ("telegram_message_link" if len(parts) > 1 else "telegram_public_link",
            normalized.lower(), normalized)

def metadata_sha256(report: dict) -> str:
    """Hash text metadata only. This function must never receive media bytes."""
    payload = "\n".join([
        str(report.get("id", "")), str(report.get("created_at", "")),
        str(report.get("category", "")), str(report.get("target_type", "")),
        str(report.get("public_link", "")), str(report.get("description", ""))
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def priority_assessment(report: dict) -> dict:
    """Transparent triage score; prioritizes review, never asserts guilt."""
    category = (report.get("category") or "").lower()
    description = (report.get("description") or "").lower()
    score, reasons = 10, ["Baseline: human review required"]
    if "minor" in category or "minor" in description or "child" in description or "underage" in description:
        score += 80
        reasons.append("Safeguarding terms detected — urgent specialist escalation; do not copy or retain media")
    if any(k in category + " " + description for k in ["non-consensual", "deepfake", "revenge", "leaked private"]):
        score += 30
        reasons.append("Potential non-consensual intimate-image concern")
    if any(k in description for k in ["sell", "selling", "price", "payment", "subscription", "crypto"]):
        score += 10
        reasons.append("Possible commercial distribution described")
    score = min(score, 100)
    return {"score": score, "priority": "critical" if score >= 80 else "high" if score >= 50 else "normal",
            "reasons": reasons, "disclaimer": "Heuristic review priority only; not a determination that a target violated a law or policy."}
