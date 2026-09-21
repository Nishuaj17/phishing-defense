"""Response guidance and indicators.

Everything here is ADVICE and DATA. Nothing is automated: the app cannot reset your
password, revoke your sessions or freeze your card, and it must never claim to. Automation
of those steps would need enterprise integrations (identity provider, mail gateway, EDR).
"""
from __future__ import annotations

_AFTER_CLICK = [
    "Change the password for that account straight away, and on any site where you reused it.",
    "Sign out of all sessions and devices from the account's security settings.",
    "Turn on multi-factor authentication. An authenticator app is safer than SMS codes.",
    "If you entered card or UPI details, call your bank or card issuer to block and replace them.",
    "Look through recent account activity and mail-forwarding rules for anything you didn't do.",
    "Expect follow-up scams that quote what you shared, and don't act on them.",
]

_REPORT = [
    "Report it to the company it pretends to be, using the contact details on their real website.",
    "In India, report at cybercrime.gov.in or call 1930, especially if money has moved.",
]


def guidance(label: str, action: str) -> dict:
    if action == "block":
        do_now = [
            "Don't open the link, and don't type passwords, OTPs or card details anywhere it leads.",
            "Delete the message, or report it as phishing in your mail or messaging app.",
            "If you were about to log in to that service, go to its official site by typing the address yourself.",
        ]
    elif label == "unverified":
        do_now = [
            "We couldn't open the page, so treat this as unchecked rather than safe.",
            "Don't enter passwords or payment details on it.",
            "If you expected it, go to the official site by typing the address yourself.",
        ]
    elif action == "warn":
        do_now = [
            "Don't enter passwords or payment details unless you're sure who runs the site.",
            "If you weren't expecting this message, go to the official site by typing the address yourself.",
            "Check the sender through another channel before you act on it.",
        ]
    else:
        do_now = ["No action needed. Still be careful with unexpected requests for passwords or payments."]
    risky = action in ("warn", "block")
    return {"do_now": do_now, "if_you_interacted": _AFTER_CLICK if risky else [], "report": _REPORT if risky else []}


def indicators(url: str | None, domain: str = "", form_action_domain: str = "", sender_domain: str = "") -> list[dict]:
    """Indicators of compromise worth sharing or blocking. Deduplicated, in stable order."""
    out: list[dict] = []
    for kind, value in (("url", url), ("domain", domain), ("form_action_domain", form_action_domain),
                        ("sender_domain", sender_domain)):
        if value and {"type": kind, "value": value} not in out:
            out.append({"type": kind, "value": value})
    return out
