from pathlib import Path
import base64
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from app.main import analyzer


TOKEN_FILE = BASE_DIR / "token.json"
STATE_FILE = BASE_DIR / "data" / "gmail_processed.json"
REPORTS_FILE = BASE_DIR / "data" / "gmail_reports.json"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def decode_body(data):
    if not data:
        return ""

    padding = "=" * (-len(data) % 4)
    decoded = base64.urlsafe_b64decode(data + padding)

    return decoded.decode("utf-8", errors="replace")


def get_header(headers, name):
    for header in headers:
        if header["name"].lower() == name.lower():
            return header["value"]

    return ""


def extract_text(payload):
    text_parts = []
    html_parts = []

    def walk(part):
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")

        if data:
            decoded = decode_body(data)

            if mime_type == "text/plain":
                text_parts.append(decoded)

            elif mime_type == "text/html":
                html_parts.append(decoded)

        for child in part.get("parts", []):
            walk(child)

    walk(payload)

    # Prefer the original plain-text version.
    if text_parts:
        return "\n".join(text_parts).strip()

    # Fallback for HTML-only emails.
    if html_parts:
        from html import unescape
        import re

        html = "\n".join(html_parts)

        # Remove scripts and styles.
        html = re.sub(
            r"<(script|style).*?>.*?</\1>",
            " ",
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )

        # Convert common block elements to line breaks.
        html = re.sub(
            r"</(p|div|br|li|tr|h[1-6])>",
            "\n",
            html,
            flags=re.IGNORECASE,
        )

        # Remove remaining HTML tags.
        html = re.sub(r"<[^>]+>", " ", html)

        # Decode HTML entities.
        html = unescape(html)

        # Normalize whitespace.
        html = re.sub(r"[ \t]+", " ", html)
        html = re.sub(r"\n\s*\n+", "\n", html)

        return html.strip()

    return ""

def get_gmail_service():
    if not TOKEN_FILE.exists():
        raise RuntimeError(
            "token.json not found. Run scripts/gmail_test.py first."
        )

    creds = Credentials.from_authorized_user_file(
        str(TOKEN_FILE),
        SCOPES,
    )

    return build("gmail", "v1", credentials=creds)


def get_email(service, message_id):
    return (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full",
        )
        .execute()
    )


def analyze_email(service, message_id):
    email = get_email(service, message_id)

    payload = email.get("payload", {})
    headers = payload.get("headers", [])

    sender = get_header(headers, "From")
    subject = get_header(headers, "Subject")
    date = get_header(headers, "Date")

    text = extract_text(payload)

    if not text:
        raise RuntimeError("No plain-text email body was found.")

    text = text[:5000]

    result = analyzer.analyze_message(
        text=text,
        sender=sender,
        subject=subject,
        mode="cascade",
    )

    return {
        "message_id": message_id,
        "sender": sender,
        "subject": subject,
        "date": date,
        "text": text,
        "result": result,
    }


def print_report(report):
    result = report["result"]

    print("\n" + "=" * 70)
    print("PHISHY GMAIL SECURITY REPORT")
    print("=" * 70)

    print(f"\nFrom:    {report['sender']}")
    print(f"Subject: {report['subject']}")
    print(f"Date:    {report['date']}")

    print("\n" + "-" * 70)
    print("RESULT")
    print("-" * 70)

    print(f"Risk:              {result.risk}/100")
    print(f"Probability:       {result.probability}")
    print(f"Verdict:           {result.label.upper()}")
    print(f"Recommended action:{result.recommended_action.upper()}")
    print(f"Verified:          {result.verified}")
    print(f"Stopped at:        {result.stopped_at}")
    print(f"Latency:           {result.latency_ms} ms")

    print("\n" + "-" * 70)
    print("MODALITIES")
    print("-" * 70)

    for name, modality in result.modalities.items():
        print(f"{name}: {modality}")

    print("\n" + "-" * 70)
    print("DETECTED LINKS")
    print("-" * 70)

    if result.links:
        for index, link in enumerate(result.links, start=1):
            print(
                f"{index}. {link['url']}\n"
                f"   Domain: {link['domain']}\n"
                f"   Risk:   {link['risk']}/100\n"
                f"   Label:  {link['label']}"
            )
    else:
        print("No links detected.")

    print("\n" + "-" * 70)
    print("EVIDENCE")
    print("-" * 70)

    if result.evidence:
        for evidence in result.evidence:
            print(
                f"[{evidence['stage']}] "
                f"{evidence['signal']}: "
                f"{evidence['detail']}"
            )
    else:
        print("No significant evidence recorded.")

    print("\n" + "-" * 70)
    print("GUIDANCE")
    print("-" * 70)

    for item in result.guidance:
        print(f"- {item}")

    print("\n" + "=" * 70)


def get_latest_messages(service, max_results=10):
    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=max_results,
        )
        .execute()
    )

    return response.get("messages", [])

import json


def load_processed_ids():
    if not STATE_FILE.exists():
        return set()

    try:
        data = json.loads(
            STATE_FILE.read_text(encoding="utf-8")
        )

        return set(data)

    except (json.JSONDecodeError, OSError):
        return set()


def save_processed_ids(processed_ids):
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    STATE_FILE.write_text(
        json.dumps(
            sorted(processed_ids),
            indent=2,
        ),
        encoding="utf-8",
    )

def load_reports():
    if not REPORTS_FILE.exists():
        return []

    try:
        return json.loads(
            REPORTS_FILE.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError):
        return []


def save_report(report):
    reports = load_reports()

    def make_json_safe(value):
        if hasattr(value, "model_dump"):
            return make_json_safe(value.model_dump())

        if hasattr(value, "__dict__"):
            return make_json_safe(vars(value))

        if isinstance(value, dict):
            return {
                key: make_json_safe(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple)):
            return [
                make_json_safe(item)
                for item in value
            ]

        if isinstance(value, (str, int, float, bool)) or value is None:
            return value

        return str(value)

    safe_report = make_json_safe(report)

    reports.append(safe_report)

    REPORTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORTS_FILE.write_text(
        json.dumps(
            reports,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

def main():
    service = get_gmail_service()

    messages = get_latest_messages(
        service,
        max_results=10,
    )

    processed_ids = load_processed_ids()

    new_count = 0
    skipped_count = 0

    print("\n" + "=" * 70)
    print("PHISHY GMAIL SECURITY SCAN")
    print("=" * 70)

    print(f"\nFound {len(messages)} message(s).")

    for index, message in enumerate(messages, start=1):
        message_id = message["id"]

        if message_id in processed_ids:
            skipped_count += 1
            continue

        print("\n" + "-" * 70)
        print(f"NEW EMAIL {index}")
        print("-" * 70)

        try:
            report = analyze_email(
                service,
                message_id,
            )

            print_report(report)

            processed_ids.add(message_id)
            new_count += 1

        except Exception as error:
            print(
                f"ERROR analyzing message "
                f"{message_id}: {error}"
            )

    save_processed_ids(processed_ids)

    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)

    print(f"\nNew emails analyzed: {new_count}")
    print(f"Already processed:   {skipped_count}")
    print(f"Total stored IDs:    {len(processed_ids)}")


if __name__ == "__main__":
    main()