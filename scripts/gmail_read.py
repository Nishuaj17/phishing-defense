from pathlib import Path
import base64

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

BASE_DIR = Path(__file__).resolve().parent.parent
TOKEN_FILE = BASE_DIR / "token.json"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def decode_body(data):
    if not data:
        return ""

    decoded = base64.urlsafe_b64decode(data + "===")
    return decoded.decode("utf-8", errors="replace")


def find_parts(payload, results):
    mime_type = payload.get("mimeType", "")

    body = payload.get("body", {})
    data = body.get("data")

    if data:
        results.append({
            "mimeType": mime_type,
            "content": decode_body(data),
        })

    for part in payload.get("parts", []):
        find_parts(part, results)


def main():
    if not TOKEN_FILE.exists():
        raise RuntimeError(
            "token.json not found. Run scripts/gmail_test.py first."
        )

    creds = Credentials.from_authorized_user_file(
        str(TOKEN_FILE),
        SCOPES,
    )

    service = build("gmail", "v1", credentials=creds)

    # Email 1 from gmail_scan.py
    message_id = "1a0bdb95427370fe"

    email = (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full",
        )
        .execute()
    )

    payload = email.get("payload", {})

    headers = payload.get("headers", [])

    print("=" * 70)
    print("EMAIL")
    print("=" * 70)

    for header in headers:
        if header["name"].lower() in {
            "from",
            "to",
            "subject",
            "date",
        }:
            print(f"{header['name']}: {header['value']}")

    parts = []
    find_parts(payload, parts)

    print("\n" + "=" * 70)
    print("CONTENT")
    print("=" * 70)

    for part in parts:
        print(f"\n--- {part['mimeType']} ---\n")
        print(part["content"][:5000])


if __name__ == "__main__":
    main()
