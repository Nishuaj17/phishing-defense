from pathlib import Path

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

BASE_DIR = Path(__file__).resolve().parent.parent
TOKEN_FILE = BASE_DIR / "token.json"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_header(headers, name):
    for header in headers:
        if header["name"].lower() == name.lower():
            return header["value"]
    return ""


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

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=10,
        )
        .execute()
    )

    messages = response.get("messages", [])

    print(f"\nFound {len(messages)} messages.\n")

    for index, message in enumerate(messages, start=1):
        email = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="metadata",
                metadataHeaders=["From", "To", "Subject", "Date"],
            )
            .execute()
        )

        headers = email.get("payload", {}).get("headers", [])

        sender = get_header(headers, "From")
        recipient = get_header(headers, "To")
        subject = get_header(headers, "Subject")
        date = get_header(headers, "Date")

        print("=" * 70)
        print(f"Email {index}")
        print(f"ID:       {message['id']}")
        print(f"From:     {sender}")
        print(f"To:       {recipient}")
        print(f"Subject:  {subject}")
        print(f"Date:     {date}")
        print(f"Snippet:  {email.get('snippet', '')[:200]}")

    print("=" * 70)


if __name__ == "__main__":
    main()
