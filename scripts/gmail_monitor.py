import time

from gmail_analyze import (
    get_gmail_service,
    get_latest_messages,
    analyze_email,
    print_report,
    load_processed_ids,
    save_processed_ids,
    save_report,
)

CHECK_INTERVAL = 30
MAX_RESULTS = 20


def check_for_new_emails(service, processed_ids):
    messages = get_latest_messages(
        service,
        max_results=MAX_RESULTS,
    )

    new_count = 0

    for message in reversed(messages):
        message_id = message["id"]

        if message_id in processed_ids:
            continue

        print("\n" + "=" * 70)
        print("NEW EMAIL DETECTED")
        print("=" * 70)

        try:
            report = analyze_email(
                service,
                message_id,
            )

            print_report(report)

            save_report(report)

            processed_ids.add(message_id)
            new_count += 1

            save_processed_ids(processed_ids)

        except Exception as error:
            print(
                f"ERROR analyzing message "
                f"{message_id}: {error}"
            )

    return new_count


def main():
    print("=" * 70)
    print("PHISHY GMAIL MONITOR")
    print("=" * 70)

    service = get_gmail_service()

    processed_ids = load_processed_ids()

    print(f"\nAlready processed: {len(processed_ids)} email(s)")
    print(f"Checking Gmail every {CHECK_INTERVAL} seconds...")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            new_count = check_for_new_emails(
                service,
                processed_ids,
            )

            if new_count == 0:
                print(
                    "No new emails."
                )

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n\nGmail monitor stopped.")


if __name__ == "__main__":
    main()
