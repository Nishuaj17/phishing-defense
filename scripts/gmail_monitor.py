
import time
import subprocess

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


def show_phishy_alert(report):
    """Show a macOS notification for suspicious emails."""

    # The analyzer result is stored inside report["result"].
    result = report.get("result")

    if result is None:
        print("No analysis result found; notification skipped.")
        return

    # Support both dictionary and object results.
    if isinstance(result, dict):
        verdict = result.get("label", "")
        action = result.get("recommended_action", "")
    else:
        verdict = getattr(result, "label", "")
        action = getattr(result, "recommended_action", "")

    verdict = str(verdict).strip().lower()
    action = str(action).strip().lower()

    print(
        f"Notification check: verdict={verdict!r}, "
        f"action={action!r}"
    )

    suspicious_verdicts = {
        "phishing",
        "suspicious",
        "malicious",
    }

    suspicious_actions = {
        "warn",
        "block",
    }

    # Notify if either the verdict or the recommended action
    # indicates a suspicious email.
    if (
        verdict not in suspicious_verdicts
        and action not in suspicious_actions
    ):
        print("No warning notification required.")
        return

    sender = str(
        report.get("sender") or "Unknown sender"
    )

    subject = str(
        report.get("subject") or "Email without a subject"
    )

    def escape_applescript(value):
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", " ")
            .replace("\r", " ")
        )[:180]

    title = escape_applescript(
        "Phishy: Suspicious Email"
    )

    message = escape_applescript(
        f"{verdict.upper() or action.upper()} — "
        f"{sender}: {subject}"
    )

    script = (
        f'display notification "{message}" '
        f'with title "{title}"'
    )

    try:
        completed = subprocess.run(
            ["osascript", "-e", script],
            check=False,
            capture_output=True,
            text=True,
        )

        if completed.returncode == 0:
            print("Phishy desktop warning displayed.")
        else:
            print(
                "Could not display macOS notification:",
                completed.stderr.strip(),
            )

    except OSError as error:
        print(f"Notification error: {error}")


def check_for_new_emails(service, processed_ids):
    """Fetch and analyze emails that have not been processed."""

    messages = get_latest_messages(
        service,
        max_results=MAX_RESULTS,
    )

    new_count = 0

    # Process older messages first when several arrive together.
    for message in reversed(messages):
        message_id = message.get("id")

        if not message_id:
            continue

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

            # Keep email reports stored locally.
            save_report(report)

            # Show a desktop warning when needed.
            show_phishy_alert(report)

            # Mark as processed after successful analysis.
            processed_ids.add(message_id)
            save_processed_ids(processed_ids)

            new_count += 1

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

    try:
        service = get_gmail_service()
    except Exception as error:
        print(f"Could not connect to Gmail: {error}")
        return

    processed_ids = load_processed_ids()

    print(
        f"\nAlready processed: "
        f"{len(processed_ids)} email(s)"
    )
    print(
        f"Checking Gmail every {CHECK_INTERVAL} seconds..."
    )
    print(
        "Monitoring the folders configured in "
        "get_latest_messages()."
    )
    print(
        "Suspicious emails will trigger macOS notifications."
    )
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                new_count = check_for_new_emails(
                    service,
                    processed_ids,
                )

                if new_count == 0:
                    print("No new emails.")

            except Exception as error:
                print(f"ERROR checking Gmail: {error}")

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\nGmail monitor stopped.")


if __name__ == "__main__":
    main()
