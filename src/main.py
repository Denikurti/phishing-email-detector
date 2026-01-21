import csv
import argparse
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_INPUT = "data/emails.csv"
DEFAULT_OUT = "report.csv"

SUSPICIOUS_KEYWORDS = [
    "verify", "locked", "suspended", "action required", "urgent", "payment failed",
    "compromised", "secure", "reset", "unusual login"
]

BRAND_KEYWORDS = ["amazon", "paypal", "netflix", "apple", "bank"]


def domain_from_email(email: str) -> str:
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower().strip()


def domain_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().strip()
    except Exception:
        return ""


def score_email(row: dict) -> tuple[int, list[str]]:
    reasons = []
    score = 0

    sender = (row.get("sender") or "").lower()
    subject = (row.get("subject") or "").lower()
    body = (row.get("body") or "").lower()
    links = (row.get("links") or "").strip()
    attachments = (row.get("attachments") or "").lower().strip()

    sender_domain = domain_from_email(sender)

    # Keyword scoring (subject/body)
    text = f"{subject} {body}"
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in text:
            score += 2
            reasons.append(f"keyword:{kw}")

    # Link scoring
    if links and links.lower() != "none":
        link_domain = domain_from_url(links)

        if links.lower().startswith("http://"):
            score += 3
            reasons.append("link:http")

        if link_domain and sender_domain and link_domain != sender_domain:
            score += 2
            reasons.append("link_domain_mismatch")

        # Brand mismatch: brand word in sender but sender domain looks off
        for brand in BRAND_KEYWORDS:
            if brand in sender and brand not in sender_domain:
                score += 3
                reasons.append(f"brand_domain_mismatch:{brand}")
                break

        # Simple typo/lookalike hint
        if "0" in links or ("-" in link_domain and link_domain):
            score += 1
            reasons.append("lookalike_hint")

    # Attachment scoring
    if attachments and attachments != "none":
        score += 2
        reasons.append("has_attachment")

        risky = [".exe", ".js", ".vbs", ".bat", ".scr", ".zip", ".iso", ".docm", ".xlsm"]
        if any(ext in attachments for ext in risky):
            score += 4
            reasons.append("risky_attachment_type")

    return score, reasons


def main():
    parser = argparse.ArgumentParser(description="Phishing Email Detector (rule-based scorer)")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input CSV path")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Output report CSV path")
    parser.add_argument("--min_score", type=int, default=0, help="Only display emails with score >= this")
    args = parser.parse_args()

    input_path = Path(args.input)
    out_path = Path(args.out)

    if not input_path.exists():
        print(f"Missing file: {input_path}")
        return

    emails = []
    with input_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            s, reasons = score_email(row)
            row["_score"] = s
            row["_reasons"] = ";".join(reasons)
            emails.append(row)

    emails.sort(key=lambda r: r["_score"], reverse=True)

    # Terminal output (filtered)
    filtered = [r for r in emails if r["_score"] >= args.min_score]

    print("=== Phishing Email Detector ===")
    print(f"Input: {input_path}")
    print(f"Loaded: {len(emails)} emails")
    print(f"Showing score >= {args.min_score}: {len(filtered)} emails\n")

    print("Top suspicious emails:")
    for r in filtered[:10]:
        print(f"- id={r.get('id')} score={r['_score']} sender={r.get('sender')} subject={r.get('subject')}")
        print(f"  reasons: {r['_reasons']}\n")

    # Write full results to CSV report (not filtered)
    fieldnames = ["id", "sender", "subject", "links", "attachments", "score", "reasons"]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in emails:
            w.writerow({
                "id": r.get("id"),
                "sender": r.get("sender"),
                "subject": r.get("subject"),
                "links": r.get("links"),
                "attachments": r.get("attachments"),
                "score": r["_score"],
                "reasons": r["_reasons"],
            })

    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
