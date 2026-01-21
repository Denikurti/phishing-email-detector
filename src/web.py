from flask import Flask, request, render_template_string
import csv
import os
from urllib.parse import urlparse

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Phishing Email Detector</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 16px; background: #f7f9fc; }
    .container { background: #fff; border: 1px solid #e6eaf2; border-radius: 12px; padding: 24px; box-shadow: 0 6px 18px rgba(0,0,0,0.06); }
    .header { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; }
    .badge { background: #e8f0ff; color: #1d4ed8; padding: 6px 10px; border-radius: 999px; font-weight: 700; font-size: 12px; }
    h1 { margin: 0; font-size: 40px; color: #0f172a; }
    .muted { color: #475569; margin-top: 6px; }
    form { margin: 18px 0; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    label { color: #0f172a; font-weight: 700; }
    input[type="number"] { width: 120px; padding: 10px; border: 1px solid #cbd5e1; border-radius: 8px; }
    button { padding: 10px 14px; cursor: pointer; border: 0; border-radius: 10px; background: #2563eb; color: white; font-weight: 700; }
    button:hover { filter: brightness(0.95); }
    .meta { color: #0f172a; font-weight: 700; margin: 10px 0 0; }
    .small { color: #64748b; font-size: 13px; margin-top: 6px; }
    table { width: 100%; border-collapse: collapse; margin-top: 14px; background: #fff; }
    th, td { border-bottom: 1px solid #e2e8f0; padding: 12px; vertical-align: top; }
    th { background: #f1f5f9; text-align: left; font-size: 14px; }
    td { font-size: 14px; }
    .score { font-weight: 800; }
    .sender, .subject { word-break: break-word; }
    .reasons ul { margin: 0; padding-left: 18px; }
    .reasons li { margin: 2px 0; color: #334155; }
    .error { background: #ffe8e8; padding: 10px; border: 1px solid #ffb3b3; border-radius: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>Phishing Email Detector</h1>
        <p class="muted">Scores emails for phishing indicators and shows the most suspicious items.</p>
      </div>
      <div class="badge">Python + Flask</div>
    </div>

    {% if error %}
      <div class="error"><b>Error:</b> {{ error }}</div>
    {% endif %}

    <form method="get">
      <label>Min score:</label>
      <input type="number" name="min_score" value="{{ min_score }}" min="0" />
      <button type="submit">Analyze</button>
    </form>

    <div class="meta">
      Input: <span class="small">{{ input_path }}</span>
      &nbsp;|&nbsp; Loaded: {{ loaded }}
      &nbsp;|&nbsp; Showing: {{ shown }}
    </div>
    <div class="small">Tip: Increase min score to show only high-risk emails.</div>

    {% if results %}
      <table>
        <thead>
          <tr>
            <th style="width:60px;">ID</th>
            <th style="width:230px;">Sender</th>
            <th>Subject</th>
            <th style="width:90px;">Score</th>
            <th style="width:360px;">Reasons</th>
          </tr>
        </thead>
        <tbody>
          {% for r in results %}
            <tr>
              <td>{{ r["id"] }}</td>
              <td class="sender">{{ r["sender"] }}</td>
              <td class="subject">{{ r["subject"] }}</td>
              <td class="score">{{ r["score"] }}</td>
              <td class="reasons">
                <ul>
                  {% for reason in r["reasons_list"] %}
                    <li>{{ reason }}</li>
                  {% endfor %}
                </ul>
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p class="small">No results.</p>
    {% endif %}
  </div>
</body>
</html>
"""

KEYWORDS = [
    "verify", "suspended", "action required", "locked", "payment failed",
    "compromised", "secure", "reset", "unusual login"
]

BRANDS = {
    "amazon": ["amazon.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com", "icloud.com"],
}

def get_domain(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""

def lookalike_hint(text: str) -> bool:
    t = (text or "").lower()
    return any(x in t for x in ["0", "1", "secure-", "-secure", "login-", "-login"])

def score_email(row: dict) -> tuple[int, list[str]]:
    sender = (row.get("sender") or "").lower()
    subject = (row.get("subject") or "").lower()
    body = (row.get("body") or "").lower()
    links = (row.get("links") or "").strip()

    score = 0
    reasons = []

    blob = f"{sender} {subject} {body}"

    for k in KEYWORDS:
        if k in blob:
            score += 2
            reasons.append(f"Keyword match: '{k}'")

    attachments = (row.get("attachments") or "").lower()
    if attachments and attachments != "none":
        score += 2
        reasons.append("Has attachment")

    if links and links.lower() != "none":
        if links.lower().startswith("http://"):
            score += 2
            reasons.append("HTTP link (not HTTPS)")

        link_domain = get_domain(links)
        sender_domain = sender.split("@")[-1] if "@" in sender else ""

        if link_domain and sender_domain and link_domain != sender_domain:
            score += 2
            reasons.append("Link domain differs from sender domain")

        for brand, legit_domains in BRANDS.items():
            if brand in sender or brand in subject or brand in body:
                if not any(d in sender for d in legit_domains):
                    score += 3
                    reasons.append(f"Brand/domain mismatch: {brand}")

    if lookalike_hint(sender) or lookalike_hint(links):
        score += 1
        reasons.append("Possible lookalike pattern")

    return score, reasons

def load_emails(csv_path: str) -> list[dict]:
    emails = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            emails.append(row)
    return emails

@app.route("/", methods=["GET"])
def index():
    base_dir = os.path.dirname(os.path.dirname(__file__))  # project root
    input_path = os.path.join(base_dir, "data", "emails.csv")

    try:
        min_score = int(request.args.get("min_score", "8"))
    except ValueError:
        min_score = 8

    try:
        emails = load_emails(input_path)
        scored = []
        for e in emails:
            s, reasons = score_email(e)
            out = {
                "id": e.get("id", ""),
                "sender": e.get("sender", ""),
                "subject": e.get("subject", ""),
                "score": s,
                "reasons_list": reasons if reasons else ["No indicators found"],
            }
            if s >= min_score:
                scored.append(out)

        scored.sort(key=lambda x: x["score"], reverse=True)

        return render_template_string(
            TEMPLATE,
            input_path="data/emails.csv",
            min_score=min_score,
            loaded=len(emails),
            shown=len(scored),
            results=scored,
            error=None,
        )
    except Exception as ex:
        return render_template_string(
            TEMPLATE,
            input_path="data/emails.csv",
            min_score=min_score,
            loaded=0,
            shown=0,
            results=[],
            error=str(ex),
        )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
