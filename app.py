from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3
from datetime import datetime
import os
import csv
import io
import smtplib
import ssl
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-prod")

DB_PATH = "leads.db"

# Admin
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # change in Render env vars!

# Email (SMTP) - set these in Render env vars when ready
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "")
OWNER_NOTIFY_EMAIL = os.environ.get("OWNER_NOTIFY_EMAIL", "")


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                company TEXT,
                message TEXT
            )
        """)
        conn.commit()


def is_admin() -> bool:
    return session.get("is_admin") is True


def email_enabled() -> bool:
    # Only enable if the critical pieces exist
    return all([SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM, OWNER_NOTIFY_EMAIL])


def send_email(to_email: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/lead", methods=["POST"])
def lead():
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    company = (request.form.get("company") or "").strip()
    message = (request.form.get("message") or "").strip()

    if not name or not email:
        flash("Name and email are required.", "error")
        return redirect(url_for("home"))

    created_at = datetime.utcnow().isoformat()

    # Save lead first (always)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO leads (created_at, name, email, phone, company, message) VALUES (?, ?, ?, ?, ?, ?)",
            (created_at, name, email, phone, company, message),
        )
        conn.commit()

    # Email notifications (fail-safe)
    if email_enabled():
        try:
            owner_subject = f"🔥 New Lead: {name} ({company or 'No company'})"
            owner_body = "\n".join([
                "A new lead was captured on Lead Machine Pro.",
                "",
                f"Time (UTC): {created_at}",
                f"Name: {name}",
                f"Email: {email}",
                f"Phone: {phone or '-'}",
                f"Company: {company or '-'}",
                "",
                "Message:",
                message or "-",
                "",
                "Admin Dashboard:",
                "Visit /admin to view all leads."
            ])
            send_email(OWNER_NOTIFY_EMAIL, owner_subject, owner_body)

            lead_subject = "✅ We got your enquiry — Lead Machine Pro"
            lead_body = "\n".join([
                f"Hi {name},",
                "",
                "Thanks — your enquiry has been received.",
                "Here’s what happens next:",
                "1) We review your message",
                "2) We respond with next steps",
                "3) If needed, we’ll book a quick call",
                "",
                "If you want to add context, just reply to this email.",
                "",
                "— Lead Machine Pro"
            ])
            send_email(email, lead_subject, lead_body)

        except Exception:
            # Don’t block lead capture if email fails
            flash("✅ Lead captured. (Email notification failed — check SMTP settings.)", "success")
            return redirect(url_for("home"))

    flash("✅ Lead captured. We'll reach out shortly.", "success")
    return redirect(url_for("home"))


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if is_admin():
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        pw = (request.form.get("password") or "").strip()
        if pw == ADMIN_PASSWORD:
            session["is_admin"] = True
            flash("✅ Admin access granted.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("❌ Incorrect password.", "error")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("👋 Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not is_admin():
        return redirect(url_for("admin_login"))

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, created_at, name, email, phone, company, message
            FROM leads
            ORDER BY datetime(created_at) DESC
        """).fetchall()

    leads = [dict(r) for r in rows]
    return render_template("admin_dashboard.html", leads=leads)


@app.route("/admin/export.csv", methods=["GET"])
def admin_export_csv():
    if not is_admin():
        return redirect(url_for("admin_login"))

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, created_at, name, email, phone, company, message
            FROM leads
            ORDER BY datetime(created_at) DESC
        """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "name", "email", "phone", "company", "message"])

    for r in rows:
        writer.writerow([r["id"], r["created_at"], r["name"], r["email"], r["phone"], r["company"], r["message"]])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=lead_machine_pro_leads.csv"
    return resp


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
else:
    # For gunicorn on Render
    init_db()
