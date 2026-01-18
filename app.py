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
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # change in prod!

# Email (SMTP) - set these in Render env vars
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "")  # e.g. "Lead Machine Pro <noreply@yourdomain.com>"
OWNER_NOTIFY_EMAIL = os.environ.get("OWNER_NOTIFY_EMAIL", "")  # where you want lead alerts

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

def is_admin():
    return session.get("is_admin") is True

def email_enabled():
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

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO leads (created_at, name, email, phone, company, message) VALUES (?, ?, ?, ?, ?, ?)",
            (created_at, name, email, phone, company, message),
        )
        conn.commit()

    # Email notifications (non-blocking for lead capture; fail safely)
    if email_enabled():
        try:
            owner_subject = f"🔥 New Lead: {name} ({company or 'No company'})"
            owner_body = (_
