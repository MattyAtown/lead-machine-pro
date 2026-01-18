from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, abort
import sqlite3
from datetime import datetime
import os
import csv
import io
import smtplib
import ssl
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

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
MAIL_FROM_DEFAULT = os.environ.get("MAIL_FROM", "")  # default From if client doesn't override
OWNER_NOTIFY_EMAIL_DEFAULT = os.environ.get("OWNER_NOTIFY_EMAIL", "")  # default owner email


# =========================
# Multi-client configuration
# =========================
# Add new clients here. "slug" is the URL part: /r/<slug>
CLIENTS = {
    "recruiters": {
        "brand_name": "Lead Machine Pro",
        "page_title": "Recruiter Lead Machine",
        "headline": "Win more hiring briefs. Faster.",
        "subheadline": "Capture warm leads, respond instantly, and stop losing clients to slower recruiters.",
        "cta": "⚡ Request a callback",
        "owner_email": OWNER_NOTIFY_EMAIL_DEFAULT,  # can override per client
        "mail_from": MAIL_FROM_DEFAULT,             # can override per client
    },
    "mortgages": {
        "brand_name": "Lead Machine Pro",
        "page_title": "Mortgage Broker Lead Machine",
        "headline": "Turn mortgage enquiries into booked calls.",
        "subheadline": "Fast capture + instant reply so your leads don’t cool off.",
        "cta": "🏡 Get a quote",
        "owner_email": OWNER_NOTIFY_EMAIL_DEFAULT,
        "mail_from": MAIL_FROM_DEFAULT,
    },
    "consulting": {
        "brand_name": "Lead Machine Pro",
        "page_title": "Consulting Lead Machine",
        "headline": "Convert visitors into paid conversations.",
        "subheadline": "A single page that captures intent and triggers fast follow-up.",
        "cta": "🚀 Start the conversation",
        "owner_email": OWNER_NOTIFY_EMAIL_DEFAULT,
        "mail_from": MAIL_FROM_DEFAULT,
    },
}

def get_client(slug: str):
    return CLIENTS.get(slug)


def _table_exists(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,)
    ).fetchone()
    return row is not None

def _columns(conn, table: str) -> set[str]:
    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {c[1] for c in cols}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")

        # -------------------
        # USERS TABLE
        # -------------------
        if not _table_exists(conn, "users"):
            conn.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_verified INTEGER NOT NULL DEFAULT 0,
                    verify_token TEXT,
                    plan TEXT NOT NULL DEFAULT 'free',
                    credits INTEGER NOT NULL DEFAULT 3,
                    stripe_customer_id TEXT,
                    created_at TEXT NOT NULL
                )
            """)

        # -------------------
        # PAGES TABLE
        # -------------------
        if not _table_exists(conn, "pages"):
            conn.execute("""
                CREATE TABLE pages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    slug TEXT NOT NULL UNIQUE,
                    brand_name TEXT NOT NULL DEFAULT 'Lead Machine Pro',
                    headline TEXT NOT NULL DEFAULT 'Turn clicks into booked calls.',
                    subheadline TEXT NOT NULL DEFAULT 'Capture leads fast, follow up faster.',
                    cta_text TEXT NOT NULL DEFAULT 'Capture Lead',
                    notify_email TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

        # -------------------
        # LEADS TABLE (existing + migrate)
        # -------------------
        if not _table_exists(conn, "leads"):
            conn.execute("""
                CREATE TABLE leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    page_slug TEXT,
                    page_id INTEGER,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT,
                    company TEXT,
                    message TEXT,
                    FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE SET NULL
                )
            """)
        else:
            # Add missing columns safely
            lead_cols = _columns(conn, "leads")
            if "page_slug" not in lead_cols:
                conn.execute("ALTER TABLE leads ADD COLUMN page_slug TEXT")
            if "page_id" not in lead_cols:
                conn.execute("ALTER TABLE leads ADD COLUMN page_id INTEGER")

            # NOTE: SQLite can't easily add FK constraints via ALTER TABLE.
            # We'll keep the FK in the CREATE TABLE for fresh DBs.
            # For existing DBs, app logic will still work fine.

        conn.commit()


def get_db():
    """Return a SQLite connection with Row dict-style access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required() -> bool:
    return session.get("user_id") is not None


def is_admin() -> bool:
    return session.get("is_admin") is True


def email_enabled_for(owner_email: str, mail_from: str) -> bool:
    return all([SMTP_HOST, SMTP_USER, SMTP_PASS, owner_email, mail_from])


def send_email(mail_from: str, to_email: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


# =========================
# Routes
# =========================
@app.route("/", methods=["GET"])
def home():
    # “Home” can be your main demo landing page
    # It uses the same template as client pages but with a default config.
    default_cfg = {
        "brand_name": "Lead Machine Pro",
        "page_title": "Lead Machine Pro",
        "headline": "Turn clicks into booked calls.",
        "subheadline": "Single-page lead capture that converts visitors into conversations.",
        "cta": "⚡ Capture Lead",
        "slug": "home",
    }
    return render_template("landing.html", cfg=default_cfg)


@app.route("/r/<slug>", methods=["GET"])
def client_page(slug):
    cfg = get_client(slug)
    if not cfg:
        abort(404)

    # inject slug so form posts with the correct routing
    cfg = dict(cfg)
    cfg["slug"] = slug
    return render_template("landing.html", cfg=cfg)


@app.route("/lead", methods=["POST"])
def lead():
    slug = (request.form.get("page_slug") or "home").strip()
    cfg = get_client(slug) if slug != "home" else None

    # Determine routing defaults
    brand_name = (cfg.get("brand_name") if cfg else "Lead Machine Pro")
    owner_email = (cfg.get("owner_email") if cfg else OWNER_NOTIFY_EMAIL_DEFAULT)
    mail_from = (cfg.get("mail_from") if cfg else MAIL_FROM_DEFAULT)

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    company = (request.form.get("company") or "").strip()
    message = (request.form.get("message") or "").strip()

    if not name or not email:
        flash("Name and email are required.", "error")
        return redirect(request.referrer or url_for("home"))

    created_at = datetime.utcnow().isoformat()

    # Save lead first (always)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO leads (created_at, page_slug, name, email, phone, company, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (created_at, slug, name, email, phone, company, message),
        )
        conn.commit()

    # Email notifications (fail-safe)
    if email_enabled_for(owner_email, mail_from):
        try:
            owner_subject = f"🔥 New Lead [{slug}]: {name} ({company or 'No company'})"
            owner_body = "\n".join([
                f"A new lead was captured on {brand_name}.",
                "",
                f"Page slug: {slug}",
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
            send_email(mail_from, owner_email, owner_subject, owner_body)

            lead_subject = f"✅ We got your enquiry — {brand_name}"
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
                f"— {brand_name}"
            ])
            send_email(mail_from, email, lead_subject, lead_body)

        except Exception:
            flash("✅ Lead captured. (Email notification failed — check SMTP settings.)", "success")
            return redirect(request.referrer or url_for("home"))

    flash("✅ Lead captured. We'll reach out shortly.", "success")
    return redirect(request.referrer or url_for("home"))


# =========================
# User Accounts (Step 2)
# =========================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("signup"))

        pw_hash = generate_password_hash(password)
        verify_token = secrets.token_urlsafe(32)
        created_at = datetime.utcnow().isoformat()

        try:
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (email, password_hash, is_verified, verify_token, plan, credits, created_at)
                    VALUES (?, ?, 0, ?, 'free', 3, ?)
                    """,
                    (email, pw_hash, verify_token, created_at),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            flash("That email is already registered. Try logging in.", "error")
            return redirect(url_for("login"))

        # Send verification email (best-effort)
        verify_link = f"{APP_BASE_URL}/verify/{verify_token}"
        try:
            subject = "Verify your email — Lead Machine Pro"
            body = "\n".join([
                "Welcome to Lead Machine Pro.",
                "",
                "Please verify your email by clicking this link:",
                verify_link,
                "",
                "If you didn't create this account, you can ignore this email."
            ])
            send_email(MAIL_FROM_DEFAULT, email, subject, body)
        except Exception:
            pass

        flash("Account created. Check your email to verify your account.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        flash("✅ Logged in.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    flash("👋 Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not login_required():
        return redirect(url_for("login"))

    user = current_user()
    return render_template("dashboard.html", user=user)


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

    # Optional filter: /admin/dashboard?slug=recruiters
    slug = (request.args.get("slug") or "").strip()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if slug:
            rows = conn.execute("""
                SELECT id, created_at, page_slug, name, email, phone, company, message
                FROM leads
                WHERE page_slug = ?
                ORDER BY datetime(created_at) DESC
            """, (slug,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, created_at, page_slug, name, email, phone, company, message
                FROM leads
                ORDER BY datetime(created_at) DESC
            """).fetchall()

    leads = [dict(r) for r in rows]
    # Pass known slugs for quick filtering UI (template can show them)
    slugs = sorted(set(list(CLIENTS.keys()) + ["home"]))
    return render_template("admin_dashboard.html", leads=leads, slugs=slugs, active_slug=slug)


@app.route("/admin/export.csv", methods=["GET"])
def admin_export_csv():
    if not is_admin():
        return redirect(url_for("admin_login"))

    slug = (request.args.get("slug") or "").strip()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if slug:
            rows = conn.execute("""
                SELECT id, created_at, page_slug, name, email, phone, company, message
                FROM leads
                WHERE page_slug = ?
                ORDER BY datetime(created_at) DESC
            """, (slug,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, created_at, page_slug, name, email, phone, company, message
                FROM leads
                ORDER BY datetime(created_at) DESC
            """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "page_slug", "name", "email", "phone", "company", "message"])

    for r in rows:
        writer.writerow([r["id"], r["created_at"], r["page_slug"], r["name"], r["email"], r["phone"], r["company"], r["message"]])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=lead_machine_pro_leads.csv"
    return resp


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
else:
    init_db()


@app.route("/verify/<token>", methods=["GET"])
def verify_email(token):
    token = (token or "").strip()
    if not token:
        flash("Invalid verification link.", "error")
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute(
            "SELECT id, is_verified FROM users WHERE verify_token = ?",
            (token,),
        ).fetchone()

        if not user:
            flash("Verification link is invalid or expired.", "error")
            return redirect(url_for("login"))

        if user["is_verified"] == 1:
            flash("Email already verified. You can log in.", "success")
            return redirect(url_for("login"))

        conn.execute(
            "UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = ?",
            (user["id"],),
        )
        conn.commit()

    flash("Email verified. Welcome!", "success")
    return redirect(url_for("dashboard"))
