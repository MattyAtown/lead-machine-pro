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

# Public base URL for verification links (set in Render)
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")

# Admin
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Email (SMTP) - set these in Render env vars when ready
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM_DEFAULT = os.environ.get("MAIL_FROM", "")
OWNER_NOTIFY_EMAIL_DEFAULT = os.environ.get("OWNER_NOTIFY_EMAIL", "")

UPGRADE_URL = os.environ.get("UPGRADE_URL", "")


# =========================
# DB helpers / migrations
# =========================
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

        # USERS
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

        # PAGES
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

        # LEADS
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
            # migrate columns safely
            lead_cols = _columns(conn, "leads")
            if "page_slug" not in lead_cols:
                conn.execute("ALTER TABLE leads ADD COLUMN page_slug TEXT")
            if "page_id" not in lead_cols:
                conn.execute("ALTER TABLE leads ADD COLUMN page_id INTEGER")

        conn.commit()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# Auth helpers
# =========================
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def is_admin() -> bool:
    return session.get("is_admin") is True

def require_login():
    if not session.get("user_id"):
        flash("Please log in first.", "error")
        return False
    return True

def require_verified(user):
    if not user or int(user["is_verified"]) != 1:
        flash("Please verify your email before using this feature.", "error")
        return False
    return True


# =========================
# Email helpers
# =========================
def email_enabled() -> bool:
    return all([SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM_DEFAULT])

def send_email(mail_from: str, to_email: str, subject: str, body: str) -> None:
    """
    Sends email via SMTP if configured. Raises on failure.
    """
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and mail_from and to_email):
        raise RuntimeError("SMTP not configured")

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
# Pages / Ownership helpers
# =========================
def get_page_and_owner_by_slug(slug: str):
    with get_db() as conn:
        page = conn.execute("""
            SELECT
                p.*,
                u.email AS owner_email,
                u.is_verified AS owner_verified,
                u.credits AS owner_credits,
                u.id AS owner_id
            FROM pages p
            JOIN users u ON u.id = p.user_id
            WHERE p.slug = ? AND p.is_active = 1
        """, (slug,)).fetchone()
        return page


# =========================
# Routes
# =========================
@app.route("/", methods=["GET"])
def home():
    default_cfg = {
        "brand_name": "Lead Machine Pro",
        "page_title": "Lead Machine Pro",
        "headline": "Turn clicks into booked calls.",
        "subheadline": "Single-page lead capture that converts visitors into conversations.",
        "cta_text": "⚡ Capture Lead",
        "slug": "home",
    }
    return render_template("landing.html", cfg=default_cfg)


@app.route("/r/<slug>", methods=["GET"])
def client_page(slug):
    slug = (slug or "").strip().lower()
    page = get_page_and_owner_by_slug(slug)
    if not page:
        abort(404)

    cfg = {
        "slug": page["slug"],
        "brand_name": page["brand_name"],
        "page_title": page["brand_name"],
        "headline": page["headline"],
        "subheadline": page["subheadline"],
        "cta_text": page["cta_text"],
    }
    return render_template("landing.html", cfg=cfg)


@app.route("/lead", methods=["POST"])
def lead():
    page_slug = (request.form.get("page_slug") or "home").strip().lower()

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    company = (request.form.get("company") or "").strip()
    message = (request.form.get("message") or "").strip()

    if not name or not email:
        flash("Name and email are required.", "error")
        return redirect(request.referrer or url_for("home"))

    created_at = datetime.utcnow().isoformat()
    page_id = None

    # Defaults for HOME (demo)
    brand_name = "Lead Machine Pro"
    owner_email = OWNER_NOTIFY_EMAIL_DEFAULT
    mail_from = MAIL_FROM_DEFAULT

    # If this is a real client page (/r/<slug>), enforce verification + credits
    if page_slug != "home":
        page = get_page_and_owner_by_slug(page_slug)
        if not page:
            flash("This lead page is not active.", "error")
            return redirect(url_for("home"))

        if int(page["owner_verified"]) != 1:
            flash("This page owner has not verified their email yet.", "error")
            return redirect(url_for("home"))

        if int(page["owner_credits"]) <= 0:
            flash("This page has run out of lead credits. Please contact the owner to upgrade.", "error")
            return redirect(url_for("client_page", slug=page_slug))

        # Route emails to the page notify email (created as user's email by default)
        brand_name = page["brand_name"]
        owner_email = page["notify_email"] or page["owner_email"]
        page_id = page["id"]

    # Save lead
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO leads (created_at, page_slug, page_id, name, email, phone, company, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (created_at, page_slug, page_id, name, email, phone, company, message),
        )
        conn.commit()

    # Decrement credits for client pages
    if page_slug != "home" and page_id is not None:
        with get_db() as conn:
            conn.execute("""
                UPDATE users
                SET credits = CASE WHEN credits > 0 THEN credits - 1 ELSE 0 END
                WHERE id = ?
            """, (page["owner_id"],))
            conn.commit()

    # Email notifications (best effort)
    if email_enabled():
        try:
            owner_subject = f"🔥 New Lead [{page_slug}]: {name} ({company or 'No company'})"
            owner_body = "\n".join([
                f"A new lead was captured on {brand_name}.",
                "",
                f"Page slug: {page_slug}",
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
            if owner_email and mail_from:
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
            if mail_from:
                send_email(mail_from, email, lead_subject, lead_body)

        except Exception:
            flash("✅ Lead captured. (Email notification failed — check SMTP settings.)", "success")
            return redirect(request.referrer or url_for("home"))

    flash("✅ Lead captured. We'll reach out shortly.", "success")
    return redirect(request.referrer or url_for("home"))


# =========================
# User Accounts
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
                conn.execute("""
                    INSERT INTO users (email, password_hash, is_verified, verify_token, plan, credits, created_at)
                    VALUES (?, ?, 0, ?, 'free', 3, ?)
                """, (email, pw_hash, verify_token, created_at))
                conn.commit()
        except sqlite3.IntegrityError:
            flash("That email is already registered. Try logging in.", "error")
            return redirect(url_for("login"))

        # Send verification email (best-effort)
        if email_enabled() and MAIL_FROM_DEFAULT:
            try:
                verify_link = f"{APP_BASE_URL}/verify/{verify_token}"
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

        if int(user["is_verified"]) == 1:
            flash("Email already verified. You can log in.", "success")
            return redirect(url_for("login"))

        conn.execute(
            "UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = ?",
            (user["id"],),
        )
        conn.commit()

    flash("✅ Email verified. Welcome!", "success")
    return redirect(url_for("dashboard"))


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

@app.route("/dev/verify_me", methods=["POST"])
def dev_verify_me():
    user = current_user()
    if not user:
        flash("Log in first.", "error")
        return redirect(url_for("login"))

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = ?",
            (user["id"],)
        )
        conn.commit()

    flash("✅ Verified (dev mode). Remove this later.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    flash("👋 Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not require_login():
        return redirect(url_for("login"))

    user = current_user()
    if not user:
        session.pop("user_id", None)
        return redirect(url_for("login"))

    # Create a lead page (verified users only)
    if request.method == "POST":
        if not require_verified(user):
            return redirect(url_for("dashboard"))

        slug = (request.form.get("slug") or "").strip().lower()
        brand_name = (request.form.get("brand_name") or "Lead Machine Pro").strip()
        headline = (request.form.get("headline") or "Turn clicks into booked calls.").strip()
        subheadline = (request.form.get("subheadline") or "Capture leads fast, follow up faster.").strip()

        if not slug:
            flash("Slug is required (e.g. mortgage-brokers).", "error")
            return redirect(url_for("dashboard"))

        allowed = "abcdefghijklmnopqrstuvwxyz0123456789-"
        slug = "".join([c for c in slug if c in allowed]).strip("-")
        if not slug:
            flash("Slug must contain letters/numbers (and hyphens).", "error")
            return redirect(url_for("dashboard"))

        created_at = datetime.utcnow().isoformat()

        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO pages (user_id, slug, brand_name, headline, subheadline, cta_text, notify_email, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    user["id"],
                    slug,
                    brand_name,
                    headline,
                    subheadline,
                    "Capture Lead",
                    user["email"],  # verified email becomes default notify email
                    created_at
                ))
                conn.commit()
            flash("✅ Lead page created!", "success")
        except sqlite3.IntegrityError:
            flash("That slug is already taken. Try another.", "error")

        return redirect(url_for("dashboard"))

    # List user pages
    with get_db() as conn:
        pages = conn.execute("""
            SELECT * FROM pages
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC
        """, (user["id"],)).fetchall()

    return render_template("dashboard.html", user=user, pages=pages)


# =========================
# Admin
# =========================
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
    # Only remove admin flag; don't nuke user login unless you want that behavior
    session.pop("is_admin", None)
    flash("👋 Admin logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
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

    leads = [dict(r) for r in rows]

    # slugs for filter UI (all known page slugs + home)
    with get_db() as conn:
        page_rows = conn.execute("SELECT slug FROM pages ORDER BY slug ASC").fetchall()
    slugs = ["home"] + [r["slug"] for r in page_rows]

    return render_template("dashboard.html", user=user, pages=pages, UPGRADE_URL=UPGRADE_URL)

@app.route("/admin/topup", methods=["GET", "POST"])
def admin_topup():
    if not is_admin():
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        amount_raw = (request.form.get("amount") or "").strip()

        # Basic validation
        try:
            amount = int(amount_raw)
        except Exception:
            flash("Amount must be a whole number.", "error")
            return redirect(url_for("admin_topup"))

        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("admin_topup"))

        if amount == 0:
            flash("Amount must not be 0.", "error")
            return redirect(url_for("admin_topup"))

        with get_db() as conn:
            user = conn.execute("SELECT id, credits FROM users WHERE email = ?", (email,)).fetchone()
            if not user:
                flash("User not found.", "error")
                return redirect(url_for("admin_topup"))

            new_credits = int(user["credits"]) + amount
            if new_credits < 0:
                new_credits = 0

            conn.execute("UPDATE users SET credits = ? WHERE id = ?", (new_credits, user["id"]))
            conn.commit()

        flash(f"✅ Updated {email} credits to {new_credits}.", "success")
        return redirect(url_for("admin_topup"))

    return render_template("admin_topup.html")


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


# =========================
# Boot
# =========================
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
