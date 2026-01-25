from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, abort, jsonify
import sqlite3
from datetime import datetime, timedelta
import os
import csv
import io
import smtplib
import ssl
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import json
import urllib.request
import urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-prod")

DB_PATH = "leads.db"

# Admin
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Email (SMTP)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM_DEFAULT = os.environ.get("MAIL_FROM", "")
OWNER_NOTIFY_EMAIL_DEFAULT = os.environ.get("OWNER_NOTIFY_EMAIL", "")
DEV_ALLOW_UNVERIFIED = os.environ.get("DEV_ALLOW_UNVERIFIED", "1") == "1"

# Dashboard upgrade link (optional)
UPGRADE_URL = os.environ.get("UPGRADE_URL", "")

# Base URL for verification links
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").strip().rstrip("/")

# Runner protection token (Render cron will call /tasks/run_searches with this)
RUNNER_TOKEN = os.environ.get("RUNNER_TOKEN", "")

# =========================
# Legacy multi-client config (kept)
# =========================
CLIENTS = {
    "recruiters": {
        "brand_name": "Lead Machine Pro",
        "page_title": "Recruiter Lead Machine",
        "headline": "Win more hiring briefs. Faster.",
        "subheadline": "Capture warm leads, respond instantly, and stop losing clients to slower recruiters.",
        "cta": "⚡ Request a callback",
        "owner_email": OWNER_NOTIFY_EMAIL_DEFAULT,
        "mail_from": MAIL_FROM_DEFAULT,
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
        else:
            cols = _columns(conn, "users")
            if "plan" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'")
            if "credits" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN credits INTEGER NOT NULL DEFAULT 3")

        # -------------------
        # PAGES TABLE (kept)
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
        # LEADS TABLE (kept + migrate)
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
                    message TEXT
                )
            """)
        else:
            lead_cols = _columns(conn, "leads")
            if "page_slug" not in lead_cols:
                conn.execute("ALTER TABLE leads ADD COLUMN page_slug TEXT")
            if "page_id" not in lead_cols:
                conn.execute("ALTER TABLE leads ADD COLUMN page_id INTEGER")

        # =========================
        # AUTOMATION TABLES (NEW)
        # =========================

        # Search programs = saved searches that run every 6 hours
        if not _table_exists(conn, "search_programs"):
            conn.execute("""
                CREATE TABLE search_programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    keywords TEXT NOT NULL,
                    location TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'inactive',
                    active_until TEXT,
                    leads_found_count INTEGER NOT NULL DEFAULT 0,
                    last_run_at TEXT,
                    next_run_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

        # Job leads = discovered opportunities
        if not _table_exists(conn, "job_leads"):
            conn.execute("""
                CREATE TABLE job_leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    company TEXT,
                    role_title TEXT NOT NULL,
                    location TEXT,
                    source_url TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    FOREIGN KEY(program_id) REFERENCES search_programs(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            # Dedupe: same URL should not be sent twice to same user
            conn.execute("CREATE UNIQUE INDEX idx_jobleads_user_url ON job_leads(user_id, source_url)")
        else:
            # Ensure the dedupe index exists (best-effort)
            try:
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobleads_user_url ON job_leads(user_id, source_url)")
            except Exception:
                pass

        # Credit events = audit log
        if not _table_exists(conn, "credit_events"):
            conn.execute("""
                CREATE TABLE credit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    delta INTEGER NOT NULL,
                    note TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

        conn.commit()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def is_admin() -> bool:
    return session.get("is_admin") is True

def email_enabled() -> bool:
    return all([SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM_DEFAULT])

def send_email(mail_from: str, to_email: str, subject: str, body: str) -> None:
    if not email_enabled() or not mail_from or not to_email:
        return
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

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

def bool_match(keywords: str, text: str) -> bool:
    """
    Very simple boolean-ish matching (v1):
    - supports OR with '|'
    - supports quoted phrases loosely (we treat as plain substring)
    - default = all space-separated tokens must appear
    Example:
      "python | golang"  => any match
      "recruiter london" => both words must appear
    """
    if not keywords:
        return False
    text_l = (text or "").lower()

    # OR groups
    if "|" in keywords:
        parts = [p.strip().lower() for p in keywords.split("|") if p.strip()]
        return any(p in text_l for p in parts)

    # AND tokens
    tokens = [t.strip().lower() for t in keywords.replace('"', '').split() if t.strip()]
    return all(t in text_l for t in tokens)

# =========================
# Free Job API Adapter (v1): Remotive
# https://remotive.com/remote-jobs/api
# =========================
def fetch_jobs_remotive() -> list[dict]:
    url = "https://remotive.com/api/remote-jobs"
    req = urllib.request.Request(url, headers={"User-Agent": "LeadMachinePro/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    jobs = data.get("jobs", []) or []
    results = []
    for j in jobs:
        results.append({
            "role_title": j.get("title") or "Untitled role",
            "company": j.get("company_name") or "",
            "location": j.get("candidate_required_location") or j.get("location") or "",
            "source_url": j.get("url") or "",
            "published_at": j.get("publication_date") or ""
        })
    return results

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat()

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
        "cta": "⚡ Capture Lead",
        "slug": "home",
    }
    return render_template("landing.html", cfg=default_cfg)

# Keep legacy public pages
@app.route("/r/<slug>", methods=["GET"])
def client_page(slug):
    cfg = get_client((slug or "").strip().lower())
    if not cfg:
        abort(404)
    cfg = dict(cfg)
    cfg["slug"] = slug
    return render_template("landing.html", cfg=cfg)

@app.route("/lead", methods=["POST"])
def lead():
    slug = (request.form.get("page_slug") or "home").strip().lower()
    cfg = get_client(slug) if slug != "home" else None

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

    created_at = now_iso()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO leads (created_at, page_slug, name, email, phone, company, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (created_at, slug, name, email, phone, company, message),
        )
        conn.commit()

    # Best-effort email
    try:
        if owner_email and mail_from and email_enabled():
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
            ])
            send_email(mail_from, owner_email, owner_subject, owner_body)
    except Exception:
        pass

    flash("✅ Lead captured. We'll reach out shortly.", "success")
    return redirect(request.referrer or url_for("home"))

# =========================
# Accounts
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
        created_at = now_iso()

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
        if APP_BASE_URL:
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

@app.route("/verify/<token>", methods=["GET"])
def verify_email(token):
    token = (token or "").strip()
    if not token:
        flash("Invalid verification link.", "error")
        return redirect(url_for("login"))

    with get_db() as conn:
        user = conn.execute("SELECT id, is_verified FROM users WHERE verify_token = ?", (token,)).fetchone()
        if not user:
            flash("Verification link is invalid or expired.", "error")
            return redirect(url_for("login"))

        if int(user["is_verified"]) == 1:
            flash("Email already verified. You can log in.", "success")
            return redirect(url_for("login"))

        conn.execute("UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = ?", (user["id"],))
        conn.commit()

    flash("Email verified. Welcome!", "success")
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

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    flash("👋 Logged out.", "success")
    return redirect(url_for("home"))

# =========================
# Dashboard: programs (NEW)
# =========================
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not require_login():
        return redirect(url_for("login"))

    user = current_user()
    if not user:
        session.pop("user_id", None)
        return redirect(url_for("login"))

    # Create a Search Program
    if request.method == "POST":
        if not require_verified(user):
            return redirect(url_for("dashboard"))

        name = (request.form.get("name") or "My Job Search").strip()
        keywords = (request.form.get("keywords") or "").strip()
        location = (request.form.get("location") or "Global").strip()

        if not keywords:
            flash("Keywords are required (supports simple boolean with |).", "error")
            return redirect(url_for("dashboard"))

        created_at = now_iso()

        with get_db() as conn:
            conn.execute("""
                INSERT INTO search_programs (user_id, name, keywords, location, status, created_at)
                VALUES (?, ?, ?, ?, 'inactive', ?)
            """, (user["id"], name, keywords, location, created_at))
            conn.commit()

        flash("✅ Search program created. Start it to consume 1 credit (7 days).", "success")
        return redirect(url_for("dashboard"))

    # List programs
    with get_db() as conn:
        programs = conn.execute("""
            SELECT * FROM search_programs
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC
        """, (user["id"],)).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        programs=programs,
        UPGRADE_URL=UPGRADE_URL
    )

@app.route("/program/<int:program_id>/start", methods=["POST"])
def start_program(program_id: int):
    if not require_login():
        return redirect(url_for("login"))
    user = current_user()
    if not require_verified(user):
        return redirect(url_for("dashboard"))

    with get_db() as conn:
        prog = conn.execute("SELECT * FROM search_programs WHERE id=? AND user_id=?", (program_id, user["id"])).fetchone()
        if not prog:
            flash("Program not found.", "error")
            return redirect(url_for("dashboard"))

        # Subscribed users (future) can start without credits. For now: plan != free means subscribed.
        is_subscribed = (user["plan"] != "free")

        if not is_subscribed:
            if int(user["credits"]) <= 0:
                flash("You have 0 credits. Top up or subscribe to start scanning.", "error")
                return redirect(url_for("dashboard"))

            # Consume 1 credit = 7 days scanning
            new_credits = int(user["credits"]) - 1
            conn.execute("UPDATE users SET credits=? WHERE id=?", (new_credits, user["id"]))
            conn.execute("""
                INSERT INTO credit_events (user_id, event_type, delta, note, created_at)
                VALUES (?, 'run_week', -1, ?, ?)
            """, (user["id"], f"Activated program #{program_id} for 7 days", now_iso()))

        active_until = (datetime.utcnow() + timedelta(days=7)).replace(microsecond=0).isoformat()
        next_run = (datetime.utcnow() + timedelta(hours=6)).replace(microsecond=0).isoformat()

        conn.execute("""
            UPDATE search_programs
            SET status='running', active_until=?, next_run_at=?, last_run_at=NULL
            WHERE id=?
        """, (active_until, next_run, program_id))
        conn.commit()

    flash("✅ Program started. It will run every 6 hours for 7 days.", "success")
    return redirect(url_for("dashboard"))

@app.route("/program/<int:program_id>/pause", methods=["POST"])
def pause_program(program_id: int):
    if not require_login():
        return redirect(url_for("login"))
    user = current_user()

    with get_db() as conn:
        conn.execute("""
            UPDATE search_programs SET status='paused'
            WHERE id=? AND user_id=?
        """, (program_id, user["id"]))
        conn.commit()

    flash("⏸ Program paused.", "success")
    return redirect(url_for("dashboard"))

# =========================
# Runner Endpoint (NEW)
# Called by Render Cron Job every 6 hours
# =========================
def _auth_runner(req) -> bool:
    if not RUNNER_TOKEN:
        return False
    auth = req.headers.get("Authorization", "")
    return auth.strip() == f"Bearer {RUNNER_TOKEN}"

@app.route("/tasks/run_searches", methods=["POST"])
def run_searches():
    if not _auth_runner(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    ran = 0
    created = 0
    expired = 0

    now = datetime.utcnow()

    with get_db() as conn:
        # Find running programs
        programs = conn.execute("""
            SELECT sp.*, u.email AS user_email, u.plan AS user_plan
            FROM search_programs sp
            JOIN users u ON u.id = sp.user_id
            WHERE sp.status='running'
        """).fetchall()

        for sp in programs:
            ran += 1

            # Expiry check
            active_until = sp["active_until"]
            if active_until:
                try:
                    au = datetime.fromisoformat(active_until)
                    if now > au:
                        conn.execute("""
                            UPDATE search_programs SET status='expired'
                            WHERE id=?
                        """, (sp["id"],))
                        expired += 1
                        continue
                except Exception:
                    pass

            keywords = sp["keywords"]
            loc = (sp["location"] or "").lower()

            # Fetch jobs from Remotive (v1 free adapter)
            try:
                jobs = fetch_jobs_remotive()
            except Exception:
                jobs = []

            for j in jobs:
                # Match keyword against title + company + location
                hay = f"{j.get('role_title','')} {j.get('company','')} {j.get('location','')}"
                if not bool_match(keywords, hay):
                    continue

                # Location filter (very light v1)
                if loc and loc != "global":
                    if loc not in (j.get("location","").lower()):
                        continue

                source_url = (j.get("source_url") or "").strip()
                if not source_url:
                    continue

                detected_at = now_iso()
                try:
                    conn.execute("""
                        INSERT INTO job_leads (program_id, user_id, company, role_title, location, source_url, detected_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sp["id"],
                        sp["user_id"],
                        j.get("company",""),
                        j.get("role_title",""),
                        j.get("location",""),
                        source_url,
                        detected_at
                    ))
                    created += 1

                    # increment counter
                    conn.execute("""
                        UPDATE search_programs
                        SET leads_found_count = leads_found_count + 1
                        WHERE id=?
                    """, (sp["id"],))

                    # Instant email per lead (best-effort)
                    try:
                        subject = f"🔥 New Job Lead: {j.get('role_title','Role')} @ {j.get('company','Company')}"
                        body = "\n".join([
                            "Lead Machine Pro found a match:",
                            "",
                            f"Company: {j.get('company','') or 'Unknown'}",
                            f"Role: {j.get('role_title','')}",
                            f"Location: {j.get('location','')}",
                            f"URL: {source_url}",
                            f"Detected (UTC): {detected_at}",
                            "",
                            "— Lead Machine Pro"
                        ])
                        send_email(MAIL_FROM_DEFAULT, sp["user_email"], subject, body)
                    except Exception:
                        pass

                except sqlite3.IntegrityError:
                    # Duplicate URL for this user; skip
                    continue

            # Update run timestamps
            last_run = now.replace(microsecond=0).isoformat()
            next_run = (now + timedelta(hours=6)).replace(microsecond=0).isoformat()
            conn.execute("""
                UPDATE search_programs
                SET last_run_at=?, next_run_at=?
                WHERE id=?
            """, (last_run, next_run, sp["id"]))

        conn.commit()

    return jsonify({"ok": True, "programs_ran": ran, "leads_created": created, "programs_expired": expired}), 200

# =========================
# Admin (kept) + Topup (optional)
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

@app.route("/program/<int:program_id>/run_now", methods=["POST"])
def run_program_now(program_id: int):
    if not require_login():
        return redirect(url_for("login"))
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not require_verified(user):
        return redirect(url_for("dashboard"))

    now = datetime.utcnow()

    with get_db() as conn:
        sp = conn.execute(
            """
            SELECT sp.*, u.email AS user_email
            FROM search_programs sp
            JOIN users u ON u.id = sp.user_id
            WHERE sp.id=? AND sp.user_id=?
            """,
            (program_id, user["id"])
        ).fetchone()

        if not sp:
            flash("Program not found.", "error")
            return redirect(url_for("dashboard"))

        # Must be running and not expired
        if sp["status"] != "running":
            flash("Start the program first (it activates for 7 days).", "error")
            return redirect(url_for("dashboard"))

        if sp["active_until"]:
            try:
                au = datetime.fromisoformat(sp["active_until"])
                if now > au:
                    conn.execute("UPDATE search_programs SET status='expired' WHERE id=?", (sp["id"],))
                    conn.commit()
                    flash("Program expired. Start it again (uses 1 credit).", "error")
                    return redirect(url_for("dashboard"))
            except Exception:
                pass

        keywords = sp["keywords"]
        loc = (sp["location"] or "").lower()

        # Fetch jobs from Remotive
        try:
            jobs = fetch_jobs_remotive()
        except Exception:
            jobs = []

        created = 0
        for j in jobs:
            hay = f"{j.get('role_title','')} {j.get('company','')} {j.get('location','')}"
            if not bool_match(keywords, hay):
                continue

            if loc and loc != "global":
                if loc not in (j.get("location","").lower()):
                    continue

            source_url = (j.get("source_url") or "").strip()
            if not source_url:
                continue

            detected_at = now_iso()
            try:
                conn.execute("""
                    INSERT INTO job_leads (program_id, user_id, company, role_title, location, source_url, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    sp["id"],
                    sp["user_id"],
                    j.get("company",""),
                    j.get("role_title",""),
                    j.get("location",""),
                    source_url,
                    detected_at
                ))
                created += 1
                conn.execute("""
                    UPDATE search_programs
                    SET leads_found_count = leads_found_count + 1
                    WHERE id=?
                """, (sp["id"],))

                # Instant email (best-effort)
                try:
                    subject = f"🔥 New Job Lead: {j.get('role_title','Role')} @ {j.get('company','Company')}"
                    body = "\n".join([
                        "Lead Machine Pro found a match:",
                        "",
                        f"Company: {j.get('company','') or 'Unknown'}",
                        f"Role: {j.get('role_title','')}",
                        f"Location: {j.get('location','')}",
                        f"URL: {source_url}",
                        f"Detected (UTC): {detected_at}",
                        "",
                        "— Lead Machine Pro"
                    ])
                    send_email(MAIL_FROM_DEFAULT, sp["user_email"], subject, body)
                except Exception:
                    pass

            except sqlite3.IntegrityError:
                continue

        last_run = now.replace(microsecond=0).isoformat()
        conn.execute("""
            UPDATE search_programs
            SET last_run_at=?
            WHERE id=?
        """, (last_run, sp["id"]))
        conn.commit()

    flash(f"✅ Manual run complete. New leads found: {created}", "success")
    return redirect(url_for("dashboard"))

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
            SELECT id, created_at, page_slug, name, email, phone, company, message
            FROM leads
            ORDER BY datetime(created_at) DESC
        """).fetchall()

    leads = [dict(r) for r in rows]
    slugs = sorted(set(list(CLIENTS.keys()) + ["home"]))
    return render_template("admin_dashboard.html", leads=leads, slugs=slugs, active_slug="")

@app.route("/admin/topup", methods=["GET", "POST"])
def admin_topup():
    if not is_admin():
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        amount_raw = (request.form.get("amount") or "").strip()

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
            conn.execute("""
                INSERT INTO credit_events (user_id, event_type, delta, note, created_at)
                VALUES (?, 'topup', ?, ?, ?)
            """, (user["id"], amount, "Admin credit adjustment", now_iso()))
            conn.commit()

        flash(f"✅ Updated {email} credits to {new_credits}.", "success")
        return redirect(url_for("admin_topup"))

    return render_template("admin_topup.html")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
else:
    init_db()
