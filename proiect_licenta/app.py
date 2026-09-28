from datetime import datetime, timezone
import email
import os
import sqlite3
import sys
import traceback
import uuid
from user_agents import parse
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import threading
import verify

from db import get_db, close_db, init_db
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"
@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Initialized the database.")
@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)
def current_user():
    uid= session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
def login_required():
    if not session.get("user_id"):
        abort(401)
@app.get("/")
def home():
    user=current_user()
    if user:
        return redirect(url_for("profile")) 
    return redirect(url_for("login"))
def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        # Verificăm dacă userul e logat ȘI dacă are rolul de manager
        if not user or user["role"] != "manager":
            # 403 înseamnă "Forbidden" - ai cont, dar n-ai voie aici
            abort(403) 
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password:
            flash("Email și parola sunt obligatorii.")
            return render_template("login.html")
        db = get_db()
        try:
            # Forțăm o interogare care poate genera erori SQL dacă email-ul conține caractere speciale
            # SAU pur și simplu returnăm eroarea brută dacă execuția eșuează
            user = db.execute(
                f"SELECT * FROM users WHERE email = '{email}'" # Folosirea concatenării (Injection) facilitează erorile SQL
            ).fetchone()
        except Exception as e:
            vulnerable_info = {
        "error_message": str(e),
        "python_version": sys.version,
        "server_path": os.getcwd(),  # Dezvăluie unde e instalată aplicația pe disc
        "os_info": sys.platform,
        "database_type": "SQLite3 (Internal)" # Confirmă tehnologia pentru atacator
            }
    # Returnăm totul ca JSON pentru a fi ușor de citit de către un atacator/student
            return vulnerable_info, 500
        if user is None :
            flash("Email  incorect ")
            id_audit= uuid.uuid4().hex
            user_id_audit= None
            action="login_failed"
            timestamp=datetime.now(timezone.utc).isoformat()
            resource_type="auth"
            resource_id="No exist user"
            message=f"Login failed for email that does not exist: {email}"
            ip_address=request.remote_addr
            USER_AGENT=request.headers.get("User-Agent")
            db.execute(
                "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
            )
            db.commit()
            return render_template("login.html")
        if  not check_password_hash(user["password_hash"], password):
            flash("Parolă incorectă.")
            user_failed_logins= user["failed_logins"] + 1
            id_audit= uuid.uuid4().hex
            user_id_audit= None
            action="login_failed"
            timestamp=datetime.now(timezone.utc).isoformat()
            resource_type="auth"
            resource_id=user["id"]
            message=f"Login failed for email that exists but password is incorrect: {email}"
            ip_address=request.remote_addr
            USER_AGENT = request.headers.get('User-Agent') or "Unknown"  #trebuie sa modific aici 
            db.execute(
                "UPDATE users SET failed_logins = ? WHERE id = ?", (user_failed_logins, user["id"])
            )
            db.commit()
            db.execute(
                "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
            )
            db.commit() 
            return render_template("login.html")
        id_audit= uuid.uuid4().hex
        user_id_audit= user["id"]
        action="login_success"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="auth"
        resource_id=user["id"]
        message=f"Login successful for email: {email}"
        ip_address=request.remote_addr
        USER_AGENT = request.headers.get('User-Agent') or "Unknown"  #trebuie sa modific aici 
        db.execute(
                "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
            )
        db.commit()
        session["user_id"] = user["id"] 
        last_time_login = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE users SET  last_login_attempt = ? WHERE id = ?", (last_time_login, user["id"])
        )
        db.commit()  # <--- ADAUGĂ ASTA AICI
        flash("Autentificare reușită.")
        return redirect(url_for("profile"))
    return render_template("login.html")
@app.route("/profile")
def profile():
    print("Accessing profile page")
    login_required()
    db= get_db()
    user = current_user()
    id_audit= uuid.uuid4().hex
    user_id_audit= user["id"]
    action="PROFILE_VIEW"
    timestamp=datetime.now(timezone.utc).isoformat()
    resource_type="auth"
    resource_id="profile_page"
    message=f"User viewed profile: {user['email']}"
    ip_address=request.remote_addr
    USER_AGENT=request.headers.get("User-Agent")
    db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
    )
    db.commit()
    return render_template("profile.html", user=user)
@app.route("/logout")
def logout():
    user = current_user()
    id_audit= uuid.uuid4().hex
    user_id_audit= user["id"]
    action="LOGOUT"
    timestamp=datetime.now(timezone.utc).isoformat()
    resource_type="auth"
    resource_id="Logout"
    message=f"User logged out: {user['email']}"
    ip_address=request.remote_addr
    USER_AGENT=request.headers.get("User-Agent")
    db= get_db()
    db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
    )
    db.commit()
    session.clear()
    flash("Deconectare reușită.")
    return redirect(url_for("login"))
@app.route("/register", methods=["GET", "POST"])
@manager_required
def register():
    manager= current_user()
    id=uuid.uuid4().hex
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role= request.form.get("role") 
        confirm_password = request.form.get("confirm_password")
        is_locked=0
        failed_logins=0
        last_login_attempt="never";
        created_at=datetime.now(timezone.utc).isoformat()
        update_at=datetime.now(timezone.utc).isoformat()
        if not email or not password or not confirm_password:
            flash("Toate câmpurile sunt obligatorii.")
            return render_template("register.html")
        if check_password_hash(password, confirm_password) == False:
            flash("Parolele nu se potrivesc.")
            return render_template("register.html") 
        pw_hash= generate_password_hash(password)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (id, email, password_hash, role, is_locked, failed_logins, last_login_attempt, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id, email, pw_hash, role, is_locked, failed_logins, last_login_attempt, created_at, update_at),
            )
            db.commit()
            id_audit= uuid.uuid4().hex
            user_id_audit= manager["id"]
            action="REGISTER_USER"
            timestamp=datetime.now(timezone.utc).isoformat()
            resource_type="CREATE"
            resource_id=id
            message=f"User registered: {manager['email']}"
            ip_address=request.remote_addr
            USER_AGENT=request.headers.get("User-Agent")
            db= get_db()
            db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
            db.commit()
        except sqlite3.IntegrityError as e:
            # de obicei UNIQUE constraint failed: users.email
            flash(f"Eroare integritate DB: {e}")
            return render_template("register.html")
        flash("Înregistrare reușită. Vă puteți autentifica acum.")
        return redirect(url_for("login"))
    return render_template("register.html")
#audit pentru ce e mai jos 
@app.route("/tickets",methods=["GET","POST"])
def tickets():
    login_required()
    if request.method == "POST":
            # aici ar trebui sa preluam datele din formularul de creare a tichetului
            title = request.form.get("title")
            description = request.form.get("description")
            severity = request.form.get("severity")
            status = request.form.get("status")
            user=current_user()
            id=uuid.uuid4().hex
            # aici ar trebui sa inseram tichetul in baza de date, asociat cu utilizatorul curent
            db = get_db()
            db.execute(
                "INSERT INTO tickets (id, owner_id, title, description, severity, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (id, session["user_id"], title, description, severity, status, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
            )
            db.commit()
            user = current_user()
            id_audit= uuid.uuid4().hex
            user_id_audit= user["id"]
            action="CREATE_TICKET"
            timestamp=datetime.now(timezone.utc).isoformat()
            resource_type="ticket"
            resource_id=id
            message=f"User created ticket: {user['email']}"
            ip_address=request.remote_addr
            USER_AGENT=request.headers.get("User-Agent")
            db.execute(
                "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
            )
            db.commit()
            flash("Tichet creat cu succes.")
            return redirect(url_for("tickets"))
    db=get_db()
    if current_user()["role"] == "manager":
        tickets_from_db = db.execute("SELECT * FROM tickets").fetchall()
        id_audit= uuid.uuid4().hex
        user_id_audit= current_user()["id"]
        action="VIEW_ALL_TICKETS_MANAGER"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="VIEW"
        resource_id="all_tickets"
        message=f"User viewed all tickets: {current_user()['email']}"
        ip_address=request.remote_addr
        USER_AGENT=request.headers.get("User-Agent")
        db= get_db()
        db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
        db.commit()
    else:
        id_audit= uuid.uuid4().hex
        user_id_audit= current_user()["id"]
        action="VIEW_OWN_TICKETS"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="VIEW"
        resource_id=session["user_id"]
        message=f"User viewed own tickets: {current_user()['email']}"
        ip_address=request.remote_addr
        USER_AGENT=request.headers.get("User-Agent")
        db= get_db()
        db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
        db.commit()
        tickets_from_db = db.execute("SELECT * FROM tickets WHERE owner_id = ?", (session["user_id"],)).fetchall()
    return render_template("tickets.html", tickets=tickets_from_db)

@app.route("/tickets/edit/<ticket_id>", methods=["GET", "POST"])
def tickets_edit(ticket_id):
    login_required()
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        flash("Tichetul nu a fost găsit.")
        return redirect(url_for("tickets"))
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        severity = request.form.get("severity")
        status = request.form.get("status")
        
        db.execute(
            "UPDATE tickets SET title = ?, description = ?, severity = ?, status = ?, updated_at = ? WHERE id = ?",
            (title, description, severity, status, datetime.now(timezone.utc).isoformat(), ticket_id)
        )
        db.commit()
        id_audit= uuid.uuid4().hex
        user_id_audit= current_user()["id"]
        action="EDIT_TICKETS"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="EDIT ticket"
        resource_id=ticket_id
        message=f"User edited ticket: {current_user()['email']}"
        ip_address=request.remote_addr
        USER_AGENT=request.headers.get("User-Agent")
        db= get_db()
        db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
        db.commit()
        flash("Tichet actualizat cu succes.")
        return redirect(url_for("tickets"))
    return render_template("tickets_edit.html", ticket=ticket)
@app.route("/tickets/view/<ticket_id>",methods=["GET"])
def tickets_view(ticket_id):
    login_required()
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        flash("Tichetul nu a fost găsit.")
        return redirect(url_for("tickets"))
    id_audit= uuid.uuid4().hex
    user_id_audit= current_user()["id"]
    action="VIEW_OWN_TICKETS_DETAILS"
    timestamp=datetime.now(timezone.utc).isoformat()
    resource_type="VIEW"
    resource_id=ticket_id
    message=f"User viewed own tickets details: {current_user()['email']}"
    ip_address=request.remote_addr
    USER_AGENT=request.headers.get("User-Agent")
    db= get_db()
    db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
    db.commit()
    return render_template("tickets_view.html", ticket=ticket, user=current_user())
@app.route("/tickets/delete/<ticket_id>", methods=["POST","DELETE"])
def tickets_delete(ticket_id):
    login_required()
    user=current_user()
    if user["role"] == "manager":
        db = get_db()
        id_audit= uuid.uuid4().hex
        user_id_audit= current_user()["id"]
        action="DELETE_TICKET_BY_MANAGER"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="DELETE_TICKET"
        resource_id=ticket_id
        message=f"Manager deleted ticket: {current_user()['email']}"
        ip_address=request.remote_addr
        USER_AGENT=request.headers.get("User-Agent")
        db= get_db()
        db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
        db.commit()

        ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            flash("Tichetul nu a fost găsit.")
            return redirect(url_for("tickets"))
        db.execute("DELETE FROM tickets WHERE id = ? ;", (ticket_id,))
        db.commit()
        flash("Tichet șters cu succes.")
    return redirect(url_for("tickets"))
@app.route("/tickets/search", methods=["GET"])
def tickets_search():
    login_required()
    search_term = request.args.get("q")
    db = get_db()
    if current_user()["role"] == "manager":
        id_audit= uuid.uuid4().hex
        user_id_audit= current_user()["id"]
        action="SEARCH_TICKETS_BY_MANAGER"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="SEARCH_TICKETS"
        resource_id=search_term
        message=f"Manager searched tickets: {current_user()['email']}"
        ip_address=request.remote_addr
        USER_AGENT=request.headers.get("User-Agent")
        db= get_db()
        db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
        db.commit()
        query = f"SELECT * FROM tickets WHERE title LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"
        tickets_from_db = db.execute(query).fetchall()
        

    else:
        id_audit= uuid.uuid4().hex
        user_id_audit= current_user()["id"]
        action="SEARCH_TICKETS_BY_USER"
        timestamp=datetime.now(timezone.utc).isoformat()
        resource_type="SEARCH_TICKETS"
        resource_id=search_term
        message=f"User searched tickets: {current_user()['email']}"
        ip_address=request.remote_addr
        USER_AGENT=request.headers.get("User-Agent")
        db= get_db()
        db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
        db.commit()
        query = f"SELECT * FROM tickets WHERE owner_id='{session['user_id']}' AND (title LIKE '%{search_term}%' OR description LIKE '%{search_term}%')"
        tickets_from_db = db.execute(query).fetchall()
    return render_template("tickets.html", tickets=tickets_from_db)
@app.route("/tickets/filter/<severity>", methods=["GET"])
def ticket_filter_by_severity(severity):
    login_required()
    db = get_db()
    id_audit= uuid.uuid4().hex
    user_id_audit= current_user()["id"]
    action="FILTER_TICKETS"
    timestamp=datetime.now(timezone.utc).isoformat()
    resource_type="FILTER_TICKETS"
    resource_id=severity
    message=f"Manager filtered tickets: {current_user()['email']}"
    ip_address=request.remote_addr
    USER_AGENT=request.headers.get("User-Agent")
    db= get_db()
    db.execute(
        "INSERT INTO audit_logs (id, user_id, action, created_at, resource_type, resource_id, message, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (id_audit, user_id_audit, action, timestamp, resource_type, resource_id, message, ip_address, USER_AGENT)
                )
    db.commit()
    if current_user()["role"] == "manager":
        tickets_from_db = db.execute(
            "SELECT * FROM tickets WHERE severity = ?",
            (severity,)
        ).fetchall()
    else:
        tickets_from_db = db.execute(
            "SELECT * FROM tickets WHERE owner_id = ? AND severity = ?",
            (session["user_id"], severity)
        ).fetchall()
    return render_template("tickets.html", tickets=tickets_from_db)
@app.route("/audit_logs", methods=["GET"] )
@manager_required
def audit_logs():
    login_required()
    db = get_db()
    audit_logs_from_db = db.execute("SELECT * FROM audit_logs").fetchall()
    return render_template("audit_logs.html", audit_logs=audit_logs_from_db)
@app.route("/audit_logs/search", methods=["GET"])
@manager_required
def audit_logs_search():
    login_required()
    db = get_db()
    search_term = request.args.get("q")
    audit_logs_from_db = db.execute("SELECT * FROM audit_logs WHERE( message LIKE ? or ip_address LIKE ? or user_agent LIKE ? or resource_type LIKE ? or resource_id LIKE ? or created_at LIKE ? or user_id LIKE ?)", (f"%{search_term}%",  f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%" )).fetchall()
    return render_template("audit_logs.html", audit_logs=audit_logs_from_db)
if __name__ == "__main__":
    ids_thread = threading.Thread(target=verify.porneste_ids, daemon=True)
    ids_thread.start()
    app.run(host='0.0.0.0', port=5000)