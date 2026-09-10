from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import re, os, logging, time

app = Flask(__name__)
app.secret_key = os.urandom(32)

logging.basicConfig(filename="security.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("appsec")

users = {
    # admin / Admin#1234  (demo credentials, hashed at runtime below)
    "admin":  {"hash": generate_password_hash("Admin@123"), "role": "admin"},
    "Charan":  {"hash": generate_password_hash("I@am#here"),  "role": "user"},
}
notes = {}  # username -> list of notes (demonstrates authorization boundaries)

# ---------------- Input validation helpers ----------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")

def validate_username(u):
    return bool(USERNAME_RE.fullmatch(u or ""))

def validate_note(text):
    """Reject notes with suspicious content (basic XSS/SQLi demo filter)."""
    if not text or len(text) > 500:
        return "Note must be 1-500 characters."
    if re.search(r"(?i)<\s*script|javascript:|union\s+select|';--", text):
        log.warning("Potentially malicious input blocked from %s", request.remote_addr)
        return "Potentially malicious content detected in input."
    return None

def current_user():
    return session.get("user")

def require_role(role):
    def decorator(fn):
        def wrapper(*a, **kw):
            if not current_user():
                return redirect(url_for("home"))
            if users[current_user()]["role"] != role:
                log.warning("Forbidden access attempt by %s to %s",
                            current_user(), request.path)
                return render_template_string(PAGE, user=current_user(),
                                              role=users[current_user()]["role"],
                                              err="Access denied: insufficient privileges.",
                                              notes=notes.get(current_user(), [])), 403
            return fn(*a, **kw)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

PAGE = """
<!doctype html><html><head><title>AppSec Demo</title>
<style>body{font-family:Arial;max-width:560px;margin:40px auto;}
input,textarea{display:block;width:100%;padding:8px;margin:6px 0;}
button{padding:8px 18px;} .msg{color:green}.err{color:red}
.box{border:1px solid #ccc;padding:10px;margin:8px 0;border-radius:6px}</style></head><body>
<h2>Application Security Demo</h2>
{% if err %}<p class="err">{{ err }}</p>{% endif %}
{% if msg %}<p class="msg">{{ msg }}</p>{% endif %}
{% if not user %}
  <h3>Login</h3>
  <form method="post" action="/login">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button>Login</button>
  </form>
  <p><small>Demo accounts: admin / Admin#1234 , alice / User#1234</small></p>
{% else %}
  <p>Logged in as <b>{{ user }}</b> (role: {{ role }})
     — <a href="{{ url_for('logout') }}">Logout</a></p>

  <div class="box"><h3>My Notes</h3>
    {% for n in notes %}<div class="box">{{ n }}</div>{% else %}<p>No notes yet.</p>{% endfor %}
    <form method="post" action="/notes">
      <textarea name="note" placeholder="Write a note (XSS/SQLi patterns are blocked)" required></textarea>
      <button>Add Note</button>
    </form>
  </div>

  {% if role == 'admin' %}
  <div class="box"><h3>Admin Panel</h3>
    <p>All registered users: {{ all_users }}</p>
  </div>
  {% endif %}
{% endif %}
</body></html>
"""

@app.route("/")
def home():
    u = current_user()
    return render_template_string(PAGE, user=u,
                                  role=users[u]["role"] if u else None,
                                  notes=notes.get(u, []) if u else [],
                                  all_users=list(users.keys()) if u and users[u]["role"]=="admin" else [],
                                  err=None, msg=None)

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    # Generic error message avoids user-enumeration
    if u in users and check_password_hash(users[u]["hash"], p):
        session.clear()
        session["user"] = u
        log.info("Successful login: %s from %s", u, request.remote_addr)
        return redirect(url_for("home"))
    log.warning("Failed login for %s from %s", u, request.remote_addr)
    return render_template_string(PAGE, user=None, role=None, notes=[],
                                  all_users=[], err="Invalid username or password.", msg=None), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/notes", methods=["POST"])
def add_note():
    u = current_user()
    if not u:
        return redirect(url_for("home"))
    text = request.form.get("note", "")
    err = validate_note(text)
    if err:
        return render_template_string(PAGE, user=u, role=users[u]["role"],
                                      notes=notes.get(u, []), all_users=[],
                                      err=err, msg=None), 400
    notes.setdefault(u, []).append(text)
    log.info("Note added by %s", u)
    return redirect(url_for("home"))

@app.route("/admin")
@require_role("admin")
def admin_panel():
    log.info("Admin panel accessed by %s", current_user())
    return jsonify({"status": "ok", "users": list(users.keys())})

# ---------- Security headers + generic error handling ----------
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.errorhandler(404)
def not_found(e):
    return render_template_string(PAGE, user=current_user(), role=None, notes=[],
                                  all_users=[], err="Page not found.", msg=None), 404

@app.errorhandler(500)
def server_error(e):
    log.error("Internal error: %s", e)
    return "Internal server error.", 500

if __name__ == "__main__":
    app.run(debug=False, port=5002)
