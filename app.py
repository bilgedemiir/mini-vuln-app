import os
import secrets
import bcrypt
from flask import Flask, render_template, request, redirect, session, abort

from db import get_db, close_db

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_csrf():
    token = session.get("csrf_token")
    form_token = request.form.get("csrf_token")
    if not token or not form_token or token != form_token:
        abort(400, description="CSRF validation failed")


@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token()}

def is_logged_in():
    return "user_id" in session


def is_admin():
    return session.get("role") == "admin"


@app.route("/")
def home():
    return redirect("/comments" if is_logged_in() else "/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        require_csrf()

        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            return "Invalid input", 400

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, "user"),
            )
            db.commit()
        except Exception as e:
            return f"Register error: {e}", 400

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        require_csrf()

        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user:
            stored = user["password_hash"]
            if isinstance(stored, str):
                stored = stored.encode("utf-8")

            if bcrypt.checkpw(password.encode("utf-8"), stored):
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["username"] = user["username"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect("/comments")

        return "Login failed", 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if not is_logged_in():
        return redirect("/login")

    db = get_db()

    if request.method == "POST":
        require_csrf()
        content = request.form["content"]

        if not content or len(content) > 500:
            return "Invalid comment", 400

        db.execute(
            "INSERT INTO comments (user_id, content) VALUES (?, ?)",
            (session["user_id"], content),
        )
        db.commit()

    rows = db.execute(
        """
        SELECT comments.id, comments.content, comments.created_at, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.id DESC
        """
    ).fetchall()

    return render_template("comments.html", comments=rows)


@app.route("/search", methods=["GET", "POST"])
def search():
    if not is_logged_in():
        return redirect("/login")

    results = []
    q = ""

    if request.method == "POST":
        require_csrf()
        q = request.form["q"].strip()

        db = get_db()
        results = db.execute(
            """
            SELECT comments.id, comments.content, comments.created_at, users.username
            FROM comments
            JOIN users ON users.id = comments.user_id
            WHERE users.username = ?
            ORDER BY comments.id DESC
            """,
            (q,),
        ).fetchall()

    return render_template("search.html", results=results, q=q)


@app.route("/admin")
def admin():
    if not is_logged_in():
        return redirect("/login")
    if not is_admin():
        return "Forbidden", 403

    db = get_db()
    rows = db.execute(
        """
        SELECT comments.id, comments.content, comments.created_at, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.id DESC
        """
    ).fetchall()

    return render_template("admin.html", comments=rows)


@app.route("/admin/delete/<int:comment_id>", methods=["POST"])
def admin_delete_comment(comment_id):
    if not is_logged_in():
        return redirect("/login")
    if not is_admin():
        return "Forbidden", 403

    require_csrf()

    db = get_db()
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    return redirect("/admin")


if __name__ == "__main__":
    app.run(debug=True)