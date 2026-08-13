"""
Demo Vulnerable Web Application
================================
This is a deliberately vulnerable Flask application used for demonstrating
the SRC Vulnerability Mining Agent.

Vulnerabilities included (for demo/testing only):
1. SQL Injection — /login (login form with concatenated SQL query)
2. Reflected XSS — /search (search results reflect query without encoding)
3. IDOR — /user/<id> (no ownership check)
4. SSRF — /fetch (URL fetch without validation)
5. Path Traversal — /view (file parameter without sanitization)
6. Command Injection — /ping (ping endpoint with shell command)

ALL DATA IS FICTIONAL AND DESENSITIZED.
DO NOT DEPLOY THIS APPLICATION PUBLICLY.
"""

import sqlite3
import subprocess
import os
from flask import Flask, request, render_template_string, jsonify, send_file

app = Flask(__name__)

# ============================================================
# Setup — In-memory SQLite database with fake data
# ============================================================
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        role TEXT,
        ssn TEXT
    )
""")
DB.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        description TEXT
    )
""")

# Insert demo data (ALL FAKE)
fake_users = [
    (1, "alice_demo", "pass123_demo", "alice@demo.local", "user", "111-11-1111"),
    (2, "bob_demo", "pass456_demo", "bob@demo.local", "admin", "222-22-2222"),
    (3, "charlie_demo", "pass789_demo", "charlie@demo.local", "user", "333-33-3333"),
]
fake_products = [
    (1, "Demo Product A", 29.99, "A sample product for demonstration"),
    (2, "Demo Product B", 59.99, "Another sample product"),
    (3, "Demo Product C", 99.99, "Premium demo product"),
]
DB.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", fake_users)
DB.executemany("INSERT INTO products VALUES (?,?,?,?)", fake_products)
DB.commit()

# ============================================================
# Base HTML Template
# ============================================================
BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Demo Corp — Internal Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 15px; color: #0066cc; text-decoration: none; }
        .result { margin-top: 15px; padding: 10px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 4px; }
        .error { color: red; }
        input, button { padding: 8px 12px; margin: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Demo Corp — Internal Portal</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/search">Search</a>
            <a href="/products">Products</a>
            <a href="/fetch">Fetch URL</a>
            <a href="/ping">Ping</a>
            <a href="/view">View File</a>
        </nav>
        <hr>
        {content}
    </div>
</body>
</html>
"""


# ============================================================
# Routes
# ============================================================

@app.route("/")
def home():
    """Home page."""
    content = """
        <h2>Welcome to Demo Corp Internal Portal</h2>
        <p>This is a demo application for security testing.</p>
        <p><strong>All data is fictional and desensitized.</strong></p>
    """
    return BASE_HTML.replace("{content}", content)


# --- Vulnerability 1: SQL Injection ---
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login page with SQL injection vulnerability.
    The username is directly concatenated into the SQL query.
    """
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILITY: String concatenation in SQL query
        # This allows: username = ' OR '1'='1' --
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        message = f"<!-- DEBUG: {query} -->"

        try:
            cursor = DB.execute(query)
            user = cursor.fetchone()
            if user:
                message += f"<p>Login successful! Welcome, {user[1]} (Role: {user[4]})</p>"
            else:
                message += "<p>Invalid username or password.</p>"
        except Exception as e:
            # VULNERABILITY: SQL error exposed to user
            message += f"<p class='error'>Database error: {str(e)}</p>"

    content = f"""
        <h2>Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Login</button>
        </form>
        <div class="result">{message}</div>
    """
    return BASE_HTML.replace("{content}", content)


# --- Vulnerability 2: Reflected XSS ---
@app.route("/search")
def search():
    """
    Search page with reflected XSS vulnerability.
    The search query is reflected without HTML encoding.
    """
    query = request.args.get("q", "")

    # VULNERABILITY: Unsanitized reflection of user input
    content = f"""
        <h2>Search Products</h2>
        <form method="GET">
            <input type="text" name="q" placeholder="Search..." value="{query}" />
            <button type="submit">Search</button>
        </form>
        <div class="result">
            <h3>Search Results for: {query}</h3>
            <p>No products found matching your query.</p>
        </div>
    """
    return BASE_HTML.replace("{content}", content)


# --- Vulnerability 3: IDOR ---
@app.route("/user/<int:user_id>")
def user_profile(user_id: int):
    """
    User profile page with IDOR vulnerability.
    No ownership check — any user can view any other user's profile.
    """
    cursor = DB.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        content = "<h2>User Not Found</h2>"
    else:
        # VULNERABILITY: No authorization check
        content = f"""
            <h2>User Profile</h2>
            <table>
                <tr><td><strong>ID:</strong></td><td>{user[0]}</td></tr>
                <tr><td><strong>Username:</strong></td><td>{user[1]}</td></tr>
                <tr><td><strong>Email:</strong></td><td>{user[2]}</td></tr>
                <tr><td><strong>Role:</strong></td><td>{user[4]}</td></tr>
            </table>
            <p><a href="/user/{user_id + 1}">Next User →</a></p>
        """
    return BASE_HTML.replace("{content}", content)


# --- Vulnerability 4: SSRF ---
@app.route("/fetch")
def fetch_url():
    """
    URL fetcher with SSRF vulnerability.
    Fetches any URL provided by the user.
    """
    url = request.args.get("url", "")
    result = ""

    if url:
        # VULNERABILITY: Unvalidated URL fetch → SSRF
        try:
            import urllib.request
            response = urllib.request.urlopen(url, timeout=5)
            data = response.read().decode("utf-8", errors="ignore")
            result = f"<pre>{data[:1000]}</pre>"
        except Exception as e:
            result = f"<p class='error'>Error fetching URL: {str(e)}</p>"

    content = f"""
        <h2>Fetch URL</h2>
        <form method="GET">
            <input type="text" name="url" placeholder="Enter URL to fetch..." size="40" value="{url}" />
            <button type="submit">Fetch</button>
        </form>
        <div class="result">{result}</div>
    """
    return BASE_HTML.replace("{content}", content)


# --- Vulnerability 5: Path Traversal ---
@app.route("/view")
def view_file():
    """
    File viewer with path traversal vulnerability.
    """
    filename = request.args.get("file", "")

    if not filename:
        content = """
            <h2>View File</h2>
            <form method="GET">
                <input type="text" name="file" placeholder="Enter filename..." size="40" />
                <button type="submit">View</button>
            </form>
            <p>Available files: welcome.txt, about.txt</p>
        """
        return BASE_HTML.replace("{content}", content)

    # Create a demo directory with safe files
    demo_dir = os.path.join(os.path.dirname(__file__), "demo_files")
    os.makedirs(demo_dir, exist_ok=True)

    # Ensure demo files exist
    if not os.path.exists(os.path.join(demo_dir, "welcome.txt")):
        with open(os.path.join(demo_dir, "welcome.txt"), "w") as f:
            f.write("Welcome to Demo Corp! This is a sample file.")
    if not os.path.exists(os.path.join(demo_dir, "about.txt")):
        with open(os.path.join(demo_dir, "about.txt"), "w") as f:
            f.write("Demo Corp is a fictional company for security testing.")

    # VULNERABILITY: Path traversal — no path sanitization
    file_path = os.path.join(demo_dir, filename)

    try:
        with open(file_path, "r") as f:
            file_content = f.read()
        content = f"""
            <h2>View File: {filename}</h2>
            <pre>{file_content}</pre>
            <p><a href="/view">Back</a></p>
        """
    except Exception as e:
        # VULNERABILITY: Error message exposes file path
        content = f"""
            <h2>View File</h2>
            <p class='error'>Error reading file: {str(e)}</p>
            <p>Path attempted: {file_path}</p>
            <p><a href="/view">Back</a></p>
        """

    return BASE_HTML.replace("{content}", content)


# --- Vulnerability 6: Command Injection ---
@app.route("/ping")
def ping():
    """
    Ping utility with command injection vulnerability.
    """
    host = request.args.get("host", "")

    if not host:
        content = """
            <h2>Ping Utility</h2>
            <form method="GET">
                <input type="text" name="host" placeholder="Enter host to ping..." size="30" />
                <button type="submit">Ping</button>
            </form>
            <p>Example: 127.0.0.1</p>
        """
        return BASE_HTML.replace("{content}", content)

    # VULNERABILITY: Command injection via unsanitized input
    # The host parameter is directly passed to ping command
    cmd = f"ping -n 1 {host}" if os.name == "nt" else f"ping -c 1 {host}"

    try:
        output = subprocess.check_output(cmd, shell=True, timeout=5, stderr=subprocess.STDOUT)
        result = output.decode("utf-8", errors="ignore")
    except subprocess.TimeoutExpired:
        result = "Ping timed out."
    except Exception as e:
        result = f"Error: {str(e)}"

    content = f"""
        <h2>Ping Utility</h2>
        <form method="GET">
            <input type="text" name="host" placeholder="Enter host to ping..." size="30" value="{host}" />
            <button type="submit">Ping</button>
        </form>
        <div class="result">
            <h3>Result:</h3>
            <pre>{result}</pre>
        </div>
    """
    return BASE_HTML.replace("{content}", content)


# --- Products listing (safe, for reference) ---
@app.route("/products")
def products():
    """Products listing page (no vulnerability)."""
    cursor = DB.execute("SELECT * FROM products")
    rows = cursor.fetchall()

    product_html = ""
    for row in rows:
        product_html += f"<li><strong>{row[1]}</strong> — ${row[2]:.2f}<br/>{row[3]}</li>"

    content = f"""
        <h2>Products</h2>
        <ul>{product_html}</ul>
    """
    return BASE_HTML.replace("{content}", content)


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  Demo Vulnerable Web Application")
    print("  FOR SECURITY TESTING / CTF DEMONSTRATION ONLY")
    print("  All data is fictional and desensitized.")
    print("=" * 60)
    print()
    print("Vulnerabilities included:")
    print("  1. SQL Injection  — POST /login (username param)")
    print("  2. Reflected XSS  — GET  /search?q=<payload>")
    print("  3. IDOR           — GET  /user/<id>")
    print("  4. SSRF           — GET  /fetch?url=<url>")
    print("  5. Path Traversal — GET  /view?file=<path>")
    print("  6. Command Inject — GET  /ping?host=<cmd>")
    print()
    print("Starting on http://127.0.0.1:5000")
    print("=" * 60)
    # threaded=True: 每个请求独立线程，单个请求hang不影响其他请求
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
