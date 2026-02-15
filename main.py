from flask import Flask, render_template, request, redirect, url_for, session, abort
import user_management as dbHandler
import secrets

app = Flask(__name__)
# SECURE: Secret key required for sessions and CSRF
app.secret_key = secrets.token_hex(16)

# Initialize DB
dbHandler.init_db()

# --- SECURITY HELPERS ---

@app.before_request
def csrf_protect():
    """Verify CSRF token on all POST requests"""
    if request.method == "POST":
        token = session.get('_csrf_token')
        if not token or token != request.form.get('csrf_token'):
            abort(403) # Forbidden if token is missing or invalid

def generate_csrf_token():
    """Generate a token and store in session"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

# Make csrf_token available in all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.after_request
def add_security_headers(response):
    """Add Secure HTTP Headers"""
    # Prevent Clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME Sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Content Security Policy (Basic)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    return response

# --- ROUTES ---

@app.before_request
def handle_redirects():
    """Securely handle the ?url= navigation pattern"""
    if request.method == "GET" and request.args.get("url"):
        target = request.args.get("url")
        # SECURE: Only allow relative URLs (starts with / but not //)
        if target.startswith('/') and not target.startswith('//'):
            return redirect(target)
        # If URL is external (e.g., google.com), ignore it to prevent Phishing/Open Redirects

@app.route("/", methods=["GET", "POST"])
@app.route("/index.html", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        if dbHandler.retrieveUsers(username, password):
            session['user'] = username # Log user in via session
            return redirect(url_for('success'))
        else:
            return render_template("index.html", msg="Invalid Credentials")
            
    msg = request.args.get("msg", "")
    return render_template("index.html", msg=msg)

@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        
        dbHandler.insertUser(username, password, dob)
        return redirect(url_for('index', msg="Registration Successful"))
        
    return render_template("signup.html")

@app.route("/success.html", methods=["GET", "POST"])
def success():
    # SECURE: Access Control - Require login
    if 'user' not in session:
        return redirect(url_for('index', msg="Please login first"))

    if request.method == "POST":
        feedback_text = request.form["feedback"]
        dbHandler.insertFeedback(feedback_text)
    
    all_feedback = dbHandler.listFeedback()
    return render_template("success.html", value=session['user'], state=True, feedback=all_feedback)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    # SECURE: Debug disabled for production-like environment
    app.run(debug=False, host="localhost", port=5000)
