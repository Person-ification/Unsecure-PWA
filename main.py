from flask import Flask, render_template, request, redirect, url_for, session, abort
import user_management as dbHandler
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

dbHandler.init_db()

# --- SECURITY HELPERS ---

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('_csrf_token')
        if not token or token != request.form.get('csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    return response

# --- ROUTES ---

@app.before_request
def handle_redirects():
    if request.method == "GET" and request.args.get("url"):
        target = request.args.get("url")
        if target.startswith('/') and not target.startswith('//'):
            return redirect(target)

@app.route("/", methods=["GET", "POST"])
@app.route("/index.html", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Step 1: Verify Username and Password
        if dbHandler.retrieveUsers(username, password):
            # Generate OTP and "send" email
            dbHandler.set_otp(username)
            
            # Store username temporarily - NOT fully logged in yet
            session['pre_2fa_user'] = username
            
            return redirect(url_for('verify_otp'))
        else:
            return render_template("index.html", msg="Invalid Credentials")
            
    msg = request.args.get("msg", "")
    return render_template("index.html", msg=msg)

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    # Ensure user has passed the password stage
    if 'pre_2fa_user' not in session:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = session['pre_2fa_user']
        code = request.form["otp_code"]
        
        # Step 2: Verify OTP
        if dbHandler.verify_otp(username, code):
            # Success - promote to full login
            session['user'] = username
            session.pop('pre_2fa_user', None) # Remove temp session
            return redirect(url_for('success'))
        else:
            return render_template("verify_otp.html", msg="Invalid or Expired Code")

    return render_template("verify_otp.html")

@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        email = request.form["email"] # Get email from form
        
        dbHandler.insertUser(username, password, dob, email)
        return redirect(url_for('index', msg="Registration Successful"))
        
    return render_template("signup.html")

@app.route("/success.html", methods=["GET", "POST"])
def success():
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
    app.run(debug=False, host="localhost", port=5000)
