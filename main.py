from flask import Flask, render_template, request, redirect, url_for, session, abort
import user_management as dbHandler
import secrets
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

dbHandler.init_db()

@app.before_request
def ensure_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('_csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            print("Session CSRF:", token)
            print("Form CSRF:", form_token)
            abort(403)


def generate_csrf_token():
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "object-src 'none'; "
        "img-src 'self' data:;"
    )
    return response


@app.route("/", methods=["GET", "POST"])
@app.route("/index.html", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
  
        if dbHandler.retrieveUsers(username, password):

            session['pre_2fa_user'] = username
            return redirect(url_for('verify_2fa'))
        else:
            return render_template("index.html", msg="Invalid Credentials")
            
    msg = request.args.get("msg", "")
    return render_template("index.html", msg=msg)

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():

    if 'pre_2fa_user' not in session:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = session['pre_2fa_user']
        code = request.form["otp_code"]
        
   
        if dbHandler.verify_totp(username, code):
            session['user'] = username
            session.pop('pre_2fa_user', None)
            return redirect(url_for('success'))
        else:
            return render_template("verify_2fa.html", msg="Invalid Code")

    return render_template("verify_2fa.html")

@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]

        success, secret = dbHandler.register_user(username, password, dob, email=None)

        if success:
 
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecurePWA")

       
            img = qrcode.make(totp_uri)
            buf = io.BytesIO()
            img.save(buf)
            buf.seek(0)
            img_base64 = base64.b64encode(buf.getvalue()).decode('ascii')

            return render_template("setup_2fa.html", qr_code=img_base64, secret=secret)
        else:
            return render_template("signup.html", msg="Username already exists")

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
