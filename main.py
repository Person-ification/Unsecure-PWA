from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask_cors import CORS
import user_management as dbHandler
import html

app = Flask(__name__)
CORS(app)

# --- ROUTES ---

@app.route("/", methods=["GET", "POST"])
@app.route("/index.html", methods=["GET", "POST"])
def index():
    # 1. Handle Open Redirect Vulnerability (if implemented in URL)
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)

    # 2. Handle Login Logic (POST)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Check credentials against DB
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        
        if isLoggedIn:
            # Successful login: Load feedback/success page
            all_feedback = dbHandler.listFeedback()
            return render_template("success.html", value=username, state=True, feedback=all_feedback)
        else:
            # Failed login: Reload index with error message
            return render_template("index.html", msg="Invalid Credentials")

    # 3. Handle Page Load (GET)
    else:
        msg = request.args.get("msg", "")
        if msg:
            # Note: For the 'Unsecure' version, we will eventually remove html.escape
            msg = html.escape(msg)
        return render_template("index.html", msg=msg)


@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        
        # Insert user into DB
        dbHandler.insertUser(username, password, dob)
        
        # Redirect to login page with success message
        return redirect(url_for('index', msg="Registration Successful"))
        
    return render_template("signup.html")


@app.route("/success.html", methods=["GET", "POST"])
def success():
    # This route handles adding feedback
    if request.method == "POST":
        feedback_text = request.form["feedback"]
        dbHandler.insertFeedback(feedback_text)
        
    # Always reload the feedback list
    all_feedback = dbHandler.listFeedback()
    
    # Note: In a real app, we should check if the user is logged in here
    return render_template(
        "success.html",
        value="User", 
        state=True, 
        feedback=all_feedback
    )

# --- SECURITY HEADERS ---
# Note: To make this an "Unsecure PWA" later, we will need to REMOVE this section.
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
    return response

if __name__ == "__main__":
    # Initialize DB (Optional, ensures tables exist if you have an init function)
    # dbHandler.init_db() 
    
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
