from flask import Flask, render_template, request, redirect, url_for
from flask_cors import CORS
import user_management as dbHandler
import html

app = Flask(__name__)
CORS(app)

# -------------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@app.route("/index.html", methods=["GET", "POST"])
def index():
    # 1. FLAW: Open Redirect (Invalid Forwarding)
    # This is required for your layout.html navigation to work!
    # It takes the '?url=' parameter and redirects the user there without validation.
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)

    # 2. Login Logic (POST)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Check credentials (using the vulnerable DB handler)
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        
        if isLoggedIn:
            # Login Success: Show feedback page
            all_feedback = dbHandler.listFeedback()
            return render_template("success.html", value=username, state=True, feedback=all_feedback)
        else:
            # Login Failed: Reload login with error
            return render_template("index.html", msg="Invalid Credentials")

    # 3. Page Load (GET)
    else:
        # FLAW: XSS (Reflected) via 'msg' parameter
        msg = request.args.get("msg", "")
        # Note: To fully demonstrate XSS, you might want to remove html.escape(msg) later,
        # but for now, we leave it to keep the app running.
        if msg:
            msg = html.escape(msg) 
        return render_template("index.html", msg=msg)


@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    # Handle the navigation redirect if present
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        
        # Save user (Vulnerable Plaintext Insert)
        dbHandler.insertUser(username, password, dob)
        
        # Redirect to login
        return redirect(url_for('index', msg="Registration Successful"))
        
    return render_template("signup.html")


@app.route("/success.html", methods=["GET", "POST"])
def success():
    # Handle the navigation redirect if present
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        # FLAW: CSRF (No token check)
        feedback_text = request.form["feedback"]
        dbHandler.insertFeedback(feedback_text)
        
    all_feedback = dbHandler.listFeedback()
    
    # Note: State is hardcoded to True here as a simplification for the PWA demo
    return render_template("success.html", value="User", state=True, feedback=all_feedback)


if __name__ == "__main__":
    # Initialize the database tables
    dbHandler.init_db()
    
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    # FLAW: Debug mode enabled
    app.run(debug=True, host="0.0.0.0", port=5000)
