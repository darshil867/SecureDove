from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from markupsafe import escape
from flask_mail import Mail, Message
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from bson.objectid import ObjectId
import uuid

import os
import random
import secrets
import string
import requests
import bcrypt
import logging
from datetime import timedelta
from datetime import datetime

# Import extensions (limiter, csrf)
from extensions import limiter, csrf
# Import blueprints
from routes.group_routes import group_bp

# --- Security Audit Logging Configuration ---
#added in response to TA comments in response to 2.2
#Sets up system that logs security events like logins or fail attempts into the docker container/server filesystem
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        #this first one goes to the security log file
        logging.FileHandler('security_audit.log'),
        #this second one goes to the console
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security_audit')


app = Flask(__name__)
# --- Security-related config for HTTPS ---
app.config['SESSION_COOKIE_SECURE'] = True      # Only send session cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True    # Preventing JavaScript from accessing cookies to carry out attacks
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # Allowws cookies for normal navigation but not cross-site requests

app.config['PREFERRED_URL_SCHEME'] = 'https' #using https instead of http

# --- Configuration ---
# Now gets secret key from environment variable
app.secret_key = os.getenv("FLASK_SECRET_KEY")
# if missing crash app immediately
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set")
# same with recaptcha
RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
if not RECAPTCHA_SITE_KEY or not RECAPTCHA_SECRET_KEY:
    raise ValueError("RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY environment variables must be set")

UPLOAD_FOLDER = 'uploads' # Folder to store uploaded files
# Ensure the uploads folder is created at startup if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Added file uploads to be a max of 16MB to try to prevent DoS attacks from huge files
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["daap_secdov"]
users = db["users"]
messages = db["messages"]
friend_requests = db["friend_requests"]
groups = db["groups"]
group_messages = db["group_messages"]
group_invitations = db["group_invitations"]
notifications = db["notifications"]


# --- email config ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
mail = Mail(app)

# --- Initialize Extensions ---
# Extensions are defined in extensions.py to avoid circular imports
# Helps protect against DoS attacks and brute force attempts
limiter.init_app(app)

# Protects against Cross-Site Request Forgery attacks
csrf.init_app(app)

# --- Register Blueprints ---
app.register_blueprint(group_bp)

# Define bcrypt work factor. Higher cost = slower hashing to limit brute force attempts
# cost 12 takes around 250ms to hash and reduces the number of passwords per second attackers can try
# 12 cost is usually a common number to use for security. More secure (liek banking apps seem to use a high value like 13 or 14)
bcrypt_cost = 12

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Security Headers ---
@app.after_request
def set_security_headers(response):
    """Add security headers to every response"""
    # tells the browser to only use the type that it is specified to use
    #avoids issues if a text file was rendered as an HTML, for example, and there was malicious code inside
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevents issues where site is rendered in another frame that could cause issues (like delete account button is selected accidentally because of frame elements vs non-frame elements)
    #just denying any frames entirely
    response.headers['X-Frame-Options'] = 'DENY'

    # Enable XSS protection (only relevant for older browsers since new browsers have protections)
    #helps prevent attackers from running scripts in some cases in other people's browsers through malicious javascript. The block prvents scripts from executing
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Force HTTPS for 1 year
    #this prevents page from being rendered in http unknowingly by the user. Age is in second. 1-2 is common
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Control what the browser is allowed to load
    #blocks resources that the browser is allowed to load unless they are specifically pre-defined (keeping google for recaptcha)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://www.google.com https://www.gstatic.com; frame-src https://www.google.com https://www.gstatic.com"

    # Control referrer information
    # prevents full urls to be sent to sites that you are navigating from. Helps avoid some tracking
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Control browser features
    # specifically denying any api calls that could access location, microphone, or camera to prevent certain unexpected javascript attacks
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    return response

# --- Routes ---

@app.route('/')
def home():
    if "username" not in session:
        return render_template('index.html')

    username = session["username"]
    user = users.find_one({"username": username})

    # Retrieve friends
    friends = user.get("friends", [])

    # Get friend requests
    incoming_reqs = list(friend_requests.find({"to": username, "status": "pending"}))
    outgoing_reqs = list(friend_requests.find({"from": username, "status": "pending"}))


    # Messages (only between friends)
    received = list(messages.find({"receiver": username, "sender": {"$in": friends}}))
    sent = list(messages.find({"sender": username, "receiver": {"$in": friends}}))

    # Get user's groups
    user_groups = list(groups.find({"members": username}))
    
    # Get group invitations
    group_invites = list(group_invitations.find({
        "to_user": username,
        "status": "pending"
    }))
    

    all_group_messages = {}
    for group in user_groups:
        group_id = group["group_id"]
        # Get user's join time
        join_time_str = group.get("member_join_times", {}).get(username)
        if join_time_str:
            join_time = datetime.fromisoformat(join_time_str)
            # Only show messages after user joined
            msgs = list(group_messages.find({
                "group_id": group_id,
                "timestamp": {"$gte": join_time}
            }).sort("timestamp", 1))
        else:
            msgs = []
        all_group_messages[group_id] = msgs

    login_count = user.get("login_count", 0)
    login_times = user.get("login_times", [])

    # Get unread notifications
    user_notifications = list(notifications.find({
        "username": username,
        "read": False
    }).sort("timestamp", -1))
    
    # Mark them as read
    if user_notifications:
        notifications.update_many(
            {"username": username, "read": False},
            {"$set": {"read": True}}
        )
    
    return render_template(
        'home.html',
        username=username,
        friends=friends,
        received=received,
        sent=sent,
        incoming_reqs=incoming_reqs,
        outgoing_reqs=outgoing_reqs,
        login_count=login_count,
        login_times=login_times,
        user_groups=user_groups,
        group_invites=group_invites,
        all_group_messages=all_group_messages,
        notifications=user_notifications 
    )


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Prevents brute force attacks
def login():
    # --- V3 Configuration (These values are required for V3 verification) ---
    RECAPTCHA_THRESHOLD = 0.6  # Score threshold: 1.0 is definitely human, 0.0 is definitely bot.
    RECAPTCHA_ACTION = 'user_login' 
    # -------------------------------------------------------------

    if request.method == 'POST':
        # -----------------------------------------------------
        # START: reCAPTCHA Verification (V3 Score Check)
        # -----------------------------------------------------
        recaptcha_response = request.form.get('g-recaptcha-response')
        
        if not recaptcha_response:
            flash("reCAPTCHA response missing. Ensure JavaScript is enabled and the token is being sent.", "error")
            return redirect(url_for('login'))

        # Send request to Google to verify the token
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        
        try:
            # Send the secret key and user response token to Google
            response = requests.post(verify_url, data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response,
            }, timeout=5) # Added timeout for safety
            
            result = response.json()
            
            # Extract and check V3 success, score, and action match
            score = result.get('score', 0.0)
            action = result.get('action')

            # V3 Verification: Check if successful AND score is above threshold AND action matches
            if not result.get('success') or score < RECAPTCHA_THRESHOLD or action != RECAPTCHA_ACTION:
                # Log the failure details for internal review
                print(f"reCAPTCHA V3 failed: Score={score}, Action={action}")
                flash("Security verification failed. Please try again.", "error")
                return redirect(url_for('login'))

        except requests.exceptions.RequestException:
            # Handle API call failure (e.g., network error)
            flash("Could not connect to reCAPTCHA service. Please try again.", "error")
            return redirect(url_for('login'))
        # -----------------------------------------------------
        # END: reCAPTCHA Verification
        # -----------------------------------------------------

        # The existing logic now only runs if reCAPTCHA is successful
        username = request.form['username']
        password = request.form['password']

        user = users.find_one({"username": username})

        # --- TIMING ATTACK MITIGATION ---
        # Always hash the password, even if user doesn't exist
        # This ensures constant-time response
        if user:
            stored_hash = user.get("password", "").encode('utf-8')
        else:
            # Use a dummy hash for non-existent users
            # This makes timing consistent with valid users
            stored_hash = bcrypt.hashpw(b"dummy_password", bcrypt.gensalt(rounds=bcrypt_cost))

        password_bytes = password.encode('utf-8')
        # This ALWAYS runs bcrypt check, regardless of whether user exists
        valid_password = bcrypt.checkpw(password_bytes, stored_hash)

        # Only proceed if BOTH user exists AND password is valid (but make sure somewhat equivalent to the other case)
        if user and valid_password:
            session["username"] = username

            # Track login
            users.update_one(
                {"username": username},
                {
                    "$inc": {"login_count": 1},
                    "$push": {"login_times": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                }
            )

            # Security audit log - successful login
            security_logger.info(f"SUCCESSFUL_LOGIN: User '{username}' from IP {get_remote_address()}")

            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('home'))
        else:
            # Same error message and same timing for both cases to make it harder for attackers to steal info

            # Security audit log - failed login attempt (only admin should realize that this is invalid such that it could be an attack)
            security_logger.warning(f"FAILED_LOGIN: Username '{username}' from IP {get_remote_address()}")

            flash("Invalid username or password.", "error")
            return redirect(url_for('login'))

    # When rendering the page (GET request), pass the public site key to the template
    return render_template(
        'login.html',
        recaptcha_site_key=RECAPTCHA_SITE_KEY
    )


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Prevents spam account creation
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # --- PASSWORD VALIDATION ---
        #previously had no restrictions on password complexity but now we have added requirements
        import re
        password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'

        if not re.match(password_regex, password):
            flash("Password must be at least 8 characters long, include 1 uppercase letter, 1 number, and 1 special character.", "error")
            return redirect(url_for('register'))

        # Check if username or email exists
        existing_user = users.find_one({"$or": [{"username": username}, {"email": email}]})
        if existing_user:
            flash("Username or email already exists.", "error")
            return redirect(url_for('register'))

        # Always hashing passwords now and storing the has in the database instead of plain text
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=bcrypt_cost)
        password_hash = bcrypt.hashpw(password_bytes, salt)

        users.insert_one({
            "username": username,
            "email": email,
            "password": password_hash.decode('utf-8'),
            "friends": [],
            "login_count": 0,
            "login_times": []
        })

        # Security audit log - new account created
        security_logger.info(f"ACCOUNT_CREATED: User '{username}' registered from IP {get_remote_address()}")

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop("username", None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    if "username" not in session:
        flash("You must be logged in to view your profile.", "error")
        return redirect(url_for('login'))

    username = session["username"]
    user = users.find_one({"username": username})

    return render_template(
        'profile.html',
        username=username,
        email=user.get("email")
    )

@app.route('/update_profile', methods=['POST'])
@limiter.limit("10 per hour")  # Prevents abuse of profile updates
def update_profile():
    if "username" not in session:
        flash("You must be logged in to update your profile.", "error")
        return redirect(url_for('login'))

    username = session["username"]
    new_email = request.form['email']

    # Check if the new email already belongs to another user
    existing_user_with_email = users.find_one(
        {"email": new_email, "username": {"$ne": username}}
    )

    if existing_user_with_email:
        flash("This email is already registered to another user.", "error")
        return redirect(url_for('profile'))

    # Update the email
    users.update_one(
        {"username": username},
        {"$set": {"email": new_email}}
    )

    flash("Your email has been successfully updated!", "success")
    return redirect(url_for('profile'))


@app.route('/send_message', methods=['POST'])
@limiter.limit("30 per minute")  # Prevents message spam while allowing normal conversation
def send_message():
    if "username" not in session:
        flash("You must be logged in to send messages.", "error")
        return redirect(url_for('login'))

    sender = session["username"]
    receiver = request.form["receiver"]

    # Sanitize message content to prevent XSS attacks
    #goal is to not store possibly malicious code in the database that other users would get exposed with. Convert characters into their safer versions
    content = escape(request.form.get("content", "").strip())
    filename = None 

    sender_data = users.find_one({"username": sender})
    if receiver not in sender_data.get("friends", []):
        flash("You can only message your friends.", "error")
        return redirect(url_for('home'))


    file = request.files.get('file')
    
    if file and file.filename:

        if allowed_file(file.filename):
            #using secure_filename to sanitize names so the intentionally malicious file names from attackers won't trigger weird behaviors.
            original_filename = secure_filename(file.filename)
            
 
            unique_id = str(uuid.uuid4())
            filename = f"{unique_id}_{original_filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            if not content:
                content = f"File shared: {original_filename}"
        elif file.filename != '':
            flash("Invalid file type. Allowed extensions: txt, pdf, png, jpg, jpeg, gif, zip.", "error")
            return redirect(url_for('chat', friend_username=receiver))


    if not content and not filename:
        flash("Cannot send an empty message or file.", "error")
        return redirect(url_for('chat', friend_username=receiver))

    messages.insert_one({
        "sender": sender,
        "receiver": receiver,
        "content": content,
        "filename": filename, # Store the unique saved filename
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    flash(f"Message sent!", "success")
    return redirect(url_for('chat', friend_username=receiver))


@app.route('/delete_message/<message_id>', methods=['POST'])
@limiter.limit("30 per minute")  # Prevents deletion spam
def delete_message(message_id):
    sender = session["username"]
    # Default redirection target
    friend_username = None 

    try:
        obj_id = ObjectId(message_id)
        
       
        message_to_delete = messages.find_one({"_id": obj_id, "sender": sender})

        if message_to_delete:
            # The friend is the receiver of the message
            friend_username = message_to_delete['receiver']

            # 2. Delete the message
            result = messages.delete_one({"_id": obj_id, "sender": sender})
            
            if result.deleted_count == 1:
                flash("Message deleted.", "success")
            else:
                flash("Error deleting message.", "error") 
        else:
            flash("Message not found or you don't have permission to delete it.", "error")
            
    except Exception as e:
        print(f"Error processing message ID: {e}")
        flash("Invalid message ID format.", "error")

    if friend_username:
        return redirect(url_for('chat', friend_username=friend_username))
    else:
        return redirect(url_for('home'))


@app.route('/download/<filename>')
def download_file(filename):
    
    if 'username' not in session:
        flash("You must be logged in to download files.", "error")
        return redirect(url_for('login'))
    
    current_user = session['username']
    
    message = messages.find_one({ 
        "filename": filename,
        "$or": [
            {"sender": current_user},
            {"receiver": current_user}
        ]
    })
    
    if not message:
        flash("File not found or you are not authorized to access it.", "error")
        return redirect(url_for('home'))

    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True 
        )
    except FileNotFoundError:
        flash("The requested file was not found on the server.", "error")
        return redirect(url_for('home'))


@app.route('/send_friend_request', methods=['POST'])
@limiter.limit("10 per hour")  # Prevents friend request spam
def send_friend_request():
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))

    from_user = session["username"]
    to_user = request.form["to_user"].strip()

    # Check if trying to friend yourself
    if to_user == from_user:
        flash("You cannot send a friend request to yourself.", "error")
        return redirect(url_for('home'))

    
    # Check if target user exists

    target_user = users.find_one({"username": to_user})

    if not target_user:
        """
        flash(f"User '{to_user}' not found.", "error")
        """
        return redirect(url_for('home'))



    # Check if already friends
    current_user = users.find_one({"username": from_user})
    if to_user in current_user.get("friends", []):
        flash(f"You are already friends with {to_user}.", "info")
        return redirect(url_for('home'))

    # Check if request already exists
    if friend_requests.find_one({"from": from_user, "to": to_user, "status": "pending"}):
        flash("Friend request already sent.", "info")
        return redirect(url_for('home'))

    friend_requests.insert_one({
        "from": from_user,
        "to": to_user,
        "status": "pending"
    })

    flash(f"Friend request sent to {to_user}.", "success")
    return redirect(url_for('home'))


@app.route('/respond_friend_request', methods=['POST'])
@limiter.limit("20 per hour")  # Prevents spam accepting/rejecting requests
def respond_friend_request():
    if "username" not in session:
        return redirect(url_for('login'))

    from_user = request.form["from_user"]
    action = request.form["action"]
    to_user = session["username"]

    if action == "accept":
        # Update status
        friend_requests.update_one(
            {"from": from_user, "to": to_user, "status": "pending"},
            {"$set": {"status": "accepted"}}
        )
        # Add each other as friends
        users.update_one({"username": to_user}, {"$addToSet": {"friends": from_user}})
        users.update_one({"username": from_user}, {"$addToSet": {"friends": to_user}})
        flash(f"You are now friends with {from_user}!", "success")
    else:
        friend_requests.update_one(
            {"from": from_user, "to": to_user, "status": "pending"},
            {"$set": {"status": "rejected"}}
        )
        flash(f"Friend request from {from_user} rejected.", "info")

    return redirect(url_for('home'))

@app.route('/chat/<friend_username>')
def chat(friend_username):
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))
    
    username = session["username"]
    user = users.find_one({"username": username})
    
    # Check if they're friends
    if friend_username not in user.get("friends", []):
        flash("You can only chat with friends.", "error")
        return redirect(url_for('home'))
    
    # Get all messages between these two users
    conversation = list(messages.find({
        "$or": [
            {"sender": username, "receiver": friend_username},
            {"sender": friend_username, "receiver": username}
        ]
    }).sort("timestamp", 1))
    
    return render_template(
        'chat.html',
        username=username,
        friend=friend_username,
        conversation=conversation
    )

@app.route('/account_activity')
def account_activity():
    if "username" not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))
    
    username = session["username"]
    user = users.find_one({"username": username})
    
    login_count = user.get("login_count", 0)
    login_times = user.get("login_times", [])
    
    return render_template(
        'account_activity.html',
        username=username,
        login_count=login_count,
        login_times=login_times
    )

# Temporary storage for password reset codes
reset_codes={}
@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")  # Prevents reset code spam and email enumeration
def forgot_password():
    if request.method == 'POST':
        email = request.form["email"]
        user = users.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})

        if not user:
            flash("No account associated with that email.", "error")
            return redirect(url_for('forgot_password'))

        # Generate cryptographically secure reset code
        # Updated to use secrets module instead of random for more security
        # updated number of digits to be 8 instead of 6. Addressed expiration concerns raised by the TA
        reset_code = ''.join(secrets.choice(string.digits) for _ in range(8))
        reset_codes[email] = {
            "code": reset_code,
            "expires": datetime.now() + timedelta(minutes=5)
        }

        # Send email
        msg = Message(
            subject="Password Reset Request",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email]
        )
        msg.body = f"Your password rest code is: {reset_code}\nThis code will expire in 5 minutes."
        mail.send(msg)

        # Security audit log - password reset requested
        security_logger.info(f"PASSWORD_RESET_REQUESTED: Email '{email}' from IP {get_remote_address()}")

        flash("A reset code has been sent to your email.", "info")
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')


@app.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Prevents brute force of reset codes
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        code = request.form['code']
        new_password = request.form['new_password']

        data = reset_codes.get(email)

        if not data:
            flash("No reset request found for this email.", "error")
            return redirect(url_for('reset_password'))

        if datetime.now() > data["expires"]:
            flash("Reset code expired.", "error")
            reset_codes.pop(email, None)
            return redirect(url_for('forgot_password'))

        if data["code"] != code:
            # Security audit log - failed password reset attempt (wrong code)
            security_logger.warning(f"PASSWORD_RESET_FAILED: Invalid code for email '{email}' from IP {get_remote_address()}")

            flash("Invalid reset code.", "error")
            return redirect(url_for('forgot_password'))

        # --- PASSWORD COMPLEXITY VALIDATION ---
        import re
        password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'

        if not re.match(password_regex, new_password):
            flash("Password must be at least 8 characters long, include 1 uppercase letter, 1 number, and 1 special character.", "error")
            return redirect(url_for('reset_password'))

        #still hashing passwords and storing them hashed just like a new registration
        password_bytes = new_password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=bcrypt_cost)
        password_hash = bcrypt.hashpw(password_bytes, salt)

        # Update password in database with HASHED password
        users.update_one({"email": email}, {"$set": {"password": password_hash.decode('utf-8')}})
        reset_codes.pop(email, None)

        # Security audit log - password successfully reset
        security_logger.info(f"PASSWORD_RESET_COMPLETED: Email '{email}' from IP {get_remote_address()}")

        flash("Your password has been reset.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


if __name__ == '__main__':
    # SSL cert and key will be placed at /certs inside the container
    ssl_context = ('/certs/cert.pem', '/certs/key.pem')
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=ssl_context)
