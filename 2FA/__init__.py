#!/usr/bin/env python3
from flask import Blueprint, request, session, redirect, render_template, url_for, flash
from CTFd.models import Users
from CTFd.plugins import register_plugin_assets_directory
from CTFd.utils.email import sendmail
from CTFd.utils.user import get_current_user
from CTFd.utils import get_config, set_config
from CTFd.utils.security.auth import logout_user
from CTFd.utils.decorators import admins_only
import random
import time

OTP_EXPIRY = 300  # 5 minutes

## TODO:
# Fix multiple redirects
# make sure that when the 2FA fails, there is an error mesage.
# it can fail 3 x
# then user is fully logged out.
# also check if a mail has been sent, we can send a mail every minute. so add a last time mailed, and do a check if we are within the minute.
# Check the initial registration.

default_2FA_text="Your CTFd 2 Factor Authentication code is: OTP_TOKEN\nPlease enter this on the CTFd website.\n\nIf you have not tried to login to the CTF, you account could be compromised and a password change is required to keep your account safe."

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user):
    last_sent = session.get('otp_last_sent')
    now = time.time()
    cooldown = 60  # seconds

    if last_sent and (now - last_sent < cooldown):
        print("OTP email cooldown active, not sending new email.")
        return  # Do NOT resend if within cooldown

    otp = generate_otp()
    store_otp(user.id, otp)
    session['otp_last_sent'] = now

    message=get_config('email_2fa_message') or default_2FA_text

    sendmail(
        addr=user.email,
        subject="Your CTFd 2FA Code",
        text=message.replace("OTP_TOKEN", otp)
    )

def store_otp(user_id, otp):
    session['otp'] = otp
    session['otp_time'] = time.time()
    session['otp_user'] = user_id

def verify_otp(user, code):
    stored_otp = session.get('otp')
    timestamp = session.get('otp_time')
    user_match = session.get('otp_user') == user.id

    if not (stored_otp and timestamp and user_match):
        return False

    if time.time() - timestamp > OTP_EXPIRY:
        return False

    return code == stored_otp


def reset_2fa_session_and_logout():
    session_keys = [
        'otp',
        'otp_time',
        'otp_user',
        'otp_last_sent',
        '2fa_passed',
        'resend_attempts',
        '2fa_code_attempts'
    ]
    for key in session_keys:
        session.pop(key, None)
    logout_user()

def define_backend_routes(app):
    bp = Blueprint('email_2fa', __name__, template_folder='templates')

    @app.before_request
    def enforce_email_2fa():
        if get_config('email_2fa_enabled') != True:
            return  # Skip enforcement if 2FA is disabled
        
        exempt_endpoints = [
            "auth.login", "auth.logout", "auth.confirm", "email_2fa.otp_prompt", "email_2fa.otp_verify",
            "views.static", "views.themes", "views.files", "views.static_html", "api.configs_config_list",
            "events.subscribe", "email_2fa.resend_otp"  
            # Allow static files and prevent multiple redirects
        ]
        if request.endpoint in exempt_endpoints:
            return
        
        if request.endpoint.startswith("plugins.") and "assets" in request.endpoint:
            # allow the plugin assets, these could be injected in pages.
            return
        
        user=get_current_user()
        
        if user and not user.verified:
            if request.endpoint == "views.settings" or request.endpoint == "api.users_user_private":
                # Dont do 2FA when a (unverified) user tries to change the email address at registration.
                return

        # if request.endpoint and request.endpoint.startswith("admin"):
        #     return  # Optional: don't block admin panel

        if user and not session.get("2fa_passed"):
            return redirect(url_for("email_2fa.otp_prompt"))

    @bp.route('/2fa', methods=['GET', 'POST'])
    def otp_prompt():
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        send_otp_email(user)
        # Pass the last sent time (or 0 if not set)
        last_sent = session.get("otp_last_sent", 0)
        session["2fa_code_attempts"] = 0
        return render_template("2fa.html", last_sent=int(last_sent))

    @bp.route('/2fa/verify', methods=['POST'])
    def otp_verify():
        code = request.form.get('otp')
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        success = verify_otp(user, code)

        if session["2fa_code_attempts"] == 3:
            reset_2fa_session_and_logout()
            return {"success": False, "error": "To many tries with an invalid code. Please log in again."}, 400

        if success:
            session["2fa_passed"] = True
            session.pop("resend_attempts", None)
            session.pop("otp_last_sent", None)
            session.pop("2fa_code_attempts", None)
            return {"success": True, "redirect": url_for("challenges.listing")}
        else:
            session["2fa_code_attempts"]+=1
            return {"success": False, "error": "Invalid code. Please try again."}, 400
    
    @bp.route('/2fa/resend', methods=['POST'])
    def resend_otp():
        user = get_current_user()
        if not user:
            return {"success": False, "error": "User not authenticated."}, 403

        # Count attempts in session
        resend_attempts = session.get("resend_attempts", 0)
        if resend_attempts >= 3:
            reset_2fa_session_and_logout()
            return {"success": False, "error": "Maximum resend attempts reached."}, 429

        session["resend_attempts"] = resend_attempts + 1
        send_otp_email(user)
        session["2fa_code_attempts"] = 0
        return {"success": True, "message": "OTP resent successfully."}

    # Route for the admin page to enable/disable 2FA
    @bp.route('/admin/2fa', methods=['GET', 'POST'])
    @admins_only
    def admin_2fa_settings():
        if request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                response = {"success": True}

                # Handle the enabled checkbox
                if "enabled" in data:
                    enabled = data.get('enabled', False)
                    set_config('email_2fa_enabled', str(enabled))
                    response['enabled'] = enabled

                # Handle the 2FA message textarea
                if "message" in data:
                    message = data.get('message', '')
                    set_config('email_2fa_message', message)
                    response['message'] = message

                return response
            else:
                return {"success": False, "error": "Invalid request format."}, 400

        # GET: render page with current settings
        enabled = get_config('email_2fa_enabled')
        message = get_config('email_2fa_message') or default_2FA_text
        print("message",message)
        return render_template('admin_2fa_settings.html', enabled=enabled, TWOFA_message=message)

    app.register_blueprint(bp)
    
def load(app):
    register_plugin_assets_directory(app, base_path="/plugins/2FA/assets")
    app.db.create_all()
    define_backend_routes(app)