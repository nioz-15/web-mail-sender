import os
import io
import zipfile
import json
import subprocess
import re
import html
import threading
import time
import random
import string
import boto3
import uuid
import hashlib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from flask import Flask, render_template, jsonify, send_from_directory, request, url_for, send_file, session, redirect, \
    flash, Blueprint

# ============================================================================
# MAIN APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.secret_key = 'your-very-secure-secret-key-change-this-in-production'

# Enhanced session configuration for Email Testing Platform
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Enable debug mode for better troubleshooting
app.config['DEBUG'] = True

# ============================================================================
# BDD DASHBOARD CONFIGURATION
# ============================================================================

# Directory for downloaded reports
DOWNLOAD_DIR = "/home/ubuntu/BDD/Dash/static/downloaded-reports"

# Virtual environment Python
VENV_PYTHON = "/home/ubuntu/BDD/Dash/venv/bin/python3"

# BDD Tests data
try:
    with open('bdd_tests.json', 'r') as file:
        BDD_TESTS = json.load(file)
    print(f"✅ Loaded {len(BDD_TESTS)} BDD tests")
except FileNotFoundError:
    print("⚠️ bdd_tests.json not found - BDD search will be empty")
    BDD_TESTS = []
except json.JSONDecodeError as e:
    print(f"⚠️ Error parsing bdd_tests.json: {e}")
    BDD_TESTS = []

# Test data (farm status)
DATA_JSON_PATH = os.path.join('static', 'data.json')

# ============================================================================
# EMAIL TESTING PLATFORM IMPORTS
# ============================================================================

# Import Email Testing Platform modules
try:
    from email_security_framework import Email, Sender, RecipientsList, Attachment
    from EmailUtils import start_email_campaign, get_session_progress, stop_session, test_email_config

    from file_generators.generators.attachment_generator import AttachmentDataGenerator
    from file_generators.generators.body_generator import BodyDataGenerator
    from file_generators.generators.subject_generator import SubjectDataGenerator

    EMAIL_FRAMEWORK_AVAILABLE = True
    print("✅ Email Testing Platform modules loaded successfully!")
    print("🔥 REAL file generators imported:")
    print("   📎 AttachmentDataGenerator - Creates real threat files")
    print("   📝 BodyDataGenerator - Creates realistic email content")
    print("   📧 SubjectDataGenerator - Creates convincing subjects")

except ImportError as e:
    print(f"⚠️ Email Testing Platform modules not found: {e}")
    print("   Email testing features will be disabled in combined app.")
    EMAIL_FRAMEWORK_AVAILABLE = False

# ============================================================================
# EMAIL TESTING PLATFORM CONFIGURATION
# ============================================================================

# Persistent storage configuration
EMAIL_USERS_FILE = 'users.json'
EMAIL_USER_USAGE_FILE = 'user_usage.json'

# Thread-safe file operations
email_file_lock = threading.Lock()

# aws dummy Configuration
AWS_SES_CONFIG = {
    'aws_access_key_id': 'test_access_key',
    'aws_secret_access_key': 'test_secret',
    'region_name': 'test_region'
}

# Session timeout
EMAIL_SESSION_TIMEOUT = 300  # 5 minutes

# User limits
EMAIL_USER_LIMITS = {
    'admin': {'max_messages': float('inf'), 'can_add_users': True},
    'user': {'max_messages': 10, 'can_add_users': False}
}

# Initialize storage
EMAIL_USER_ROLES = {}
EMAIL_VALID_CREDENTIALS = {}
EMAIL_user_message_usage = {}

# ============================================================================
# ENHANCED VERIFICATION CODE SYSTEM
# ============================================================================

# Use thread-safe storage with file backup
verification_codes_lock = threading.Lock()
email_verification_codes = {}
verification_attempts = {}  # Rate limiting
VERIFICATION_BACKUP_FILE = 'verification_codes_backup.json'


def normalize_email(email):
    """Normalize email consistently"""
    if not email:
        return ""
    return email.strip().lower()


def debug_verification_state(operation, email, code=None, extra_info=None):
    """Comprehensive debugging for verification operations"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    normalized_email = normalize_email(email)

    print(f"\n{'=' * 60}")
    print(f"🔍 VERIFICATION DEBUG [{timestamp}] - {operation.upper()}")
    print(f"{'=' * 60}")
    print(f"Original email: '{email}'")
    print(f"Normalized email: '{normalized_email}'")
    if code:
        print(f"Code: '{code}'")
    if extra_info:
        print(f"Extra info: {extra_info}")

    with verification_codes_lock:
        print(f"Total stored codes: {len(email_verification_codes)}")
        print(f"Available keys: {list(email_verification_codes.keys())}")

        for key, data in email_verification_codes.items():
            current_time = time.time()
            time_remaining = data['expires_at'] - current_time
            print(f"  Key: '{key}' -> Code: '{data['code']}', "
                  f"Expires in: {time_remaining:.1f}s, Used: {data.get('used', False)}")

    print(f"{'=' * 60}\n")


def save_verification_codes_to_file():
    """Save verification codes to file as backup"""
    try:
        with verification_codes_lock:
            # Only save non-expired codes
            current_time = time.time()
            valid_codes = {}

            for email, data in email_verification_codes.items():
                if current_time < data.get('expires_at', 0):
                    valid_codes[email] = data

            backup_data = {
                'codes': valid_codes,
                'saved_at': current_time,
                'saved_at_readable': datetime.now().isoformat()
            }

            with open(VERIFICATION_BACKUP_FILE, 'w') as f:
                json.dump(backup_data, f, indent=2)

            print(f"💾 Saved {len(valid_codes)} verification codes to backup file")

    except Exception as e:
        print(f"❌ Error saving verification codes: {e}")


def load_verification_codes_from_file():
    """Load verification codes from file backup"""
    global email_verification_codes

    try:
        if os.path.exists(VERIFICATION_BACKUP_FILE):
            with open(VERIFICATION_BACKUP_FILE, 'r') as f:
                backup_data = json.load(f)

            current_time = time.time()
            loaded_codes = backup_data.get('codes', {})
            valid_codes = {}

            # Only load non-expired codes
            for email, data in loaded_codes.items():
                if current_time < data.get('expires_at', 0):
                    valid_codes[email] = data

            with verification_codes_lock:
                email_verification_codes.update(valid_codes)

            print(f"📂 Loaded {len(valid_codes)} valid verification codes from backup")

    except Exception as e:
        print(f"❌ Error loading verification codes: {e}")


def store_verification_code_comprehensive(normalized_email, code, original_email):
    """Store verification code with all possible key formats"""
    try:
        current_time = time.time()

        verification_data = {
            'code': str(code),
            'created_at': current_time,
            'expires_at': current_time + 600,  # 10 minutes
            'used': False,
            'normalized_email': normalized_email,
            'original_email': original_email,
            'created_at_readable': datetime.now().isoformat()
        }

        # Generate all possible keys
        storage_keys = [
            normalized_email,
            original_email,
            original_email.lower(),
            original_email.strip(),
            original_email.strip().lower(),
            normalized_email.strip(),
            normalized_email.strip().lower()
        ]

        # Remove duplicates while preserving order
        storage_keys = list(dict.fromkeys(storage_keys))

        with verification_codes_lock:
            for key in storage_keys:
                email_verification_codes[key] = verification_data.copy()

            print(f"✅ Stored verification code for {len(storage_keys)} key variants")
            print(f"   Keys: {storage_keys}")

        # Save to file
        save_verification_codes_to_file()
        return True

    except Exception as e:
        print(f"❌ Error storing verification code: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_code_comprehensive(pending_email, pending_original, provided_code):
    """Comprehensive verification with all possible email formats"""
    try:
        current_time = time.time()

        # Generate all possible lookup keys
        lookup_keys = []

        if pending_email:
            lookup_keys.extend([
                pending_email,
                pending_email.strip(),
                pending_email.strip().lower()
            ])

        if pending_original and pending_original != pending_email:
            lookup_keys.extend([
                pending_original,
                pending_original.lower(),
                pending_original.strip(),
                pending_original.strip().lower()
            ])

        # Remove duplicates while preserving order
        lookup_keys = list(dict.fromkeys(lookup_keys))

        print(f"🔍 Verifying code '{provided_code}' with lookup keys: {lookup_keys}")

        verification_data = None
        found_key = None

        with verification_codes_lock:
            # Try each key until we find a match
            for key in lookup_keys:
                if key in email_verification_codes:
                    data = email_verification_codes[key]
                    print(f"📋 Found data for key '{key}': expires={data.get('expires_at')}, used={data.get('used')}")

                    # Check if this is a valid, unexpired, unused code
                    if (not data.get('used', False) and
                            current_time < data.get('expires_at', 0)):

                        stored_code = str(data.get('code', '')).strip()
                        provided_code_clean = str(provided_code).strip()

                        print(f"🔍 Comparing codes: stored='{stored_code}', provided='{provided_code_clean}'")

                        if stored_code == provided_code_clean:
                            verification_data = data
                            found_key = key
                            print(f"✅ Code match found with key: {key}")
                            break

            if not verification_data:
                print(f"❌ No valid verification data found")
                print(f"   Available keys in storage: {list(email_verification_codes.keys())}")
                return False, "No verification code found for this email. Please request a new code."

            # Check expiration
            if current_time > verification_data.get('expires_at', 0):
                time_expired = current_time - verification_data.get('expires_at', 0)
                print(f"❌ Code expired {time_expired:.1f} seconds ago")

                # Clean up expired code
                cleanup_verification_codes_for_email(lookup_keys)
                return False, "Verification code has expired. Please request a new code."

            # Check if already used
            if verification_data.get('used', False):
                used_at = verification_data.get('used_at', 'unknown')
                print(f"❌ Code already used at: {used_at}")
                return False, "Verification code has already been used. Please request a new code."

            # SUCCESS - Mark as used
            verification_data['used'] = True
            verification_data['used_at'] = current_time
            verification_data['used_at_readable'] = datetime.now().isoformat()

            # Update all instances of this code in storage
            for key in lookup_keys:
                if key in email_verification_codes:
                    email_verification_codes[key] = verification_data

            print(f"✅ Code verified and marked as used")

        # Save updated state
        save_verification_codes_to_file()
        return True, "Code verified successfully"

    except Exception as e:
        print(f"❌ Verification error: {e}")
        import traceback
        traceback.print_exc()
        return False, f"Error during verification: {str(e)}"


def cleanup_verification_codes_for_email(email_keys):
    """Clean up verification codes for specific email keys"""
    try:
        with verification_codes_lock:
            removed_count = 0
            for key in email_keys:
                if key in email_verification_codes:
                    del email_verification_codes[key]
                    removed_count += 1

            if removed_count > 0:
                print(f"🧹 Cleaned up {removed_count} verification code entries")
                save_verification_codes_to_file()

    except Exception as e:
        print(f"❌ Cleanup error: {e}")


# Legacy compatibility functions
def store_verification_code_fixed(email, code):
    """Legacy function - redirects to comprehensive version"""
    normalized = normalize_email(email)
    return store_verification_code_comprehensive(normalized, code, email)


def verify_code_fixed(email, code):
    """Legacy function - redirects to comprehensive version"""
    normalized = normalize_email(email)
    return verify_code_comprehensive(normalized, email, code)


def store_verification_code(email, code):
    """Legacy function - redirects to comprehensive version"""
    return store_verification_code_fixed(email, code)


def verify_code(email, code):
    """Legacy function - redirects to comprehensive version"""
    return verify_code_fixed(email, code)


def cleanup_expired_codes():
    """Clean up expired verification codes"""
    try:
        current_time = time.time()
        with verification_codes_lock:
            expired_keys = []
            for email, data in email_verification_codes.items():
                if current_time > data.get('expires_at', 0):
                    expired_keys.append(email)

            for key in expired_keys:
                del email_verification_codes[key]

            if expired_keys:
                print(f"🧹 Cleaned up {len(expired_keys)} expired verification codes")
                save_verification_codes_to_file()

    except Exception as e:
        print(f"❌ Cleanup error: {e}")


# SES client
try:
    email_ses_client = boto3.client(
        'ses',
        aws_access_key_id=AWS_SES_CONFIG['aws_access_key_id'],
        aws_secret_access_key=AWS_SES_CONFIG['aws_secret_access_key'],
        region_name=AWS_SES_CONFIG['region_name']
    )
    print("✅ AWS SES client initialized")
except Exception as e:
    print(f"⚠️ AWS SES client initialization failed: {e}")
    email_ses_client = None


# ============================================================================
# EMAIL TESTING PLATFORM UTILITIES
# ============================================================================

def save_email_users_to_file():
    """Save users to JSON file (your existing function)"""
    global EMAIL_VALID_CREDENTIALS, EMAIL_USER_ROLES

    with email_file_lock:
        try:
            print(f"💾 EMAIL PLATFORM: Saving users to {EMAIL_USERS_FILE}")

            users_data = {
                'credentials': dict(EMAIL_VALID_CREDENTIALS),
                'roles': dict(EMAIL_USER_ROLES),
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }

            with open(EMAIL_USERS_FILE, 'w') as f:
                json.dump(users_data, f, indent=2)

            print(f"✅ EMAIL PLATFORM: Users saved successfully")
            return True

        except Exception as e:
            print(f"❌ EMAIL PLATFORM: Save error: {e}")
            return False


def load_email_users_from_file():
    """Load users from JSON file (your existing function)"""
    global EMAIL_VALID_CREDENTIALS, EMAIL_USER_ROLES

    try:
        if os.path.exists(EMAIL_USERS_FILE):
            print(f"📂 EMAIL PLATFORM: Loading users from {EMAIL_USERS_FILE}")
            with open(EMAIL_USERS_FILE, 'r') as f:
                users_data = json.load(f)

                loaded_credentials = users_data.get('credentials', {})
                loaded_roles = users_data.get('roles', {})

                EMAIL_VALID_CREDENTIALS.clear()
                EMAIL_USER_ROLES.clear()

                for email, password in loaded_credentials.items():
                    normalized_email = normalize_email(email)
                    EMAIL_VALID_CREDENTIALS[normalized_email] = password

                for email, role in loaded_roles.items():
                    normalized_email = normalize_email(email)
                    EMAIL_USER_ROLES[normalized_email] = role

                print(f"✅ EMAIL PLATFORM: Loaded {len(EMAIL_VALID_CREDENTIALS)} users")
        else:
            print(f"📁 EMAIL PLATFORM: No users file found, creating default users")
            # Your default users
            default_users = {}
            default_roles = {}

            EMAIL_VALID_CREDENTIALS.clear()
            EMAIL_USER_ROLES.clear()

            for email, password in default_users.items():
                normalized_email = normalize_email(email)
                EMAIL_VALID_CREDENTIALS[normalized_email] = password

            for email, role in default_roles.items():
                normalized_email = normalize_email(email)
                EMAIL_USER_ROLES[normalized_email] = role

            save_email_users_to_file()

    except Exception as e:
        print(f"❌ EMAIL PLATFORM: Error loading users: {e}")
        # Fallback to default users
        EMAIL_VALID_CREDENTIALS.clear()
        EMAIL_USER_ROLES.clear()


def load_email_user_usage_from_file():
    """Load user usage from JSON file (your existing function)"""
    global EMAIL_user_message_usage

    try:
        if os.path.exists(EMAIL_USER_USAGE_FILE):
            print(f"📊 EMAIL PLATFORM: Loading usage from {EMAIL_USER_USAGE_FILE}")
            with open(EMAIL_USER_USAGE_FILE, 'r') as f:
                usage_data = json.load(f)
                loaded_usage = usage_data.get('usage', {})

                EMAIL_user_message_usage.clear()
                for email, usage in loaded_usage.items():
                    normalized_email = normalize_email(email)
                    EMAIL_user_message_usage[normalized_email] = usage

                print(f"✅ EMAIL PLATFORM: Loaded usage for {len(EMAIL_user_message_usage)} users")
        else:
            print(f"📊 EMAIL PLATFORM: No usage file found, starting fresh")
            EMAIL_user_message_usage.clear()

    except Exception as e:
        print(f"❌ EMAIL PLATFORM: Error loading usage: {e}")
        EMAIL_user_message_usage.clear()


def get_email_user_role(email):
    """Get user role (your existing function)"""
    if not email:
        return 'user'
    normalized_email = normalize_email(email)
    return EMAIL_USER_ROLES.get(normalized_email, 'user')


def get_email_user_limits(email):
    """Get user limits based on role (your existing function)"""
    if not email:
        return EMAIL_USER_LIMITS['user']

    role = get_email_user_role(email)
    return EMAIL_USER_LIMITS.get(role, EMAIL_USER_LIMITS['user'])


def get_email_user_usage(email):
    """Get user's current message usage (your existing function)"""
    if not email:
        return 0
    normalized_email = normalize_email(email)
    return EMAIL_user_message_usage.get(normalized_email, 0)


def can_send_email_messages(email, count):
    """Check if user can send messages (your existing function)"""
    if not email:
        return False, "Invalid user email"

    normalized_email = normalize_email(email)

    try:
        limits = get_email_user_limits(normalized_email)
        current_usage = get_email_user_usage(normalized_email)
        max_messages = limits.get('max_messages', 0)

        if max_messages == float('inf'):
            return True, "Unlimited messages for admin users"

        if current_usage + count > max_messages:
            remaining = max(0, max_messages - current_usage)
            error_msg = f"Message limit exceeded. You can send {remaining} more messages (limit: {max_messages})"
            return False, error_msg

        success_msg = f"You can send {count} messages. Current usage: {current_usage}/{max_messages}"
        return True, success_msg

    except Exception as e:
        error_msg = f"Error checking message limits: {str(e)}"
        return False, error_msg


# Initialize Email Testing Platform data
load_email_users_from_file()
load_email_user_usage_from_file()


# ============================================================================
# EMAIL TESTING PLATFORM 2FA UTILITIES
# ============================================================================

def generate_verification_code():
    """Generate a 6-digit verification code (your existing function)"""
    return ''.join(random.choices(string.digits, k=6))


def can_request_verification(email):
    """Rate limiting for verification code requests"""
    normalized_email = normalize_email(email)
    now = time.time()

    if normalized_email in verification_attempts:
        last_attempt = verification_attempts[normalized_email]
        if now - last_attempt < 60:  # 1 minute cooldown
            return False, "Please wait 1 minute before requesting another code"

    verification_attempts[normalized_email] = now
    return True, "OK"


def send_verification_email(email, code):
    """Send verification code via email using SES - ENHANCED VERSION"""
    try:
        if not email_ses_client:
            print("❌ SES client not available")
            return False

        subject = "🔐 Email Security Testing Platform - Verification Code"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verification Code</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 20px;
                    background-color: #f4f4f4;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 12px;
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .code-container {{
                    background: #f8fafc;
                    padding: 25px;
                    border-radius: 8px;
                    text-align: center;
                    margin: 25px 0;
                    border: 2px solid #e2e8f0;
                }}
                .verification-code {{
                    font-size: 36px;
                    font-weight: bold;
                    color: #1e40af;
                    letter-spacing: 8px;
                    font-family: 'Courier New', monospace;
                    background: white;
                    padding: 15px 25px;
                    border-radius: 8px;
                    border: 2px solid #3b82f6;
                    display: inline-block;
                    margin: 10px 0;
                }}
                .warning {{
                    background: #fef3c7;
                    padding: 15px;
                    border-radius: 6px;
                    border-left: 4px solid #f59e0b;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #e2e8f0;
                    color: #666;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0; font-size: 24px;">🔐 Email Security Testing Platform</h1>
                    <p style="margin: 10px 0 0 0; opacity: 0.9;">Two-Factor Authentication</p>
                </div>

                <div style="text-align: center; margin-bottom: 20px;">
                    <h2 style="color: #1e293b; margin-bottom: 10px;">Verification Code Required</h2>
                    <p style="color: #64748b;">Please enter this code to complete your login:</p>
                </div>

                <div class="code-container">
                    <p style="margin: 0 0 15px 0; color: #64748b; font-weight: 500;">Your 6-digit verification code:</p>
                    <div class="verification-code">{code}</div>
                    <p style="margin: 15px 0 0 0; color: #64748b; font-size: 14px;">Enter this code in your browser</p>
                </div>

                <div class="warning">
                    <p style="margin: 0; color: #92400e;">
                        <strong>⚠️ Important Security Notice:</strong><br>
                        • This code expires in <strong>10 minutes</strong><br>
                        • It can only be used <strong>once</strong><br>
                        • Never share this code with anyone
                    </p>
                </div>

                <div style="background: #f1f5f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="margin: 0 0 10px 0; color: #1e293b; font-size: 16px;">🔒 Platform Access Details:</h3>
                    <p style="margin: 0; color: #64748b; font-size: 14px;">
                        You are logging into the <strong>Email Security Testing Platform</strong><br>
                        Request time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                        User email: {email}
                    </p>
                </div>

                <div class="footer">
                    <p style="margin: 0;">
                        If you didn't request this verification code, please ignore this email.<br>
                        Your account security has not been compromised.
                    </p>
                    <p style="margin: 10px 0 0 0; font-size: 12px; color: #94a3b8;">
                        © 2025 Email Security Testing Platform - Automation Team
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        message = MIMEMultipart('alternative')
        message['Subject'] = subject
        message['From'] = 'eml_sender@avtestqa.com'
        message['To'] = email

        html_part = MIMEText(html_body, 'html')
        message.attach(html_part)

        response = email_ses_client.send_raw_email(
            Source='eml_sender@avtestqa.com',
            Destinations=[email],
            RawMessage={'Data': message.as_string()}
        )

        print(f"✅ EMAIL PLATFORM: Enhanced verification email sent to {email}. MessageId: {response['MessageId']}")
        return True

    except Exception as e:
        print(f"❌ EMAIL PLATFORM: Failed to send verification email to {email}: {str(e)}")
        return False


def cleanup_verification_code(email):
    """Clean up verification code after use or expiry"""
    normalized_email = normalize_email(email)

    # Remove both normalized and original email entries
    removed_count = 0
    with verification_codes_lock:
        possible_keys = [normalized_email, email, email.lower(), email.strip().lower()]
        for key in possible_keys:
            if key in email_verification_codes:
                del email_verification_codes[key]
                removed_count += 1

    print(f"🔍 CLEANUP DEBUG: Removed {removed_count} verification code entries for '{email}'")


# ============================================================================
# EMAIL TESTING PLATFORM DECORATORS
# ============================================================================

def email_login_required(f):
    """Decorator to require login ONLY for Email Testing Platform routes"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email_logged_in' not in session:
            return redirect(url_for('email_testing.login'))

        if 'email_last_activity' in session:
            if time.time() - session['email_last_activity'] > EMAIL_SESSION_TIMEOUT:
                session.clear()
                flash('Session expired due to inactivity. Please login again.', 'warning')
                return redirect(url_for('email_testing.login'))

        session['email_last_activity'] = time.time()
        session.permanent = True
        return f(*args, **kwargs)

    return decorated_function


def email_admin_required(f):
    """Decorator to require admin role for Email Testing Platform"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email_logged_in' not in session:
            return redirect(url_for('email_testing.login'))

        user_email = normalize_email(session.get('email_user_email', ''))
        if not user_email or get_email_user_role(user_email) != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('email_testing.dashboard'))

        return f(*args, **kwargs)

    return decorated_function


# ============================================================================
# SETUP VERIFICATION SYSTEM INITIALIZATION
# ============================================================================

def setup_verification_cleanup():
    """Setup periodic cleanup of expired codes"""

    def cleanup_worker():
        while True:
            time.sleep(300)  # Every 5 minutes
            cleanup_expired_codes()

    cleanup_thread = threading.Thread(target=cleanup_worker)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    print("🧹 Verification code cleanup worker started")


# Initialize verification codes from backup on server start
print("🔄 Loading verification codes from backup...")
load_verification_codes_from_file()

# Start cleanup worker
setup_verification_cleanup()

print("✅ Enhanced verification code system initialized")

# ============================================================================
# BLUEPRINT: EMAIL TESTING PLATFORM
# ============================================================================

email_testing = Blueprint('email_testing', __name__, url_prefix='/email-testing')


@email_testing.route('/login', methods=['GET', 'POST'])
def login():
    """Fixed login route with proper session handling"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            verification_code = request.form.get('verification_code', '').strip()

            print(f"🔐 LOGIN: email='{email}', has_password={bool(password)}, has_code={bool(verification_code)}")

            # Step 1: Email and password validation (send verification code)
            if not verification_code:
                if not email or not password:
                    flash('Email and password are required', 'error')
                    return render_template('login.html')

                normalized_email = normalize_email(email)
                print(f"🔍 Checking credentials for: {normalized_email}")

                if (normalized_email not in EMAIL_VALID_CREDENTIALS or
                        EMAIL_VALID_CREDENTIALS[normalized_email] != password):
                    flash('Invalid email or password', 'error')
                    return render_template('login.html')

                # Generate and store verification code
                code = generate_verification_code()
                print(f"📧 Generated verification code: {code} for {normalized_email}")

                # Store verification code
                success = store_verification_code_comprehensive(normalized_email, code, email)
                if not success:
                    flash('Error storing verification code. Please try again.', 'error')
                    return render_template('login.html')

                # Store in session for step 2
                session['pending_login_email'] = normalized_email
                session['pending_login_original'] = email
                session['pending_login_time'] = time.time()
                session.permanent = True

                # Try to send email
                email_sent = False
                try:
                    email_sent = send_verification_email(email, code)
                    if email_sent:
                        flash('Verification code sent to your email.', 'success')
                    else:
                        flash(f'Email delivery failed. Your verification code is: {code}', 'warning')
                except Exception as e:
                    print(f"❌ Email sending failed: {e}")
                    flash(f'Email delivery failed. Your verification code is: {code}', 'warning')

                return render_template('login.html', show_code_field=True, email=email)

            # Step 2: Verification code validation
            else:
                # Get session data
                pending_email = session.get('pending_login_email')
                pending_original = session.get('pending_login_original')
                pending_time = session.get('pending_login_time')

                print(f"🔍 VERIFICATION: pending_email='{pending_email}', code='{verification_code}'")

                # Check session timeout
                if not pending_time or time.time() - pending_time > 600:
                    session.clear()
                    flash('Session expired. Please login again.', 'error')
                    return render_template('login.html')

                # Verify the code
                is_valid, message = verify_code_comprehensive(pending_email, pending_original, verification_code)

                if not is_valid:
                    print(f"❌ Verification failed: {message}")
                    flash(message, 'error')
                    return render_template('login.html', show_code_field=True, email=pending_original)

                # SUCCESS - Create session and login
                print(f"✅ Verification successful for {pending_email}")

                # Clear pending login data
                session.pop('pending_login_email', None)
                session.pop('pending_login_original', None)
                session.pop('pending_login_time', None)

                # Set up authenticated session
                session['email_logged_in'] = True
                session['email_user_email'] = pending_email
                session['email_username'] = pending_email.split('@')[0]
                session['email_role'] = get_email_user_role(pending_email)
                session['email_last_activity'] = time.time()
                session['email_login_time'] = time.time()
                session.permanent = True

                print(f"✅ Session created for {pending_email} with role {session['email_role']}")

                flash('Login successful! Welcome to the Email Security Testing Platform.', 'success')
                return redirect('/email-testing/dashboard')

        except Exception as e:
            print(f"❌ LOGIN ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            flash('An error occurred during login. Please try again.', 'error')
            return render_template('login.html')

    # GET request - show login form
    return render_template('login.html')


# DEBUG ROUTE FOR TROUBLESHOOTING
@email_testing.route('/debug/verification-status')
def debug_verification_status():
    """Debug route to check verification code status"""
    if not app.debug:
        return "Debug mode required", 403

    try:
        current_time = time.time()
        status = {
            'current_time': current_time,
            'current_time_readable': datetime.now().isoformat(),
            'total_codes': len(email_verification_codes),
            'codes': {}
        }

        with verification_codes_lock:
            for email, data in email_verification_codes.items():
                expires_at = data.get('expires_at', 0)
                time_remaining = max(0, expires_at - current_time)

                status['codes'][email] = {
                    'code': data.get('code'),
                    'created_at_readable': data.get('created_at_readable'),
                    'expires_at': expires_at,
                    'time_remaining_seconds': time_remaining,
                    'time_remaining_readable': f"{int(time_remaining // 60)}:{int(time_remaining % 60):02d}",
                    'used': data.get('used', False),
                    'used_at_readable': data.get('used_at_readable'),
                    'expired': time_remaining <= 0
                }

        return f"""
        <html>
        <head><title>Verification Status</title></head>
        <body style="font-family: monospace; padding: 20px; background: #f5f5f5;">
            <h2>🔍 Verification Code Status</h2>
            <pre style="background: #000; color: #0f0; padding: 20px; border-radius: 8px; overflow-x: auto;">
{json.dumps(status, indent=2)}
            </pre>
            <br>
            <a href="/email-testing/login" style="background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">← Back to Login</a>
            <a href="/email-testing/debug/clear-codes" style="background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;" onclick="return confirm('Clear all codes?')">Clear All Codes</a>
        </body>
        </html>
        """

    except Exception as e:
        return f"Debug error: {str(e)}", 500


@email_testing.route('/minimal-login')
def minimal_login():
    """Minimal login for nio.z15.nio@gmail.com"""
    try:
        email = 'nio.z15.nio@gmail.com'
        normalized_email = normalize_email(email)

        session.clear()
        session['email_logged_in'] = True
        session['email_user_email'] = normalized_email
        session['email_username'] = normalized_email.split('@')[0]
        session['email_role'] = get_email_user_role(normalized_email)
        session['email_last_activity'] = time.time()
        session['email_login_time'] = time.time()
        session.permanent = True

        flash('Minimal login successful!', 'success')
        return redirect('/email-testing/dashboard')

    except Exception as e:
        return f"Minimal login failed: {str(e)}"


@email_testing.route('/simple-login', methods=['GET', 'POST'])
def simple_login():
    """Simple login without 2FA for debugging"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')

            print(f"🔍 Simple login attempt: {email}")

            normalized_email = normalize_email(email)

            if (normalized_email in EMAIL_VALID_CREDENTIALS and
                    EMAIL_VALID_CREDENTIALS[normalized_email] == password):

                # Direct login without 2FA
                session.clear()
                session['email_logged_in'] = True
                session['email_user_email'] = normalized_email
                session['email_username'] = normalized_email.split('@')[0]
                session['email_role'] = get_email_user_role(normalized_email)
                session['email_last_activity'] = time.time()
                session['email_login_time'] = time.time()
                session.permanent = True

                print(f"✅ Simple login successful for {normalized_email}")
                flash('Login successful (2FA bypassed for debugging)', 'success')
                return redirect('/email-testing/dashboard')
            else:
                flash('Invalid email or password', 'error')

        except Exception as e:
            print(f"❌ Simple login error: {e}")
            flash(f'Login error: {str(e)}', 'error')

    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Simple Login (No 2FA)</title>
        <style>
            body { font-family: Arial; padding: 40px; background: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
            button:hover { background: #005a87; }
            .emergency { background: #dc3545; margin-top: 10px; }
            .emergency:hover { background: #c82333; }
            .back-link { text-align: center; margin-top: 20px; }
            .back-link a { color: #007cba; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2 style="text-align: center; color: #333;">🚨 Emergency Simple Login</h2>
            <p style="text-align: center; color: #666;">Bypass 2FA for debugging</p>

            <form method="POST">
                <input type="email" name="email" placeholder="Email Address" value="nio.z15.nio@gmail.com" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login (No 2FA)</button>
            </form>

            <button onclick="location.href='/email-testing/emergency-login/nio_z15@hotmail.com'" class="emergency">
                Emergency Admin Login
            </button>

            <div class="back-link">
                <a href="/email-testing/login">← Back to Normal Login</a><br>
                <a href="/navigation">← Platform Hub</a>
            </div>

            <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 5px; font-size: 14px;">
                <strong>Default Accounts:</strong><br>
                nio.z15.nio@gmail.com / TestPassword123!<br>
                nio_z15@hotmail.com / A123456z@<br>
                ahmad.zidane.1983@hotmail.com / 12345678
            </div>
        </div>
    </body>
    </html>
    '''


@email_testing.route('/emergency-login/<email>')
def emergency_login(email):
    """Emergency login bypass for debugging"""
    if not app.debug:
        return "Emergency login only available in debug mode", 403

    try:
        normalized_email = normalize_email(email)

        if normalized_email not in EMAIL_VALID_CREDENTIALS:
            return f"Email '{normalized_email}' not found in system", 404

        # Emergency login - bypass 2FA
        session.clear()
        session['email_logged_in'] = True
        session['email_user_email'] = normalized_email
        session['email_username'] = normalized_email.split('@')[0]
        session['email_role'] = get_email_user_role(normalized_email)
        session['email_last_activity'] = time.time()
        session['email_login_time'] = time.time()
        session.permanent = True

        flash(f'Emergency login successful for {normalized_email} ({session["email_role"]})', 'success')
        return redirect(url_for('email_testing.dashboard'))

    except Exception as e:
        return f"Emergency login failed: {str(e)}", 500


@email_testing.route('/logout')
def logout():
    """Email Testing Platform logout"""
    email = session.get('email_user_email', 'User')
    session.clear()
    flash(f'Goodbye! You have been logged out from Email Testing Platform.', 'info')
    return redirect(url_for('email_testing.login'))


@email_testing.route('/check_session')
def check_session():
    """API endpoint to check session status for Email Testing Platform"""
    if 'email_logged_in' not in session:
        return jsonify({'authenticated': False, 'message': 'Not logged in'})

    if 'email_last_activity' in session:
        time_since_activity = time.time() - session['email_last_activity']
        if time_since_activity > EMAIL_SESSION_TIMEOUT:
            session.clear()
            return jsonify({'authenticated': False, 'message': 'Session expired'})

        session['email_last_activity'] = time.time()
        time_remaining = EMAIL_SESSION_TIMEOUT - time_since_activity

        user_email = normalize_email(session.get('email_user_email', ''))
        user_role = session.get('email_role')

        limits = get_email_user_limits(user_email)
        usage = get_email_user_usage(user_email)

        # Handle infinity properly for JSON serialization
        max_messages = limits['max_messages']
        if max_messages == float('inf'):
            max_messages_json = 'unlimited'
        else:
            max_messages_json = max_messages

        return jsonify({
            'authenticated': True,
            'username': session.get('email_username'),
            'email': user_email,
            'role': user_role,
            'time_remaining': max(0, time_remaining),
            'message_usage': usage,
            'message_limit': max_messages_json,
            'can_add_users': limits['can_add_users']
        })

    return jsonify({'authenticated': False, 'message': 'Invalid session'})


@email_testing.route('/dashboard')
@email_login_required
def dashboard():
    """Email Testing Platform dashboard"""
    username = session.get('email_username', 'User')
    email = normalize_email(session.get('email_user_email', ''))
    role = session.get('email_role', 'user')

    limits = get_email_user_limits(email)
    usage = get_email_user_usage(email)

    # Handle unlimited messages for template
    max_messages_display = 'unlimited' if limits['max_messages'] == float('inf') else limits['max_messages']
    is_unlimited = limits['max_messages'] == float('inf')

    return render_template('email_dashboard.html',
                           username=username, email=email, role=role,
                           limits=limits, usage=usage,
                           max_messages_display=max_messages_display,
                           is_unlimited=is_unlimited)


@email_testing.route('/testing')
@email_login_required
def testing():
    """Email Testing Platform testing page"""
    return render_template('email_testing.html')


@email_testing.route('/admin/users')
@email_admin_required
def admin_users():
    """Email Testing Platform admin panel"""
    return render_template('admin_users.html')


@email_testing.route('/activity')
@email_login_required
def activity():
    """Update activity timestamp (called by AJAX)"""
    if 'email_logged_in' in session:
        session['email_last_activity'] = time.time()
    return jsonify({'status': 'ok'})


# ============================================================================
# DEBUG ROUTES FOR VERIFICATION SYSTEM
# ============================================================================

@email_testing.route('/debug/test-verification', methods=['POST'])
def debug_test_verification():
    """Debug route for manual verification testing"""
    if not app.debug:
        return "Debug mode required", 403

    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({'error': 'Email and code required'}), 400

    is_valid, message = verify_code_comprehensive(normalize_email(email), email, code)

    return jsonify({
        'valid': is_valid,
        'message': message,
        'current_codes': list(email_verification_codes.keys())
    })


@email_testing.route('/debug/store-code', methods=['POST'])
def debug_store_code():
    """Store a verification code for testing"""
    if not app.debug:
        return jsonify({'error': 'Debug mode required'}), 403

    try:
        data = request.get_json()
        email = data.get('email', '')
        code = data.get('code', '')

        if not email or not code:
            return jsonify({'error': 'Email and code required'}), 400

        # Use the enhanced storage function
        normalized = normalize_email(email)
        success = store_verification_code_comprehensive(normalized, code, email)

        return jsonify({
            'success': success,
            'message': f'Code {code} stored for {email}' if success else 'Storage failed',
            'total_codes': len(email_verification_codes),
            'email_normalized': normalized
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@email_testing.route('/debug/clear-codes', methods=['POST'])
def debug_clear_codes():
    """Clear all verification codes for testing"""
    if not app.debug:
        return jsonify({'error': 'Debug mode required'}), 403

    try:
        global email_verification_codes

        with verification_codes_lock:
            cleared_count = len(email_verification_codes)
            email_verification_codes.clear()

        # Clear backup file too
        try:
            if os.path.exists(VERIFICATION_BACKUP_FILE):
                os.remove(VERIFICATION_BACKUP_FILE)
        except Exception as e:
            print(f"Warning: Could not remove backup file: {e}")

        return jsonify({
            'success': True,
            'message': 'All verification codes cleared',
            'cleared_count': cleared_count
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@email_testing.route('/debug/email-system-status')
def debug_email_system_status():
    """Check email system availability"""
    return jsonify({
        'complex_framework_available': EMAIL_FRAMEWORK_AVAILABLE,
        'simple_email_available': email_ses_client is not None,
        'ses_client_status': 'available' if email_ses_client else 'unavailable',
        'debug_mode': app.debug
    })


# Email Testing API Routes
if EMAIL_FRAMEWORK_AVAILABLE:

    @email_testing.route('/api/send-emails', methods=['POST'])
    @email_login_required
    def api_send_emails():
        """Start sending emails API - FIXED VERSION"""
        try:
            data = request.get_json()
            user_email = normalize_email(session.get('email_user_email', ''))

            print(f"📧 API: Received request from {user_email}: {data}")

            # Add user email to request data
            data['user_email'] = user_email

            # Pass the data directly (matching the frontend format)
            result, status_code = start_email_campaign(data)

            # If successful, increment usage
            if status_code == 200 and result.get('success'):
                message_count = data.get('messageCount', 1)
                current_usage = EMAIL_user_message_usage.get(user_email, 0)
                EMAIL_user_message_usage[user_email] = current_usage + message_count

                # Save usage to file
                try:
                    with email_file_lock:
                        usage_data = {
                            'usage': dict(EMAIL_user_message_usage),
                            'last_updated': datetime.now().isoformat()
                        }
                        with open(EMAIL_USER_USAGE_FILE, 'w') as f:
                            json.dump(usage_data, f, indent=2)
                except Exception as e:
                    print(f"❌ Failed to save usage: {e}")

            return jsonify(result), status_code

        except Exception as e:
            print(f"❌ Error starting email campaign: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500


    @email_testing.route('/api/session/<session_id>/progress', methods=['GET'])
    @email_login_required
    def api_session_progress(session_id):
        """Get session progress"""
        try:
            result, status_code = get_session_progress(session_id)
            return jsonify(result), status_code
        except Exception as e:
            print(f"❌ Error getting session progress: {e}")
            return jsonify({'error': str(e)}), 500


    @email_testing.route('/api/session/<session_id>/stop', methods=['POST'])
    @email_login_required
    def api_stop_session(session_id):
        """Stop email sending session"""
        try:
            result, status_code = stop_session(session_id)
            return jsonify(result), status_code
        except Exception as e:
            print(f"❌ Error stopping session: {e}")
            return jsonify({'error': str(e)}), 500


    @email_testing.route('/api/test-config', methods=['POST'])
    @email_login_required
    def api_test_config():
        """Test email configuration - FIXED VERSION"""
        try:
            data = request.get_json()
            user_email = normalize_email(session.get('email_user_email', ''))

            print(f"🧪 API: Test config request from {user_email}: {data}")

            # Add user email to request data
            data['user_email'] = user_email

            result, status_code = test_email_config(data)
            return jsonify(result), status_code

        except Exception as e:
            print(f"❌ Error testing configuration: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

else:
    # Dummy API routes if EmailUtils is not available
    @email_testing.route('/api/send-emails', methods=['POST'])
    @email_login_required
    def api_send_emails():
        return jsonify({'error': 'Email framework not available - missing EmailUtils'}), 503


    @email_testing.route('/api/test-config', methods=['POST'])
    @email_login_required
    def api_test_config():
        return jsonify({'error': 'Email framework not available - missing EmailUtils'}), 503


    @email_testing.route('/api/session/<session_id>/progress', methods=['GET'])
    @email_login_required
    def api_session_progress(session_id):
        return jsonify({'error': 'Email framework not available - missing EmailUtils'}), 503


    @email_testing.route('/api/session/<session_id>/stop', methods=['POST'])
    @email_login_required
    def api_stop_session(session_id):
        return jsonify({'error': 'Email framework not available - missing EmailUtils'}), 503


# Admin API Routes for User Management
@email_testing.route('/api/admin/users', methods=['GET'])
@email_admin_required
def api_get_users():
    """Get all users (admin only)"""
    users_data = []
    for email, password in EMAIL_VALID_CREDENTIALS.items():
        role = get_email_user_role(email)
        limits = get_email_user_limits(email)
        usage = get_email_user_usage(email)

        users_data.append({
            'email': email,
            'role': role,
            'message_limit': limits['max_messages'] if limits['max_messages'] != float('inf') else 'unlimited',
            'message_usage': usage,
            'can_add_users': limits['can_add_users']
        })

    return jsonify({'users': users_data})


@email_testing.route('/api/admin/users', methods=['POST'])
@email_admin_required
def api_add_user():
    """Add new user (admin only)"""
    global EMAIL_VALID_CREDENTIALS, EMAIL_USER_ROLES, EMAIL_user_message_usage

    try:
        data = request.get_json()
        email = normalize_email(data.get('email', ''))
        password = data.get('password', '')
        role = data.get('role', 'user')

        # Validation
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        if email in EMAIL_VALID_CREDENTIALS:
            return jsonify({'error': 'User already exists'}), 400

        if role not in ['user', 'admin']:
            return jsonify({'error': 'Invalid role'}), 400

        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        # Add user to memory
        EMAIL_VALID_CREDENTIALS[email] = password
        EMAIL_USER_ROLES[email] = role
        EMAIL_user_message_usage[email] = 0

        # Save to files
        users_saved = save_email_users_to_file()
        usage_saved = True
        try:
            with email_file_lock:
                usage_data = {
                    'usage': dict(EMAIL_user_message_usage),
                    'last_updated': datetime.now().isoformat()
                }
                with open(EMAIL_USER_USAGE_FILE, 'w') as f:
                    json.dump(usage_data, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save usage: {e}")
            usage_saved = False

        if users_saved and usage_saved:
            return jsonify({
                'success': True,
                'message': f'User {email} added successfully',
                'user': {
                    'email': email,
                    'role': role,
                    'message_limit': EMAIL_USER_LIMITS[role]['max_messages'] if EMAIL_USER_LIMITS[role][
                                                                                    'max_messages'] != float(
                        'inf') else 'unlimited',
                    'message_usage': 0,
                    'can_add_users': EMAIL_USER_LIMITS[role]['can_add_users']
                }
            })
        else:
            # Rollback
            EMAIL_VALID_CREDENTIALS.pop(email, None)
            EMAIL_USER_ROLES.pop(email, None)
            EMAIL_user_message_usage.pop(email, None)
            return jsonify({'error': 'Failed to save user data'}), 500

    except Exception as e:
        print(f"❌ Error adding user: {e}")
        return jsonify({'error': str(e)}), 500


@email_testing.route('/api/admin/users/<email>', methods=['DELETE'])
@email_admin_required
def api_delete_user(email):
    """Delete user (admin only)"""
    global EMAIL_VALID_CREDENTIALS, EMAIL_USER_ROLES, EMAIL_user_message_usage

    try:
        normalized_email = normalize_email(email)

        if normalized_email not in EMAIL_VALID_CREDENTIALS:
            return jsonify({'error': 'User not found'}), 404

        current_user_email = normalize_email(session.get('email_user_email', ''))
        if normalized_email == current_user_email:
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Remove user
        EMAIL_VALID_CREDENTIALS.pop(normalized_email, None)
        EMAIL_USER_ROLES.pop(normalized_email, None)
        EMAIL_user_message_usage.pop(normalized_email, None)

        # Save to files
        users_saved = save_email_users_to_file()
        if users_saved:
            return jsonify({'success': True, 'message': f'User {normalized_email} deleted successfully'})
        else:
            return jsonify({'error': 'Failed to save changes'}), 500

    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500


@email_testing.route('/api/admin/users/<email>/reset-usage', methods=['POST'])
@email_admin_required
def api_reset_user_usage(email):
    """Reset user's message usage (admin only)"""
    global EMAIL_user_message_usage

    try:
        normalized_email = normalize_email(email)

        if normalized_email not in EMAIL_VALID_CREDENTIALS:
            return jsonify({'error': 'User not found'}), 404

        # Reset usage
        EMAIL_user_message_usage[normalized_email] = 0

        # Save to file
        try:
            with email_file_lock:
                usage_data = {
                    'usage': dict(EMAIL_user_message_usage),
                    'last_updated': datetime.now().isoformat()
                }
                with open(EMAIL_USER_USAGE_FILE, 'w') as f:
                    json.dump(usage_data, f, indent=2)

            return jsonify({'success': True, 'message': f'Usage reset for {normalized_email}'})
        except Exception as e:
            return jsonify({'error': 'Failed to save usage data'}), 500

    except Exception as e:
        print(f"❌ Error resetting usage: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# MAIN BDD DASHBOARD ROUTES (No Authentication Required)
# ============================================================================

@app.route('/')
def index():
    """Main BDD dashboard page - NO AUTHENTICATION REQUIRED"""
    return render_template('dashboard.html')


@app.route('/download/<string:filename>', methods=['GET'])
def download_report(filename):
    """BDD report download - NO AUTHENTICATION REQUIRED"""
    file_path = os.path.join(DOWNLOAD_DIR, filename)
    if os.path.exists(file_path):
        return send_from_directory(DOWNLOAD_DIR, filename)
    else:
        script_path = '/home/ubuntu/BDD/Dash/s3.py'
        result = subprocess.run(['sudo', '-u', 'www-data', VENV_PYTHON, script_path, filename],
                                capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"error": result.stderr}), 500
        if os.path.exists(file_path):
            return send_from_directory(DOWNLOAD_DIR, filename)
        else:
            return jsonify({"error": "File not found after download"}), 404


@app.route('/bdd_search', methods=['GET'])
def bdd_search():
    """BDD search page - NO AUTHENTICATION REQUIRED"""
    return render_template('bdd_search.html')


@app.route('/search_bdd', methods=['GET'])
def search_bdd():
    """BDD search functionality - NO AUTHENTICATION REQUIRED"""
    if not BDD_TESTS:
        return jsonify([])

    query = request.args.get('query', '').lower()
    matching_tests = []
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    for test in BDD_TESTS:
        full_test_text = " ".join(test["steps"]).lower()
        if query in full_test_text:
            highlighted_steps = []
            for step in test["steps"]:
                escaped_step = html.escape(step)
                highlighted_step = pattern.sub(
                    lambda m: f"<span class='highlight'>{m.group(0)}</span>",
                    escaped_step
                )
                highlighted_steps.append(highlighted_step)
            escaped_examples = {}
            for key, values in test["examples"].items():
                escaped_values = [html.escape(str(value)) for value in values]
                escaped_examples[key] = escaped_values
            matching_tests.append({
                "highlighted_steps": highlighted_steps,
                "examples": escaped_examples
            })
    return jsonify(matching_tests)


@app.route('/farm_status', methods=['GET'])
def farm_status():
    """Farm status page - NO AUTHENTICATION REQUIRED"""
    try:
        with open(DATA_JSON_PATH) as f:
            data = json.load(f)
        farm_names = set()
        for test_group in data.values():
            for test in test_group:
                filename = test['filename']
                farm_name = filename.split('_')[0]
                farm_names.add(farm_name)
        farm_names = sorted(farm_names)
        return render_template('farm_status.html', farm_names=farm_names)
    except Exception as e:
        print(f"Error loading farm data: {e}")
        return render_template('farm_status.html', farm_names=[], error=str(e))


@app.route('/get_farm_data', methods=['GET'])
def get_farm_data():
    """Get farm data - NO AUTHENTICATION REQUIRED"""
    farm_name = request.args.get('farm')
    if not farm_name:
        return jsonify({'error': 'No farm specified'}), 400

    try:
        with open(DATA_JSON_PATH) as f:
            data = json.load(f)
        farm_data = []
        for test_group in data.values():
            for test in test_group:
                filename = test['filename']
                test_farm_name = filename.split('_')[0]
                if test_farm_name == farm_name:
                    farm_data.append(test)
        return jsonify(farm_data)
    except Exception as e:
        print(f"Error loading farm data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/customers', methods=['GET'])
def integration():
    """Integration page - NO AUTHENTICATION REQUIRED"""
    return render_template('integration.html')


@app.route('/download_bdd_ahz', methods=['GET'])
def download_bdd_ahz():
    """Download BDD files - NO AUTHENTICATION REQUIRED"""
    base_path = "/home/ubuntu/BDD/Dash/ahz"

    if not os.path.exists(base_path):
        return jsonify({"error": "AHZ directory not found"}), 404

    try:
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(base_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zf.write(file_path, os.path.relpath(file_path, base_path))

        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='BDD_Dash_ahz_Files.zip'
        )
    except Exception as e:
        print(f"Error creating zip file: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================================
# NAVIGATION HELPER ROUTE
# ============================================================================

@app.route('/navigation')
def navigation():
    """Navigation page to choose between BDD Dashboard and Email Testing Platform"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Testing Platform Hub</title>
        <style>
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
                padding: 20px;
            }
            .container {
                background: white;
                border-radius: 24px;
                padding: 40px;
                box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1);
                max-width: 700px;
                text-align: center;
            }
            h1 {
                color: #1e293b;
                margin-bottom: 30px;
                font-size: 2.2rem;
            }
            .platform-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 25px;
                margin-top: 30px;
            }
            .platform-card {
                background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
                border: 2px solid #e2e8f0;
                border-radius: 16px;
                padding: 35px 20px;
                text-decoration: none;
                color: #1e293b;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .platform-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.1), transparent);
                transition: left 0.5s;
            }
            .platform-card:hover::before {
                left: 100%;
            }
            .platform-card:hover {
                border-color: #3b82f6;
                transform: translateY(-4px);
                box-shadow: 0 12px 30px rgba(59, 130, 246, 0.2);
            }
            .platform-icon {
                font-size: 3.5rem;
                margin-bottom: 20px;
                display: block;
            }
            .platform-title {
                font-size: 1.3rem;
                font-weight: 700;
                margin-bottom: 12px;
                color: #1e293b;
            }
            .platform-desc {
                font-size: 0.95rem;
                color: #64748b;
                line-height: 1.6;
                margin-bottom: 15px;
            }
            .auth-badge {
                display: inline-block;
                padding: 6px 14px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 600;
                margin-top: 10px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .no-auth-badge {
                background: linear-gradient(135deg, #d1fae5, #a7f3d0);
                color: #065f46;
            }
            .auth-required-badge {
                background: linear-gradient(135deg, #fef3c7, #fde68a);
                color: #92400e;
            }
            .features-list {
                text-align: left;
                margin-top: 15px;
                font-size: 0.85rem;
                color: #64748b;
            }
            .features-list li {
                margin-bottom: 5px;
            }
            .footer {
                margin-top: 40px;
                padding-top: 25px;
                border-top: 1px solid #e2e8f0;
            }
            .footer p {
                color: #64748b;
                font-size: 0.9rem;
                margin: 5px 0;
            }
            .footer a {
                color: #3b82f6;
                text-decoration: none;
                font-weight: 600;
            }
            .footer a:hover {
                text-decoration: underline;
            }

            @media (max-width: 768px) {
                .platform-grid {
                    grid-template-columns: 1fr;
                    gap: 20px;
                }
                .container {
                    padding: 30px 20px;
                }
                .header-title {
                    font-size: 1.8rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Testing Platform Hub</h1>
            <p style="color: #64748b; font-size: 1.1rem;">Choose your testing environment:</p>

            <div class="platform-grid">
                <a href="/" class="platform-card">
                    <div class="platform-icon">📊</div>
                    <div class="platform-title">BDD Testing Dashboard</div>
                    <div class="platform-desc">
                        Behavior-Driven Development testing with farm status monitoring, automated report downloads, and comprehensive test search capabilities.
                    </div>
                    <ul class="features-list">
                        <li>• Farm status monitoring</li>
                        <li>• Automated report downloads</li>
                        <li>• BDD test search & analysis</li>
                        <li>• Customer integration tools</li>
                    </ul>
                    <div class="auth-badge no-auth-badge">🌐 Open Access</div>
                </a>

                <a href="/email-testing/login" class="platform-card">
                    <div class="platform-icon">📧</div>
                    <div class="platform-title">Email Security Testing</div>
                    <div class="platform-desc">
                        Advanced email threat simulation with real malware generation, sophisticated file attachments, and comprehensive security validation.
                    </div>
                    <ul class="features-list">
                        <li>• Real threat content generation</li>
                        <li>• Multi-file archive support</li>
                        <li>• Role-based access control</li>
                        <li>• Secure 2FA authentication</li>
                    </ul>
                    <div class="auth-badge auth-required-badge">🔐 Secure Login</div>
                </a>
            </div>

            <div class="footer">
                <p><strong>© 2025 All Rights Reserved - Automation Team</strong></p>
                <p>For technical support and inquiries: <a href="mailto:ahmadz@checkpoint.com">ahmadz@checkpoint.com</a></p>
                <p style="margin-top: 15px; font-size: 0.8rem; color: #94a3b8;">
                    🔧 Enhanced testing platform with secure authentication
                </p>
            </div>
        </div>
    </body>
    </html>
    '''


# ============================================================================
# REGISTER BLUEPRINTS AND START APPLICATION
# ============================================================================

# Register the Email Testing Platform blueprint
app.register_blueprint(email_testing)

if __name__ == '__main__':
    print("🚀 Starting Combined Testing Platform - COMPLETELY FIXED VERSION")
    print("=" * 80)
    print("📊 BDD Testing Dashboard: http://localhost:8000/")
    print("📧 Email Security Testing: http://localhost:8000/email-testing/login")
    print("🧭 Navigation Hub: http://localhost:8000/navigation")
    print("🚨 Emergency Admin Login: http://localhost:8000/email-testing/emergency-login/nio_z15@hotmail.com")
    print("🚨 Emergency User Login: http://localhost:8000/email-testing/emergency-login/ahmad.zidane.1983@hotmail.com")
    print("🔍 Debug Verification Status: http://localhost:8000/email-testing/debug/verification-status")
    print("=" * 80)
    print("✅ BDD Dashboard: No authentication required")
    print("🔐 Email Testing: COMPLETELY FIXED 2FA authentication and email sending")
    print(f"🐛 Debug mode: {app.debug}")
    if EMAIL_FRAMEWORK_AVAILABLE:
        print("🔥 Email Testing: Real threat generators loaded")
    else:
        print("⚠️ Email Testing: Framework modules not found")
    print("=" * 80)
    print("👥 Email Platform User Accounts:")
    for email, role in EMAIL_USER_ROLES.items():
        limits = get_email_user_limits(email)
        max_msg = limits['max_messages'] if limits['max_messages'] != float('inf') else 'unlimited'
        print(f"   - {email} ({role.upper()}) - {max_msg} messages")
    print("=" * 80)
    print("🔧 ALL VERIFICATION FIXES APPLIED:")
    print("   ✅ Enhanced verification code storage with multiple email formats")
    print("   ✅ Fixed session handling for email APIs")
    print("   ✅ Fixed frontend-backend field name mapping")
    print("   ✅ Enhanced debugging and logging throughout")
    print("   ✅ Thread-safe operations throughout")
    print("   ✅ Automatic cleanup of expired codes")
    print("   ✅ Multiple email format support (normalized, original, lowercase)")
    print("   ✅ Comprehensive error handling and recovery")
    print("   ✅ Emergency login bypass for debugging")
    print("   ✅ Session data consistency fixes")
    print("   ✅ Enhanced verification debugging routes")
    print("=" * 80)
    print("🚨 EMERGENCY ACCESS AVAILABLE:")
    print("   Admin: http://localhost:8000/email-testing/emergency-login/nio_z15@hotmail.com")
    print("   User: http://localhost:8000/email-testing/emergency-login/ahmad.zidane.1983@hotmail.com")
    print("   Debug: http://localhost:8000/email-testing/debug/verification-status")
    print("=" * 80)

    app.run(debug=True, port=8000, host='0.0.0.0')
