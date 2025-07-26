import threading
import time
import smtplib
import ssl
import uuid
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from email_security_framework import Email, Sender, RecipientsList, Attachment

EMAIL_FRAMEWORK_AVAILABLE = True
import json
import os
from typing import Dict, List, Any, Optional
from flask import session

# aws dummy Configuration
AWS_SES_CONFIG = {
    'aws_access_key_id': 'test_access_key',
    'aws_secret_access_key': 'test_secret',
    'region_name': 'test_region'
}


# Provider configurations for DLP (SMTP-based)
PROVIDER_CONFIGS = {
    'microsoft': {
        'smtp_server': 'smtp.office365.com',
        'smtp_port': 587
    },
    'google': {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587
    }
}

# Global session storage
active_email_sessions = {}
session_lock = threading.Lock()

# USER MANAGEMENT - File paths and configuration (same as app.py)
USERS_FILE = 'users.json'
USER_USAGE_FILE = 'user_usage.json'

# User limits configuration (same as in app.py)
USER_LIMITS = {
    'admin': {'max_messages': float('inf'), 'can_add_users': True},
    'user': {'max_messages': 10, 'can_add_users': False}
}


def normalize_email_local(email):
    """Local email normalization function (same logic as app.py)"""
    if not email:
        return ""
    return email.strip().lower()


def load_user_data_local():
    """Load user data from files - LOCAL VERSION (same logic as app.py)"""
    try:
        users = {}
        roles = {}
        usage = {}

        # Load users and roles
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                data = json.load(f)
                for email, password in data.get('credentials', {}).items():
                    normalized_email = normalize_email_local(email)
                    users[normalized_email] = password

                for email, role in data.get('roles', {}).items():
                    normalized_email = normalize_email_local(email)
                    roles[normalized_email] = role

        # Load usage
        if os.path.exists(USER_USAGE_FILE):
            with open(USER_USAGE_FILE, 'r') as f:
                data = json.load(f)
                for email, user_usage in data.get('usage', {}).items():
                    normalized_email = normalize_email_local(email)
                    usage[normalized_email] = user_usage

        print(f"📊 EmailUtils loaded user data: {len(users)} users, {len(roles)} roles, {len(usage)} usage records")
        return users, roles, usage

    except Exception as e:
        print(f"❌ EmailUtils error loading user data: {e}")
        return {}, {}, {}


def get_user_role_local(email):
    """Get user role - LOCAL VERSION (same logic as app.py)"""
    if not email:
        return 'user'

    normalized_email = normalize_email_local(email)
    users, roles, usage = load_user_data_local()

    role = roles.get(normalized_email, 'user')
    print(f"🔍 EmailUtils get_user_role_local: {normalized_email} -> {role}")
    return role


def get_user_limits_local(email):
    """Get user limits - LOCAL VERSION (same logic as app.py)"""
    if not email:
        return USER_LIMITS['user']

    role = get_user_role_local(email)
    limits = USER_LIMITS.get(role, USER_LIMITS['user'])
    print(f"🔍 EmailUtils get_user_limits_local: {email} -> role: {role}, limits: {limits}")
    return limits


def get_user_usage_local(email):
    """Get user usage - LOCAL VERSION (same logic as app.py)"""
    if not email:
        return 0

    normalized_email = normalize_email_local(email)
    users, roles, usage = load_user_data_local()

    current_usage = usage.get(normalized_email, 0)
    print(f"🔍 EmailUtils get_user_usage_local: {normalized_email} -> {current_usage}")
    return current_usage


def can_send_messages_local(email, count):
    """Check if user can send messages - LOCAL VERSION WITH FULL DEBUG (same logic as app.py)"""
    if not email:
        print(f"❌ EmailUtils can_send_messages_local: Empty email provided")
        return False, "Invalid user email"

    normalized_email = normalize_email_local(email)
    print(
        f"🔍 EmailUtils can_send_messages_local: Checking '{email}' (normalized: '{normalized_email}') for {count} messages")

    try:
        limits = get_user_limits_local(normalized_email)
        current_usage = get_user_usage_local(normalized_email)

        print(f"🔍 EmailUtils can_send_messages_local FULL CHECK:")
        print(f"   Email: {email}")
        print(f"   Normalized email: {normalized_email}")
        print(f"   Requested count: {count}")
        print(f"   Current usage: {current_usage}")
        print(f"   Limits object: {limits}")
        print(f"   Max messages: {limits.get('max_messages', 'MISSING')}")
        print(f"   Max is infinite: {limits.get('max_messages') == float('inf')}")

        max_messages = limits.get('max_messages', 0)

        # Safety check for infinite limits (admin users)
        if max_messages == float('inf'):
            print(f"✅ EmailUtils can_send_messages_local: Unlimited messages for admin user")
            return True, "Unlimited messages for admin users"

        # Check if user can send the requested number of messages
        if current_usage + count > max_messages:
            remaining = max(0, max_messages - current_usage)
            error_msg = f"Message limit exceeded. You can send {remaining} more messages (limit: {max_messages})"
            print(f"❌ EmailUtils can_send_messages_local: {error_msg}")
            return False, error_msg

        success_msg = f"You can send {count} messages. Current usage: {current_usage}/{max_messages}"
        print(f"✅ EmailUtils can_send_messages_local: {success_msg}")
        return True, success_msg

    except Exception as e:
        error_msg = f"Error checking message limits: {str(e)}"
        print(f"❌ EmailUtils can_send_messages_local: Exception occurred: {error_msg}")
        import traceback
        traceback.print_exc()
        return False, error_msg


def get_current_user_email_local():
    """Get current user email from Flask session - LOCAL VERSION"""
    try:
        user_email = session.get('email_user_email', '')  # Use correct session key
        normalized_email = normalize_email_local(user_email)
        print(f"🔍 EmailUtils get_current_user_email_local: '{user_email}' -> '{normalized_email}'")

        if not normalized_email:
            print(f"❌ EmailUtils get_current_user_email_local: No email in session")
            print(f"   Available session keys: {list(session.keys())}")
            return None

        return normalized_email
    except Exception as e:
        print(f"❌ EmailUtils get_current_user_email_local error: {e}")
        return None


@dataclass
class EmailSession:
    """Enhanced email session tracking with DLP support"""

    def __init__(self, session_id: str, total_emails: int):
        self.session_id = session_id
        self.total_emails = total_emails
        self.sent_emails = 0
        self.failed_emails = 0
        self.start_time = time.time()
        self.is_stopped = False
        self.logs = []
        self.lock = threading.Lock()
        self.dlp_type = None  # Track DLP testing type

    def add_log(self, level: str, message: str):
        """Add log entry with enhanced formatting"""
        with self.lock:
            log_entry = {
                'timestamp': time.time(),
                'level': level,
                'message': message
            }
            self.logs.append(log_entry)

            # Enhanced console logging
            if self.dlp_type:
                prefix = f"[{self.dlp_type.upper()} DLP]"
            else:
                prefix = ""

            print(f"Email Session {self.session_id} {prefix}: {message}")

    def set_dlp_type(self, dlp_type):
        """Set DLP testing type"""
        self.dlp_type = dlp_type
        if dlp_type:
            self.add_log('info', f'DLP Testing Mode: {dlp_type.upper()}')

    def update_progress(self, sent: int = None, failed: int = None):
        """Update counters"""
        with self.lock:
            if sent is not None:
                self.sent_emails += sent
            if failed is not None:
                self.failed_emails += failed

    def get_progress(self):
        """Get progress info"""
        with self.lock:
            elapsed_time = time.time() - self.start_time
            completed = self.sent_emails + self.failed_emails
            progress_percent = (completed / self.total_emails * 100) if self.total_emails > 0 else 0

            return {
                'session_id': self.session_id,
                'total_emails': self.total_emails,
                'sent_emails': self.sent_emails,
                'failed_emails': self.failed_emails,
                'progress_percent': progress_percent,
                'elapsed_time': elapsed_time,
                'is_stopped': self.is_stopped,
                'logs': self.logs[-50:],  # Last 50 logs
                'dlp_type': self.dlp_type
            }

    def stop(self):
        """Stop session"""
        with self.lock:
            self.is_stopped = True
            self.add_log('info', 'Session stopped by user')


class SimpleEmailSender:
    """Enhanced email sender with DLP direction support"""

    def __init__(self):
        # Initialize boto3 SES client
        self.ses_client = boto3.client(
            'ses',
            aws_access_key_id=AWS_SES_CONFIG['aws_access_key_id'],
            aws_secret_access_key=AWS_SES_CONFIG['aws_secret_access_key'],
            region_name=AWS_SES_CONFIG['region_name']
        )

    def send_email_ses(self, email_obj, recipients):
        """Send email using boto3 SES - COMPLETELY FIXED VERSION"""
        try:
            # Get sender from email object
            sender = email_obj.sender.address

            # Initialize response variable at the start
            response = None
            successful_sends = 0
            failed_recipients = []

            print(f"📧 SES: Starting email send process")
            print(f"📤 Sender: {sender}")
            print(f"📮 Recipients: {recipients}")

            # Validate recipients first
            if not recipients:
                print("❌ SES: No recipients provided")
                return {
                    'success': False,
                    'error': 'No recipients provided',
                    'message_id': None,
                    'recipients_sent': 0,
                    'failed_recipients': []
                }

            if not isinstance(recipients, (list, tuple)):
                print(f"❌ SES: Invalid recipients format: {type(recipients)}")
                return {
                    'success': False,
                    'error': f'Recipients must be a list, got {type(recipients)}',
                    'message_id': None,
                    'recipients_sent': 0,
                    'failed_recipients': []
                }

            print(f"📧 SES: Sending to {len(recipients)} recipients")

            # Send to each recipient with individual error handling
            for i, recipient in enumerate(recipients, 1):
                try:
                    if not recipient or not isinstance(recipient, str):
                        print(f"❌ SES: Invalid recipient #{i}: {recipient}")
                        failed_recipients.append(str(recipient))
                        continue

                    print(f"📤 SES: Sending to recipient #{i}: {recipient}")

                    # Attempt to send
                    response = self.ses_client.send_raw_email(
                        Source=sender,
                        Destinations=[recipient],
                        RawMessage={'Data': email_obj.as_string()}
                    )

                    message_id = response.get('MessageId', 'unknown')
                    print(f"✅ SES: Success for {recipient} - MessageId: {message_id}")
                    successful_sends += 1

                except Exception as recipient_error:
                    print(f"❌ SES: Failed to send to {recipient}: {str(recipient_error)}")
                    failed_recipients.append(recipient)
                    continue

            # Handle results based on what actually happened
            print(f"📊 SES: Results - Success: {successful_sends}, Failed: {len(failed_recipients)}")

            if successful_sends > 0:
                # At least one email sent successfully
                final_message_id = response.get('MessageId', 'unknown') if response else f'batch_{uuid.uuid4().hex[:8]}'

                return {
                    'success': True,
                    'message_id': final_message_id,
                    'recipients_sent': successful_sends,
                    'failed_recipients': failed_recipients,
                    'total_attempted': len(recipients)
                }
            else:
                # All sends failed
                return {
                    'success': False,
                    'error': f'Failed to send to all {len(recipients)} recipients',
                    'message_id': None,
                    'recipients_sent': 0,
                    'failed_recipients': failed_recipients,
                    'total_attempted': len(recipients)
                }

        except Exception as e:
            print(f"❌ SES: Critical error during send process: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'message_id': getattr(email_obj, 'message_id', None),
                'recipients_sent': 0,
                'failed_recipients': recipients if isinstance(recipients, list) else [],
                'total_attempted': len(recipients) if isinstance(recipients, list) else 0
            }

    def send_email_dlp(self, email_obj, recipients, sender_email, sender_password, provider):
        """Send email using DLP provider (SMTP-based) - ENHANCED with better error handling"""
        try:
            config = PROVIDER_CONFIGS.get(provider)
            if not config:
                raise ValueError(f"Unsupported provider: {provider}")

            print(f"🔗 Connecting to {provider} SMTP: {config['smtp_server']}:{config['smtp_port']}")

            # Create SSL context with better compatibility for Microsoft 365
            if provider == 'microsoft':
                # Microsoft 365 specific SSL context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                print("🔒 Using relaxed SSL context for Microsoft 365")
            else:
                # Google and other providers
                context = ssl.create_default_context()
                print("🔒 Using default SSL context")

            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                print("📡 SMTP connection established")

                # Enable debug output for troubleshooting
                server.set_debuglevel(1)

                print("🔐 Starting TLS...")
                server.starttls(context=context)
                print("✅ TLS established")

                print(f"🔑 Authenticating as {sender_email}...")
                server.login(sender_email, sender_password)
                print("✅ Authentication successful")

                # Update sender in email object
                email_obj['From'] = sender_email

                print(f"📧 Sending to {len(recipients)} recipients...")
                text = email_obj.as_string()
                result = server.sendmail(sender_email, recipients, text)
                print("✅ Email sent successfully via DLP provider")

                return {
                    'success': True,
                    'message_id': getattr(email_obj, 'message_id', 'unknown'),
                    'recipients_sent': len(recipients),
                    'failed_recipients': list(result.keys()) if result else [],
                    'provider': provider
                }

        except smtplib.SMTPAuthenticationError as e:
            error_code = str(e)
            error_msg = f"SMTP Authentication failed for {sender_email}"

            # Provide specific solutions based on error codes
            if "5.7.139" in error_code and "SmtpClientAuthentication is disabled for the Tenant" in error_code:
                solution = "Your organization has disabled SMTP authentication. Contact IT admin to enable SMTP for your tenant or use Incoming DLP testing instead."
                tenant_smtp_disabled = True
            elif "535" in error_code:
                solution = "Use App Password instead of regular password. Go to Microsoft 365 Security > App passwords"
                tenant_smtp_disabled = False
            elif "534" in error_code:
                solution = "Account requires 2FA. Generate an App Password in your Microsoft account settings"
                tenant_smtp_disabled = False
            else:
                solution = "Check email/password or enable authenticated SMTP in mailbox settings"
                tenant_smtp_disabled = False

            full_error = f"{error_msg}: {error_code}. SOLUTION: {solution}"
            print(f"❌ {full_error}")

            return {
                'success': False,
                'error': full_error,
                'message_id': getattr(email_obj, 'message_id', None),
                'provider': provider,
                'tenant_smtp_disabled': tenant_smtp_disabled,
                'error_code': error_code
            }

        except smtplib.SMTPConnectError as e:
            error_msg = f"Cannot connect to {provider} SMTP server: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'message_id': getattr(email_obj, 'message_id', None),
                'provider': provider
            }

        except smtplib.SMTPRecipientsRefused as e:
            error_msg = f"Recipients refused by {provider}: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'message_id': getattr(email_obj, 'message_id', None),
                'provider': provider
            }

        except smtplib.SMTPException as e:
            error_msg = f"SMTP error with {provider}: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'message_id': getattr(email_obj, 'message_id', None),
                'provider': provider
            }

        except Exception as e:
            error_msg = f"Connection error to {provider}: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'message_id': getattr(email_obj, 'message_id', None),
                'provider': provider
            }


def create_email_from_config(email_config):
    """Create email object from config"""
    if not EMAIL_FRAMEWORK_AVAILABLE:
        raise Exception("Email framework not available")

    print(f"🔍 EmailUtils create_email_from_config: Creating email from config")
    print(f"📧 Config recipients: {email_config.get('recipients', {})}")

    # Build framework config
    framework_config = {
        'recipients': email_config['recipients']
    }

    # Add sender (use SES sender by default)
    if 'sender' in email_config and email_config['sender'].get('provider') in ['microsoft', 'google']:
        framework_config['sender'] = email_config['sender']
    else:
        # Use SES sender
        framework_config['sender'] = {
            'provider': 'ses',
            'address': 'eml_sender@avtestqa.com'
        }

    # Add content based on location
    if 'subject' in email_config:
        framework_config['subject'] = email_config['subject']
        print(f"📧 Using subject config: {framework_config['subject']}")
    elif 'body' in email_config:
        framework_config['body'] = email_config['body']
        print(f"📧 Using body config: {framework_config['body']}")
    elif 'attachments' in email_config:
        framework_config['attachments'] = email_config['attachments']
        print(f"📧 Using attachments config: {framework_config['attachments']}")

    # Determine WD type
    wd_type = 'ses'
    if email_config.get('sender', {}).get('provider') in ['microsoft', 'google']:
        wd_type = 's3'

    print(f"🔍 Creating Email object with wd_type: {wd_type}")

    # Create email
    email_obj = Email(framework_config, wd_type=wd_type)

    print(f"✅ Email object created successfully")
    print(f"📧 Subject: {email_obj.subject}")
    print(f"📤 Sender: {email_obj.sender.address}")

    return email_obj


def extract_recipients(email_config):
    """Extract all recipients - FIXED VERSION"""
    recipients = []

    print(f"🔍 EmailUtils extract_recipients: Processing config")
    print(f"📧 Recipients config: {email_config.get('recipients', {})}")

    try:
        for recipient_type in ['to', 'cc', 'bcc']:
            if 'recipients' in email_config and recipient_type in email_config['recipients']:
                type_recipients = email_config['recipients'][recipient_type]
                print(f"📮 Found {len(type_recipients)} {recipient_type.upper()} recipients")

                for recipient_obj in type_recipients:
                    if isinstance(recipient_obj, dict) and 'address' in recipient_obj:
                        address = recipient_obj['address'].strip()
                        if address:  # Only add non-empty addresses
                            recipients.append(address)
                            print(f"✅ Added recipient: {address}")
                    else:
                        print(f"⚠️ Invalid recipient object: {recipient_obj}")

        # Remove duplicates while preserving order
        unique_recipients = []
        seen = set()
        for recipient in recipients:
            if recipient not in seen:
                unique_recipients.append(recipient)
                seen.add(recipient)

        print(f"📊 Final recipients list: {len(unique_recipients)} unique recipients")
        print(f"📮 Recipients: {unique_recipients}")

        return unique_recipients

    except Exception as e:
        print(f"❌ Error extracting recipients: {e}")
        import traceback
        traceback.print_exc()
        return []


def build_email_config(form_data):
    """Build email config from form data - ENHANCED with DLP direction support"""
    print(f"🔍 EmailUtils build_email_config: Building config from form data")
    print(f"📧 To Recipients: {form_data.get('toRecipients', 'MISSING')}")

    config = {
        'recipients': {
            'to': [{'mode': 'external', 'address': addr.strip()}
                   for addr in form_data['toRecipients'].split(',') if addr.strip()]
        }
    }

    print(f"📮 Built TO recipients: {config['recipients']['to']}")

    # Add CC/BCC
    if form_data.get('ccRecipients'):
        config['recipients']['cc'] = [
            {'mode': 'external', 'address': addr.strip()}
            for addr in form_data['ccRecipients'].split(',') if addr.strip()
        ]
        print(f"📮 Built CC recipients: {config['recipients']['cc']}")

    if form_data.get('bccRecipients'):
        config['recipients']['bcc'] = [
            {'mode': 'external', 'address': addr.strip()}
            for addr in form_data['bccRecipients'].split(',') if addr.strip()
        ]
        print(f"📮 Built BCC recipients: {config['recipients']['bcc']}")

    # Configure sender based on threat type and DLP direction
    threat_type = form_data['threatType']
    content_type = form_data.get('contentType', 'dummy')
    dlp_direction = form_data.get('dlpDirection', 'incoming')  # Default to incoming

    if threat_type == 'dlp':
        if dlp_direction == 'outgoing':
            # Outgoing DLP: MUST use organizational SMTP
            config['sender'] = {
                'provider': form_data['dlpProvider'],
                'address': form_data['dlpSenderEmail'],
                'credentials': {'password': form_data['dlpSenderPassword']}
            }
            config['dlp_type'] = 'outgoing'
            print(f"🔄 Outgoing DLP: Using organizational SMTP {form_data['dlpSenderEmail']}")

        else:
            # Incoming DLP: Use SES to simulate external threats
            config['sender'] = {'provider': 'ses'}
            config['dlp_type'] = 'incoming'
            print(f"📧 Incoming DLP: Using SES to simulate external threat")
    else:
        # Non-DLP threats: Use SES
        config['sender'] = {'provider': 'ses'}
        print(f"📧 Using SES for {threat_type} testing")

    # Configure threat content
    attachment_mode = form_data.get('attachmentMode', 'single')

    # Debug logging
    print(f"🔍 EmailUtils Debug:")
    print(f"   Threat Type: {threat_type}")
    print(f"   Content Type: {content_type}")
    print(f"   Location: {form_data['threatLocation']}")
    print(f"   DLP Direction: {dlp_direction}")
    print(f"   Attachment Mode: {attachment_mode}")

    if form_data['threatLocation'] == 'subject':
        # Format correctly for SubjectDataGenerator: "threattype:subject_contenttype"
        config['subject'] = f"{threat_type}:subject_{content_type}"
        print(f"📧 Subject config (FIXED FORMAT): {config['subject']}")
    elif form_data['threatLocation'] == 'body':
        config['body'] = f"{threat_type}:{content_type}"
        print(f"📧 Body config: {config['body']}")
    elif form_data['threatLocation'] == 'attachment':
        if attachment_mode == 'single':
            # Single file attachment
            attachment_config = {
                content_type: form_data['fileType'],
                'location': 'center'
            }

            if form_data.get('encryptFile', False):
                attachment_config['encrypt'] = True
                print(f"🔐 Encryption enabled for attachment")

            if form_data.get('compressFile', False):
                compression_type = form_data.get('compressionType', 'zip')
                attachment_config['compression'] = compression_type
                print(f"🗜️ Compression enabled: {compression_type}")

            if threat_type == 'ctp':
                config['attachments'] = [{'clean': attachment_config}]
            else:
                config['attachments'] = [{threat_type: attachment_config}]

            print(f"📎 Single Attachment config: {config['attachments']}")
        else:
            # Multiple files attachment
            files_data = form_data.get('filesData', [])
            compress_all = form_data.get('compressAllFiles', False)
            global_compression = form_data.get('globalCompressionType', 'zip')
            encrypt_final = form_data.get('encryptFinalArchive', False)

            print(f"📁 Multiple files mode:")
            print(f"   Files count: {len(files_data)}")
            print(f"   Compress all: {compress_all}")
            print(f"   Global compression: {global_compression}")
            print(f"   Encrypt final: {encrypt_final}")

            if compress_all:
                # All files in one archive
                individual_files = []
                for file_data in files_data:
                    file_config = {
                        file_data['threatType']: {
                            file_data['contentType']: file_data['fileType'],
                            'location': 'center'
                        }
                    }
                    # Individual file encryption and compression are handled separately
                    if file_data.get('encrypt', False):
                        file_config[file_data['threatType']]['encrypt'] = True
                    if file_data.get('compress', False):
                        file_config[file_data['threatType']]['compression'] = file_data.get('compressionType', 'zip')

                    individual_files.append(file_config)

                # Create multi-file archive configuration
                config['attachments'] = {
                    'mode': 'multi_archive',
                    'files': individual_files,
                    'archive_compression': global_compression,
                    'encrypt_archive': encrypt_final
                }
            else:
                # Individual files
                config['attachments'] = []
                for file_data in files_data:
                    file_config = {
                        file_data['contentType']: file_data['fileType'],
                        'location': 'center'
                    }

                    if file_data.get('encrypt', False):
                        file_config['encrypt'] = True
                    if file_data.get('compress', False):
                        file_config['compression'] = file_data.get('compressionType', 'zip')

                    file_threat_type = file_data['threatType']
                    if file_threat_type == 'ctp':
                        config['attachments'].append({'clean': file_config})
                    else:
                        config['attachments'].append({file_threat_type: file_config})

            print(f"📎 Multiple files config: {config['attachments']}")

    print(f"✅ Final email config built successfully")
    return config


def send_single_email(email_config, email_number, session, sender):
    """Send single email - ENHANCED for DLP direction handling"""
    try:
        if session.is_stopped:
            return {'success': False, 'error': 'Session stopped'}

        session.add_log('info', f'Starting email {email_number}')

        # Check DLP type for logging
        dlp_type = email_config.get('dlp_type')
        if dlp_type:
            session.set_dlp_type(dlp_type)
            session.add_log('info', f'DLP Type: {dlp_type.upper()} DLP testing')

        print(f"📧 EmailUtils send_single_email: Processing email {email_number}")

        # Create email
        session.add_log('info', f'Creating email {email_number}')
        email_obj = create_email_from_config(email_config)

        # Extract recipients with validation
        session.add_log('info', f'Extracting recipients for email {email_number}')
        recipients = extract_recipients(email_config)

        if not recipients:
            error_msg = f"No valid recipients found for email {email_number}"
            session.add_log('error', error_msg)
            return {'success': False, 'error': error_msg}

        print(f"📮 Email {email_number}: Sending to {len(recipients)} recipients: {recipients}")

        # Send email based on sender configuration
        session.add_log('info', f'Sending email {email_number} to {len(recipients)} recipients')

        if email_config.get('sender', {}).get('provider') in ['microsoft', 'google']:
            # Outgoing DLP or other SMTP sending
            sender_email = email_config['sender']['address']
            sender_password = email_config['sender']['credentials']['password']
            provider = email_config['sender']['provider']

            if dlp_type == 'outgoing':
                session.add_log('info', f'Outgoing DLP: Sending via {provider} SMTP from {sender_email}')

            print(f"📧 Email {email_number}: Sending via {provider} SMTP")
            result = sender.send_email_dlp(
                email_obj, recipients, sender_email, sender_password, provider
            )

            # Enhanced error handling for outgoing DLP
            if not result['success'] and dlp_type == 'outgoing':
                if result.get('tenant_smtp_disabled'):
                    session.add_log('error', 'TENANT SMTP DISABLED: Organization blocks SMTP authentication')
                    session.add_log('info', 'Solution: Contact IT admin or use Incoming DLP testing instead')
                    result['dlp_suggestion'] = 'Use Incoming DLP testing as alternative'

        else:
            # Incoming DLP or SES sending
            if dlp_type == 'incoming':
                session.add_log('info', f'Incoming DLP: Sending via SES (simulating external threat)')

            print(f"📧 Email {email_number}: Sending via SES")
            result = sender.send_email_ses(email_obj, recipients)

        # Update session based on results
        if result['success']:
            session.update_progress(sent=1)
            success_msg = f'Email {email_number} sent successfully to {result.get("recipients_sent", len(recipients))} recipients'
            if result.get('failed_recipients'):
                success_msg += f' (failed: {len(result["failed_recipients"])})'

            if dlp_type:
                success_msg += f' [{dlp_type.upper()} DLP]'

            session.add_log('success', success_msg)
            print(f"✅ {success_msg}")
        else:
            session.update_progress(failed=1)
            error_msg = f'Email {email_number} failed: {result.get("error", "Unknown error")}'

            if dlp_type == 'outgoing' and result.get('tenant_smtp_disabled'):
                error_msg += ' [TENANT SMTP DISABLED]'

            session.add_log('error', error_msg)
            print(f"❌ {error_msg}")

        return result

    except Exception as e:
        error_msg = f'Email {email_number} failed with exception: {str(e)}'
        print(f"❌ EmailUtils send_single_email: {error_msg}")
        import traceback
        traceback.print_exc()

        session.update_progress(failed=1)
        session.add_log('error', error_msg)
        return {'success': False, 'error': str(e)}


def send_emails_worker(email_config, message_count, delay_between, enable_threading, thread_count, session):
    """Background worker to send emails"""
    sender = SimpleEmailSender()

    if enable_threading and message_count > 1:
        # Threaded sending
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            for i in range(message_count):
                if session.is_stopped:
                    break
                future = executor.submit(send_single_email, email_config, i + 1, session, sender)
                futures.append(future)

                if delay_between > 0:
                    time.sleep(delay_between / thread_count)

            # Wait for completion
            for future in as_completed(futures):
                if session.is_stopped:
                    break
                try:
                    future.result(timeout=30)
                except Exception as e:
                    session.add_log('error', f'Future failed: {str(e)}')
    else:
        # Sequential sending
        for i in range(message_count):
            if session.is_stopped:
                break

            send_single_email(email_config, i + 1, session, sender)

            if i < message_count - 1 and delay_between > 0:
                time.sleep(delay_between)


# Flask route handlers
def start_email_campaign(request_data):
    """Start email sending campaign - ENHANCED with DLP direction support"""
    try:
        if not EMAIL_FRAMEWORK_AVAILABLE:
            return {'error': 'Email framework not available'}, 500

        # Extract data
        form_data = request_data.get('formData', {})
        message_count = request_data.get('messageCount', 1)
        delay_between = request_data.get('delayBetween', 1.0)
        enable_threading = request_data.get('enableThreading', True)
        thread_count = request_data.get('threadCount', 5)

        print(f"🔍 EmailUtils start_email_campaign: Processing request for {message_count} messages")
        print(f"📧 Form data keys: {list(form_data.keys())}")

        # Log DLP direction if applicable
        if form_data.get('threatType') == 'dlp':
            dlp_direction = form_data.get('dlpDirection', 'incoming')
            print(f"🔒 DLP Testing Direction: {dlp_direction.upper()}")

        # Check user limits using LOCAL functions
        user_email = get_current_user_email_local()
        print(f"🔍 EmailUtils start_email_campaign: Current user email: {user_email}")

        if not user_email:
            print(f"❌ EmailUtils start_email_campaign: No user email found in session")
            print(f"   Session keys: {list(session.keys()) if 'session' in globals() else 'session not available'}")
            return {'error': 'User session not found'}, 401

        print(f"🔍 EmailUtils start_email_campaign: Checking limits for user: {user_email}")
        can_send, message = can_send_messages_local(user_email, message_count)

        if not can_send:
            print(
                f"❌ EmailUtils start_email_campaign: User {user_email} cannot send {message_count} messages: {message}")
            return {'error': message}, 403

        print(f"✅ EmailUtils start_email_campaign: User {user_email} can send {message_count} messages: {message}")

        # Build email config
        email_config = build_email_config(form_data)

        # Create session
        session_id = str(uuid.uuid4())
        email_session = EmailSession(session_id, message_count)

        # Set DLP type if applicable
        if email_config.get('dlp_type'):
            email_session.set_dlp_type(email_config['dlp_type'])

        with session_lock:
            active_email_sessions[session_id] = email_session

        email_session.add_log('info', f'Starting email campaign: {message_count} emails')

        # Start background thread
        thread = threading.Thread(
            target=send_emails_worker,
            args=(email_config, message_count, delay_between, enable_threading, thread_count, email_session)
        )
        thread.daemon = True
        thread.start()

        return {
            'success': True,
            'session_id': session_id,
            'message': f'Started sending {message_count} emails',
            'dlp_type': email_config.get('dlp_type')
        }, 200

    except Exception as e:
        print(f"❌ EmailUtils start_email_campaign error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'error': str(e)}, 500


def get_session_progress(session_id):
    """Get session progress"""
    with session_lock:
        session = active_email_sessions.get(session_id)

    if not session:
        return {'error': 'Session not found'}, 404

    return session.get_progress(), 200


def stop_session(session_id):
    """Stop session"""
    with session_lock:
        session = active_email_sessions.get(session_id)

    if not session:
        return {'error': 'Session not found'}, 404

    session.stop()
    return {'success': True, 'message': 'Session stopped'}, 200


def test_email_config(request_data):
    """Test email configuration - ENHANCED with DLP direction support"""
    try:
        if not EMAIL_FRAMEWORK_AVAILABLE:
            return {'error': 'Email framework not available'}, 400

        form_data = request_data.get('formData', {})
        message_count = form_data.get('messageCount', 1)

        print(f"🔍 EmailUtils test_email_config: Testing configuration for {message_count} messages")

        # Check user limits using LOCAL functions
        user_email = get_current_user_email_local()
        print(f"🔍 EmailUtils test_email_config: Current user email: {user_email}")

        if not user_email:
            print(f"❌ EmailUtils test_email_config: No user email found in session")
            print(f"   Session keys: {list(session.keys()) if 'session' in globals() else 'session not available'}")
            return {'error': 'User session not found'}, 401

        print(f"🔍 EmailUtils test_email_config: Checking limits for user: {user_email}")
        can_send, message = can_send_messages_local(user_email, message_count)

        if not can_send:
            print(f"❌ EmailUtils test_email_config: User {user_email} cannot send {message_count} messages: {message}")
            return {'error': message}, 403

        print(f"✅ EmailUtils test_email_config: User {user_email} can send {message_count} messages: {message}")

        email_config = build_email_config(form_data)

        # Create test email
        email_obj = create_email_from_config(email_config)
        recipients = extract_recipients(email_config)

        # Enhanced preview with DLP info
        preview = {
            'subject': email_obj.subject,
            'recipients': recipients,
            'sender': email_obj.sender.address,
            'body_preview': email_obj.body[:200] + '...' if len(email_obj.body) > 200 else email_obj.body,
            'attachments': len(email_obj.attachments) if email_obj.attachments else 0,
            'threat_details': email_obj.email_threats,
            'dlp_type': email_config.get('dlp_type'),
            'dlp_direction': form_data.get('dlpDirection')
        }

        return {
            'success': True,
            'preview': preview,
            'message': 'Configuration is valid'
        }, 200

    except Exception as e:
        print(f"❌ EmailUtils test_email_config error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': str(e)
        }, 400


def test_smtp_credentials(email, password, provider):
    """Test SMTP credentials for outgoing DLP"""
    try:
        print(f"🔍 Testing SMTP for {email} via {provider}")

        config = PROVIDER_CONFIGS.get(provider)
        if not config:
            return {
                'success': False,
                'error': f'Unsupported provider: {provider}'
            }

        # Test SMTP connection
        if provider == 'microsoft':
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context()

        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
            server.starttls(context=context)
            server.login(email, password)

        return {
            'success': True,
            'message': f'SMTP connection successful to {provider}',
            'provider': provider,
            'email': email
        }

    except smtplib.SMTPAuthenticationError as e:
        error_str = str(e)
        tenant_smtp_disabled = 'SmtpClientAuthentication is disabled for the Tenant' in error_str

        return {
            'success': False,
            'error': f'SMTP Authentication failed: {error_str}',
            'tenant_smtp_disabled': tenant_smtp_disabled,
            'provider': provider,
            'suggestion': 'Contact IT admin to enable SMTP authentication' if tenant_smtp_disabled else 'Check credentials or use app password'
        }

    except Exception as e:
        return {
            'success': False,
            'error': f'SMTP connection failed: {str(e)}',
            'provider': provider
        }


def cleanup_old_sessions():
    """Cleanup old sessions"""
    current_time = time.time()
    max_age = 3600  # 1 hour

    with session_lock:
        sessions_to_remove = []
        for session_id, session in active_email_sessions.items():
            if current_time - session.start_time > max_age:
                sessions_to_remove.append(session_id)

        for session_id in sessions_to_remove:
            del active_email_sessions[session_id]
            print(f"Cleaned up old session: {session_id}")


def setup_cleanup_scheduler():
    """Setup periodic cleanup"""

    def cleanup_worker():
        while True:
            time.sleep(300)  # Every 5 minutes
            cleanup_old_sessions()

    cleanup_thread = threading.Thread(target=cleanup_worker)
    cleanup_thread.daemon = True
    cleanup_thread.start()


# Initialize cleanup
setup_cleanup_scheduler()

print("📧 EmailUtils ENHANCED with DLP Direction Support!")
print("🔒 Incoming DLP: Uses SES to simulate external threats")
print("🔄 Outgoing DLP: Uses organizational SMTP (requires tenant permission)")
print("✅ Enhanced error handling for SMTP tenant restrictions")
print("✅ Comprehensive logging and session tracking")
print("🚀 Ready for both incoming and outgoing DLP testing!")
