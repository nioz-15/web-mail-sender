#!/usr/bin/env python3

import time
import uuid
import hashlib
import random
import base64
from dataclasses import dataclass, field, asdict
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from datetime import datetime
import pytz

# Import file generators with try/catch to prevent circular imports
try:
    from file_generators.generators.attachment_generator import AttachmentDataGenerator

    ATTACHMENT_GENERATOR_AVAILABLE = True
    print("✅ AttachmentDataGenerator imported")
except ImportError as e:
    ATTACHMENT_GENERATOR_AVAILABLE = False
    print(f"⚠️ AttachmentDataGenerator not available: {e}")

try:
    from file_generators.generators.body_generator import BodyDataGenerator

    BODY_GENERATOR_AVAILABLE = True
    print("✅ BodyDataGenerator imported")
except ImportError as e:
    BODY_GENERATOR_AVAILABLE = False
    print(f"⚠️ BodyDataGenerator not available: {e}")

try:
    from file_generators.generators.subject_generator import SubjectDataGenerator

    SUBJECT_GENERATOR_AVAILABLE = True
    print("✅ SubjectDataGenerator imported")
except ImportError as e:
    SUBJECT_GENERATOR_AVAILABLE = False
    print(f"⚠️ SubjectDataGenerator not available: {e}")


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def timenow():
    """Generate timestamp for file naming"""
    try:
        return datetime.now().astimezone(pytz.timezone('Etc/GMT-3')).strftime("%d%m%y_%H_%M_%S_%f")
    except Exception:
        # Fallback if pytz is not available
        return datetime.now().strftime("%d%m%y_%H_%M_%S_%f")


def sender_factory(self, **sender_dict):
    """Factory function to create sender addresses"""
    if "address" in sender_dict:
        self.address = sender_dict.get("address")
    else:
        self.address = "eml_sender@avtestqa.com"
    self.provider = sender_dict.get("provider", "ses")
    return self.address


def recipient_factory(self, **recipient_dict):
    """Factory function to create recipient addresses"""
    self.mode = recipient_dict.get("mode", "external")
    self.provider = recipient_dict.get("provider", None)
    self.workflow = recipient_dict.get("workflow", {})
    self.address = recipient_dict.get("address")

    if self.mode == "group":
        self.members = []
        for member in recipient_dict.get("members", []):
            member["provider"] = self.provider
            member["mode"] = member.get("mode", "external")
            member["workflow"] = member.get("workflow", {})
            # Avoid circular import by creating Recipient directly
            recipient = Recipient(**member)
            self.members.append(recipient)


def recipients_list_factory(self, many_recipients: dict):
    """Factory function to create recipients lists"""
    self.to_list, self.cc_list, self.bcc_list = [], [], []
    for key, recipients_list in many_recipients.items():
        for meta in recipients_list:
            recipient = Recipient(**meta)
            getattr(self, f"{key}_list").append(recipient)


# ============================================================================
# SUBJECT FACTORY WITH SAFE IMPORTS
# ============================================================================

def subject_factory(email_dict: dict) -> str:
    """Enhanced subject factory - FIXED LOGIC VERSION"""
    timestamp = timenow()
    subject = email_dict.get("subject")  # This contains threat config like "phishing:link"
    attachments = email_dict.get("attachments")
    body = email_dict.get("body")

    # CASE 1: Threat location is SUBJECT - Use real generator for threatening subjects
    if subject:
        try:
            if ':' in subject:
                parts = subject.split(':')
                threat_type = parts[0] if len(parts) > 0 else "unknown"
                content_type = parts[-1] if len(parts) > 1 else ""
            else:
                threat_type = subject
                content_type = ""

            print(f"🔍 SUBJECT THREAT: '{subject}' -> type: '{threat_type}', content: '{content_type}'")
        except Exception as e:
            print(f"⚠️ Subject parsing error: {e}")
            threat_type = "unknown"
            content_type = ""

        # Try real SubjectDataGenerator for ALL threat types when threat is in SUBJECT
        if SUBJECT_GENERATOR_AVAILABLE:
            try:
                print(f"🔥 Using REAL SubjectDataGenerator for SUBJECT threat: '{threat_type}:{content_type}'")

                # Try different parameter formats the real generator might expect
                generated_subject = None

                # Method 1: Pass the full subject config (e.g., "phishing:link")
                try:
                    generated_subject = SubjectDataGenerator.generate_subject(subject_type=subject)
                    print(f"✅ Method 1 success with full config: '{subject}'")
                except Exception as e1:
                    print(f"⚠️ Method 1 failed: {e1}")

                    # Method 2: Pass just the threat type (e.g., "phishing")
                    try:
                        generated_subject = SubjectDataGenerator.generate_subject(subject_type=threat_type)
                        print(f"✅ Method 2 success with threat type: '{threat_type}'")
                    except Exception as e2:
                        print(f"⚠️ Method 2 failed: {e2}")

                        # Method 3: Try with content type if available
                        if content_type:
                            try:
                                generated_subject = SubjectDataGenerator.generate_subject(subject_type=content_type)
                                print(f"✅ Method 3 success with content type: '{content_type}'")
                            except Exception as e3:
                                print(f"⚠️ Method 3 failed: {e3}")

                # Check if we got a valid result from real generator
                if generated_subject and str(generated_subject).strip():
                    result_subject = f"REAL_{threat_type}_{timestamp} {generated_subject}"
                    print(f"✅ REAL SubjectDataGenerator SUCCESS: '{result_subject}'")
                    return result_subject
                else:
                    print(f"⚠️ Real generator returned empty: '{generated_subject}'")

            except Exception as e:
                print(f"⚠️ SubjectDataGenerator error: {e}")
                import traceback
                traceback.print_exc()

        # Fallback to threatening templates when threat is in SUBJECT
        print(f"🔄 Using fallback THREATENING templates for subject threat: '{threat_type}'")
        threatening_templates = {
            'malware': [
                "Urgent: Invoice Payment Required",
                "Security Alert - Action Needed",
                "Your Account Has Been Suspended",
                "Critical System Update Available"
            ],
            'phishing': [
                "Verify your account to avoid suspension",
                "Security alert: Click here to verify",
                "Your account will be closed in 24 hours",
                "Action Required: Update Payment Information"
            ],
            'spam': [
                "🎉 CONGRATULATIONS! You've Won $1,000,000!",
                "Make $5000 Working From Home!",
                "URGENT: Claim Your Prize Now!",
                "Limited Time Offer - Act Fast!"
            ],
            'ctp': [
                "Important link for your review",
                "Access your updated resources",
                "Click to view shared document",
                "New resource available for download"
            ],
            'dlp': [
                "Confidential: Employee SSN List",
                "INTERNAL: Customer Database Export",
                "RESTRICTED: Financial Records Q4",
                "CONFIDENTIAL: Personnel Information"
            ],
            'clean': [
                "Monthly Business Report",
                "Meeting Notes - Please Review",
                "Project Update - Q4 2024",
                "Policy Update Notification"
            ]
        }

        if threat_type.lower() in threatening_templates:
            try:
                subject_value = random.choice(threatening_templates[threat_type.lower()])
                result_subject = f"TEMPLATE_{threat_type}_{timestamp} {subject_value}"
                print(f"📝 Threatening template used: '{result_subject}'")
                return result_subject
            except Exception:
                pass

        # Final fallback for subject threats
        fallback_subject = f"AUTO_{threat_type}_{timestamp} Test Threat Subject"
        print(f"📝 Subject threat fallback: '{fallback_subject}'")
        return fallback_subject

    # CASE 2: Threat location is BODY or ATTACHMENT - Generate CLEAN subjects
    print(f"🔍 NON-SUBJECT threat location detected")

    if attachments:
        print(f"📎 Attachment threat detected - generating CLEAN subject")
        tag = "clean_email_with_attachment"
    elif body:
        print(f"📝 Body threat detected - generating CLEAN subject")
        tag = "clean_email_with_body_threat"
    else:
        print(f"📧 Default case - generating CLEAN subject")
        tag = "clean_test_email"

    # Generate CLEAN, NORMAL subjects when threat is NOT in subject
    clean_subjects = [
        "Monthly Report Available",
        "Document for Review",
        "Important Information",
        "Please Review Attached",
        "Update Notification",
        "Business Communication",
        "Weekly Summary",
        "Information Request",
        "Document Delivery",
        "Standard Communication"
    ]

    try:
        clean_subject = random.choice(clean_subjects)
        result_subject = f"CLEAN_{tag}_{timestamp} {clean_subject}"
        print(f"📧 Clean subject generated: '{result_subject}'")
        return result_subject
    except Exception:
        fallback_subject = f"AUTO_{tag}_{timestamp}"
        print(f"📧 Clean subject fallback: '{fallback_subject}'")
        return fallback_subject


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Sender(object):
    """Email sender configuration"""
    mode: str = field(default=None)
    address: str = field(default=None)
    provider: str = field(default=None)
    alias: str = field(default=None)
    workflow: dict = field(default=None)
    domain: str = field(default=None)

    def __repr__(self):
        return "<Sender %r>" % asdict(self)

    def __init__(self, default=False, **kwargs):
        if not default:
            sender_factory(self, **kwargs)
            if '@' in self.address:
                self.alias, self.domain = self.address.split('@')
            else:
                self.alias, self.domain = self.address, 'unknown'
            self.workflow = kwargs.get("workflow", {})
            self.mode = kwargs.get("mode")
        else:
            self.tag = "default"
            self.provider = "ses"
            self.address = "eml_sender@avtestqa.com"
            self.alias, self.domain = self.address.split('@')


@dataclass
class Recipient:
    """Email recipient configuration"""
    mode: str = field(default=None)
    address: str = field(default=None)
    provider: str = field(default=None)
    workflow: dict = field(default=None)
    members = []

    def __repr__(self):
        return "<Recipient %r>" % asdict(self)

    def __init__(self, **recipient_dict):
        recipient_factory(self, **recipient_dict)


@dataclass
class RecipientsList(object):
    """Container for email recipients"""
    to_list: list = field(default=None)
    cc_list: list = field(default=None)
    bcc_list: list = field(default=None)

    def __repr__(self):
        return "<RecipientsList %r>" % asdict(self)

    def __init__(self, many_recipients: dict):
        recipients_list_factory(self, many_recipients)

    def all(self):
        """Get all recipients from all lists"""
        results = []
        for recipient_list_type in [self.to_list, self.cc_list, self.bcc_list]:
            if recipient_list_type:
                for single_recipient in recipient_list_type:
                    results.extend(self.get_recipient(single_recipient))
        return results

    def get_recipient(self, recipient):
        """Get individual recipients, handling groups"""
        results = []
        if recipient.mode == "group":
            for single_recipient in recipient.members:
                results.extend(self.get_recipient(single_recipient))
        else:
            results.append(recipient)
        return results


@dataclass
class Headers:
    """Email headers generator - simplified"""
    email: 'Email'
    wd_type: str
    value: dict = field(init=False)

    def __init__(self, email: 'Email', wd_type: str):
        self.email = email
        self.wd_type = wd_type.lower()
        self.value = self.set_wd_headers()

    def __repr__(self):
        return f"<Headers {self.value}>"

    def set_wd_headers(self) -> dict:
        """Generate headers with safe access"""
        try:
            # Safe recipient access
            if self.email.recipients and self.email.recipients.to_list:
                mailbox_address = self.email.recipients.to_list[0].address
            else:
                mailbox_address = "default@example.com"

            sender = getattr(self.email.sender, 'address', 'default@example.com')

            # Simple header generation
            headers = {
                "X-CLOUD-SEC-AV-Mode": "inline",
                "X-CLOUD-SEC-AV-Receiver": mailbox_address,
                "X-CLOUD-SEC-AV-Sender": sender,
                "X-CLOUD-SEC-AV-Info": "test_customer,ses,inline",
                "test-id": uuid.uuid4().hex,
                "customer": "test_customer",
                "Message-ID": f"<{str(random.random())}@{sender.split('@')[1] if '@' in sender else 'example.com'}>"
            }

            return headers

        except Exception as e:
            print(f"⚠️ Header generation error: {e}")
            return {
                "X-CLOUD-SEC-AV-Mode": "inline",
                "Message-ID": f"<{str(random.random())}@example.com>"
            }


@dataclass
class Attachment:
    """Email attachment with safe generator calls"""
    file_name: str = field(default=None)
    file_ext: str = field(default=None)
    content: bytes = field(default=None)
    encrypt: bool = field(default=False)
    is_multi_file: bool = field(default=False)
    file_count: int = field(default=1)

    def __repr__(self):
        if self.is_multi_file:
            return f"<MultiFileAttachment {self.file_count} files: {self.file_name}>"
        return f"<Attachment {self.file_name}>"

    def __init__(self, attachment_input=None):
        if attachment_input is None:
            return

        if isinstance(attachment_input, list):
            self.is_multi_file = True
            self.file_count = len(attachment_input)
            self._create_multi_file_archive(attachment_input)
        else:
            self.is_multi_file = False
            self.file_count = 1
            self._create_single_file(attachment_input)

    def _create_single_file(self, attachment_dict):
        """Create single file with safe generator calls"""
        try:
            tag = next(iter(attachment_dict.keys()))
            config = attachment_dict[tag]

            # Find content verdict and file type
            config_params = {'location', 'encrypt', 'compression'}
            verdict = None
            mime_type = None

            for key, value in config.items():
                if key not in config_params:
                    verdict = key
                    mime_type = value
                    break

            if verdict is None or mime_type is None:
                raise ValueError(f"No content verdict found: {attachment_dict}")

            # Generate filename
            timestamp = timenow().replace(' ', '_')
            self.file_ext = self.determine_file_extension(tag, mime_type, verdict, config.get("compression"))
            self.file_name = f"{tag}_{verdict}_{timestamp}.{self.file_ext}"
            self.encrypt = config.get("encrypt", False)

            # Try real generator if available
            if ATTACHMENT_GENERATOR_AVAILABLE:
                try:
                    generator = AttachmentDataGenerator()
                    self.content = generator.generate_attachment(
                        tag=tag,
                        verdict=verdict,
                        file_type=mime_type,
                        file_location=config.get("location"),
                        encrypt=self.encrypt,
                        compression=config.get("compression")
                    )
                    print(f"✅ Generated real {tag} attachment: {len(self.content)} bytes")
                    return
                except Exception as e:
                    print(f"⚠️ Real generator failed: {e}")

            # Fallback content generation
            self.content = self._generate_fallback_content(tag, verdict, mime_type)
            print(f"✅ Generated fallback {tag} attachment: {len(self.content)} bytes")

        except Exception as e:
            print(f"❌ Attachment generation error: {e}")
            self.content = b"Fallback attachment content"
            self.file_name = f"fallback_{timenow()}.txt"
            self.file_ext = "txt"

    def _generate_fallback_content(self, tag, verdict, mime_type):
        """Generate fallback attachment content"""
        if tag == "malware" and verdict == "eicar":
            return b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        elif tag == "dlp":
            return f"CONFIDENTIAL: {verdict.upper()} DATA\n" \
                   f"SSN: 123-45-6789\n" \
                   f"Credit Card: 4111-1111-1111-1111\n" \
                   f"Generated: {datetime.now()}".encode()
        else:
            return f"Test {tag} {verdict} content for {mime_type} file\n" \
                   f"Generated at: {datetime.now()}\n" \
                   f"This is simulated threat content for testing.".encode()

    def _create_multi_file_archive(self, files_list):
        """Create multi-file archive with safe handling"""
        try:
            if not files_list:
                raise ValueError("Multi-file archive requires at least one file")

            files_data = []
            for file_config in files_list:
                temp_attachment = Attachment()
                temp_attachment._create_single_file(file_config)
                files_data.append((temp_attachment.file_name, temp_attachment.content))

            # Try real archive generator
            if ATTACHMENT_GENERATOR_AVAILABLE:
                try:
                    generator = AttachmentDataGenerator()
                    self.content = generator.create_multi_file_archive(files_data, "zip", False)
                    self.file_name = f"multi_archive_{timenow()}.zip"
                    self.file_ext = "zip"
                    print(f"✅ Generated real multi-file archive: {len(self.content)} bytes")
                    return
                except Exception as e:
                    print(f"⚠️ Real archive generator failed: {e}")

            # Fallback ZIP creation
            self.content = self._create_fallback_archive(files_data)
            self.file_name = f"fallback_archive_{timenow()}.zip"
            self.file_ext = "zip"
            print(f"✅ Generated fallback archive: {len(self.content)} bytes")

        except Exception as e:
            print(f"❌ Multi-file archive error: {e}")
            self.content = b"Fallback archive content"
            self.file_name = f"fallback_archive_{timenow()}.zip"
            self.file_ext = "zip"

    def _create_fallback_archive(self, files_data):
        """Create simple fallback archive"""
        archive_content = b"PK\x03\x04"  # ZIP file signature
        for filename, data in files_data:
            archive_content += f"\n--- {filename} ---\n".encode()
            archive_content += data[:500]  # First 500 bytes of each file
            archive_content += b"\n"
        return archive_content

    @staticmethod
    def determine_file_extension(tag, mime_type, verdict, compression=None):
        """Determine appropriate file extension"""
        if compression:
            return compression.lower()

        extensions = {
            "word": "docx", "excel": "xlsx", "pdf": "pdf",
            "txt": "txt", "csv": "csv", "zip": "zip"
        }
        return extensions.get(mime_type.lower(), "txt")


@dataclass
class Email(MIMEMultipart):
    """Main Email class - no circular imports"""
    subject: str = field(default=None)
    body: str = field(default=None)
    email_threats: dict = field(default_factory=dict)
    recipients: RecipientsList = field(default=None)
    attachments: list = field(default=None)
    headers: dict = field(default_factory=dict)
    message_id: str = field(default=None)
    message_id_uuid: str = field(default=None)
    full_message_id: str = field(default=None)

    def __repr__(self):
        return "<Email %r>" % asdict(self)

    def __init__(self, email_dict, wd_type=False):
        super(Email, self).__init__("alternative")

        # Initialize sender
        if "sender" not in email_dict:
            self.sender = Sender(default=True)
        else:
            self.sender = Sender(**email_dict.get("sender"))

        # Generate subject
        self.subject = subject_factory(email_dict)

        # Generate body
        body_type = email_dict.get("body")
        if body_type:
            self.body = self._generate_body_content(body_type)
        else:
            self.body = "This is a test email generated by the Email Security Testing Platform."

        # Set threat details
        self.email_threats = self._set_mail_threat_details(email_dict)

        # Handle attachments
        if email_dict.get("attachments"):
            self.attachments = self._process_attachments(email_dict["attachments"])
        else:
            self.attachments = []

        # Build the email
        self._build_eml(email_dict.get("recipients"), wd_type)

    def _generate_body_content(self, body_type):
        """Generate email body content"""
        if BODY_GENERATOR_AVAILABLE:
            try:
                generated_body = BodyDataGenerator.generate_body(body_type=body_type)
                if isinstance(generated_body, str) and generated_body.strip():
                    return generated_body
                elif isinstance(generated_body, list):
                    return self._build_html_from_urls(generated_body)
            except Exception as e:
                print(f"⚠️ Body generator error: {e}")

        # Fallback body generation
        return self._generate_fallback_body(body_type)

    def _generate_fallback_body(self, body_type):
        """Generate fallback body content"""
        if 'phishing' in body_type:
            urls = [
                ('link', 'https://fake-bank.malicious.com/verify'),
                ('link', 'https://paypal-security.phishing.net/update')
            ]
            return self._build_html_from_urls(urls)
        elif 'ctp' in body_type:
            urls = [
                ('link', 'https://company-docs.sharepoint.com/review'),
                ('link', 'https://teams.microsoft.com/join/meeting')
            ]
            return self._build_html_from_urls(urls)
        elif 'spam' in body_type:
            return "🎉 CONGRATULATIONS! You've won a FREE vacation! Click here to claim your prize!"
        else:
            return f"This is a test email for {body_type} security testing."

    def _build_html_from_urls(self, urls):
        """Build HTML email from URL list - safe version"""
        try:
            html_lines = [
                '<html><body>',
                '<h1>Test Email</h1>',
                '<p>This email contains links for security testing:</p>'
            ]

            for i, url_data in enumerate(urls, 1):
                if isinstance(url_data, (list, tuple)) and len(url_data) >= 2:
                    url = url_data[1]
                else:
                    url = str(url_data)

                if not url.startswith(('http://', 'https://')):
                    url = f'https://{url}'

                html_lines.append(f'<p>{i}: <a href="{url}">{url}</a></p>')

            html_lines.extend(['</body></html>'])
            return '\n'.join(html_lines)

        except Exception as e:
            print(f"⚠️ HTML generation error: {e}")
            return "<html><body><p>Test email content</p></body></html>"

    def _process_attachments(self, attachments_config):
        """Process attachment configuration"""
        try:
            attachments = []
            if isinstance(attachments_config, list):
                for attachment_dict in attachments_config:
                    attachment = Attachment(attachment_dict)
                    attachments.append(attachment)
            else:
                attachment = Attachment(attachments_config)
                attachments = [attachment]
            return attachments
        except Exception as e:
            print(f"⚠️ Attachment processing error: {e}")
            return []

    def _build_eml(self, target_recipients: dict = None, wd: str = None):
        """Build the complete email structure"""
        self["Subject"] = self.subject
        self["From"] = self.sender.address
        self["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())

        # Set body
        content_type = "html" if '<html>' in self.body else "plain"
        self.attach(MIMEText(self.body, content_type))

        # Set attachments
        if self.attachments:
            for attachment in self.attachments:
                try:
                    content = attachment.content
                    if isinstance(content, list) and content:
                        content = content[0]

                    part = MIMEApplication(
                        _data=content,
                        Name=attachment.file_name,
                        subtype=attachment.file_ext
                    )
                    part['Content-Disposition'] = f'attachment; filename="{attachment.file_name}"'
                    self.attach(part)
                except Exception as e:
                    print(f"⚠️ Attachment error: {e}")

        # Set recipients
        if target_recipients:
            self.recipients = RecipientsList(target_recipients)
            if self.recipients.to_list:
                self["To"] = ','.join([obj.address for obj in self.recipients.to_list])
            if self.recipients.cc_list:
                self["Cc"] = ','.join([obj.address for obj in self.recipients.cc_list])
            if self.recipients.bcc_list:
                self["Bcc"] = ','.join([obj.address for obj in self.recipients.bcc_list])

        # Set headers
        if wd:
            try:
                self.headers = Headers(email=self, wd_type=wd).value
                for key, value in self.headers.items():
                    self.add_header(key, value)
            except Exception as e:
                print(f"⚠️ Headers error: {e}")

        # Set message ID
        self.message_id = hashlib.md5(uuid.uuid4().hex.encode('utf-8')).hexdigest()

    def _set_mail_threat_details(self, email_dict):
        """Set threat details for tracking"""
        threats = {}

        if "subject" in email_dict:
            subject = email_dict.get("subject", "")
            if ":" in subject:
                threat_type = subject.split(":")[0]
                threats["subject"] = [(threat_type, subject)]

        if "body" in email_dict:
            body = email_dict.get("body", "")
            if ":" in body:
                threat_type = body.split(":")[0]
                threats["body"] = [(threat_type, body)]

        if "attachments" in email_dict:
            threats["attachments"] = ["attachment_threat"]

        return threats

    def as_json(self):
        """Convert to JSON for API compatibility"""
        return {
            "subject": self["Subject"],
            "from": {"emailAddress": {"address": self["From"]}},
            "body": {"contentType": "HTML", "content": self.body},
            "attachments": len(self.attachments) if self.attachments else 0
        }


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

print(f"🔥 File generators available:")
print(f"   📎 AttachmentDataGenerator: {'✅' if ATTACHMENT_GENERATOR_AVAILABLE else '❌'}")
print(f"   📝 BodyDataGenerator: {'✅' if BODY_GENERATOR_AVAILABLE else '❌'}")
print(f"   📧 SubjectDataGenerator: {'✅' if SUBJECT_GENERATOR_AVAILABLE else '❌'}")
print("✅ Framework ready with fallback content generation!")