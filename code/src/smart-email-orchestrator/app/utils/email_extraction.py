import json
import os
import re
import email
from email import policy
from email.parser import BytesParser
from app.utils.classification import advanced_classify_email, classify_email, generate_intent_and_reasoning
from app.models import load_config

CONFIG = load_config("config.json")

def extract_email_details(eml_file_path):
    """Extracts subject, body, and attachments from an .eml file."""
    with open(eml_file_path, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    email_data = {
        "subject": msg["subject"],
        "body": get_email_body(msg),
        "attachments": extract_attachments(msg)
    }

    return email_data

def get_email_body(msg):
    """Extract plain-text email body."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")

def extract_attachments(msg):
    """Extract attachment filenames."""
    attachments = []
    for part in msg.walk():
        if part.get("Content-Disposition") is not None:
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
    return attachments

def extract_fields(email_body):
    """Extract predefined fields dynamically from email body using regex."""
    extracted_data = {}
    fields = CONFIG["email_processing"]["extract_fields"]

    regex_patterns = {
        "amount": r"(?i)\b(?:amount|total):?\s?\$?(\d+(?:,\d{3})*(?:\.\d{2})?)\b",
        "due_date": r"(?i)\b(?:due date|payment date):?\s?(\d{1,2}/\d{1,2}/\d{2,4})\b",
        "customer_id": r"(?i)\b(?:customer ID|account ID):?\s?(\w+)\b",
        "account_number": r"(?i)\b(?:account number|acc no):?\s?(\d+)\b",
        "loan_number": r"(?i)\b(?:loan number|loan ID):?\s?(\d+)\b"
    }

    for field in fields:
        pattern = regex_patterns.get(field)
        if pattern:
            match = re.search(pattern, email_body)
            if match:
                extracted_data[field] = match.group(1)

    return extracted_data

def process_emails(upload_folder, config):
    """Processes uploaded .eml files."""
    results = []

    for filename in os.listdir(upload_folder):
        if filename.endswith(".eml"):
            eml_path = os.path.join(upload_folder, filename)
            email_data = extract_email_details(eml_path)
            classification = classify_email(email_data,upload_folder)
            #classification = advanced_classify_email(email_data)
            extracted_fields = extract_fields(email_data["body"])
            sender_intent, reasoning = generate_intent_and_reasoning(email_data["body"])
            

            result = {
               "file": filename, "subject": email_data["subject"],
                "request_type": classification["request_type"], "sub_request_type": classification["sub_request_type"],
                "confidence_score": classification["confidence_score"], "attachments": email_data["attachments"],
                "senders_intent": sender_intent, "department": classification["department"],"reasoning": reasoning
            }

            results.append(result)

    with open(config["OUTPUT_FILE"], "w") as file:
        json.dump(results, file, indent=2)

    return results

