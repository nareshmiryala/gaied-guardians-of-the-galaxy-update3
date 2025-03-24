import openai
from transformers import pipeline
from app.models import load_config
from app.utils.ocr import extract_text_from_image
import os
import PyPDF2
import docx

CONFIG = load_config("config.json")


# Initialize the text classification pipeline with a more advanced model
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

def identify_department(email_body):
    """Identifies the department based on keywords/phrases in the email body."""
    department_keywords = CONFIG["department_keywords"]
    email_content = email_body.lower()
    
    # Check for keywords in the email body
    for department, keywords in department_keywords.items():
        for keyword in keywords:
            if keyword.lower() in email_content:
                return department
    
    # If no keywords are found, use the zero-shot classification model as a fallback
    candidate_labels = list(CONFIG["department_keywords"].keys())
    result = classifier(email_body, candidate_labels)
    detected_department = result["labels"][0]
    return detected_department

def extract_text_from_attachment(file_path):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".pdf":
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                return " ".join(page.extract_text() for page in reader.pages if page.extract_text())
        elif ext == ".docx":
            doc = docx.Document(file_path)
            return " ".join(para.text for para in doc.paragraphs)
        elif ext == ".txt":
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as e:
        print(f"Error extracting text from {file_path}: {e}")
    return ""
    


def classify_email(email_data, UPLOAD_FOLDER):
    """Classifies emails based on request types using a language model."""
    detected_request_type = None
    detected_sub_request_type = None
    confidence_score = 0

    content_sources = [email_data["body"]]
    for attachment in email_data["attachments"]:
        attachment_path = os.path.join(UPLOAD_FOLDER, attachment)
        content_sources.append(extract_text_from_attachment(attachment_path))
    candidate_labels = [req["request_type"] for req in CONFIG["request_types"]]
    if not candidate_labels:
        return {"request_type": "Unknown", "sub_request_type": "Unknown", "confidence_score": 0}

    for content in content_sources:
        if content:
            result = classifier(content, candidate_labels)
            detected_request_type = result["labels"][0]
            confidence_score = result["scores"][0] * 100

            for req in CONFIG["request_types"]:
                if req["request_type"] == detected_request_type and req["sub_request_types"]:
                    sub_result = classifier(content, req["sub_request_types"])
                    detected_sub_request_type = sub_result["labels"][0]
                    confidence_score += sub_result["scores"][0] * 30
                    print("sub_result")
                    print(sub_result)
                    break

    department = identify_department(email_data["body"])

    # Ensure the detected request type is valid for the detected department
    valid_request_types = CONFIG["department_request_mapping"].get(department, [])
    if detected_request_type not in valid_request_types:
        detected_request_type = "Unknown"
        detected_sub_request_type = "Unknown"
        confidence_score = 0

    return {
        "request_type": detected_request_type,
        "sub_request_type": detected_sub_request_type,
        "confidence_score": min(confidence_score, 100),
        "department": department
    }

# Advanced classification using OpenAI GPT-3.5
def advanced_classify_email(email_data):
    """Classifies emails using OpenAI GPT-3.5-turbo for better contextual understanding."""
    client = openai.OpenAI(
        api_key="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"
    )
    
    detected_request_type = None
    detected_sub_request_type = None
    confidence_score = 0

    content_sources = [email_data["body"]]
    candidate_labels = [req["request_type"] for req in CONFIG["request_types"]]

    for content in content_sources:
        if content:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",  # Changed from gpt-4 to gpt-3.5-turbo
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that classifies email content."},
                    {"role": "user", "content": f"Classify the following email content into one of these categories: {', '.join(candidate_labels)}.\n\nEmail content:\n{content}"}
                ]
            )
            detected_request_type = response.choices[0].message.content.strip()
            confidence_score = 100  # Assuming high confidence for GPT-3.5

            for req in CONFIG["request_types"]:
                if req["request_type"] == detected_request_type:
                    sub_candidate_labels = req["sub_request_types"]
                    sub_response = client.chat.completions.create(
                        model="gpt-3.5-turbo",  # Changed from gpt-4 to gpt-3.5-turbo
                        messages=[
                            {"role": "system", "content": "You are a helpful assistant that classifies email content."},
                            {"role": "user", "content": f"Classify the following email content into one of these sub-categories: {', '.join(sub_candidate_labels)}.\n\nEmail content:\n{content}"}
                        ]
                    )
                    detected_sub_request_type = sub_response.choices[0].message.content.strip()
                    confidence_score += 30  # Adding confidence for sub-request type
                    break

    department = identify_department(email_data["body"])

    # Ensure the detected request type is valid for the detected department
    valid_request_types = CONFIG["department_request_mapping"].get(department, [])
    if detected_request_type not in valid_request_types:
        detected_request_type = "Unknown"
        detected_sub_request_type = "Unknown"
        confidence_score = 0

    return {
        "request_type": detected_request_type,
        "sub_request_type": detected_sub_request_type,
        "confidence_score": min(confidence_score, 100),
        "department": department
    }

def generate_intent_and_reasoning(email_body):
    if not email_body:
        return "Unknown", "Insufficient information to determine intent."
    intent_labels = ["Inquiry", "Complaint", "Request", "Follow-up", "Acknowledgment"]
    result = classifier(email_body, intent_labels)
    print(result)
    return result["labels"][0], f"The email is classified as '{result['labels'][0]}' because it discusses {result['labels'][0].lower()} matters."