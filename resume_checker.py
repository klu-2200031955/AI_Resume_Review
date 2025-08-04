import google.generativeai as genai
from prompts import resume_analysis_prompt
from utils import extract_text_from_pdf
import os
from dotenv import load_dotenv
import time

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# Configure with the latest model
genai.configure(
    api_key=API_KEY,
    transport='rest',  # More reliable than grpc for some users
    client_options={
        "api_endpoint": "generativelanguage.googleapis.com"
    }
)

# Using the most capable current model
model = genai.GenerativeModel("gemini-1.5-flash")

def analyze_resume(resume_path, job_role, company):
    try:
        resume_text = extract_text_from_pdf(resume_path)
        if len(resume_text) > 10000:
            resume_text = resume_text[:10000] + "\n[Content truncated]"
            
        prompt = f"""
Please provide a concise analysis (max 3000 characters) of this resume for the {job_role} position at {company}.
Focus on key strengths and potential gaps relative to the role.

Resume:
{resume_text}
"""
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Error analyzing resume: {str(e)}"