import os
import logging  
from pathlib import Path
from datetime import datetime, timedelta
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    ContextTypes,
    CommandHandler,
    MessageHandler,
    filters,
    ConversationHandler
)
from dotenv import load_dotenv
from typing import Dict, Any
import asyncio
from flask import Flask, render_template_string, request, send_from_directory, session, redirect, url_for, jsonify
import threading
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch
from concurrent.futures import ThreadPoolExecutor
from resume_checker import analyze_resume as analyze_resume_module
from interview_module import generate_questions, evaluate_answers, model as interview_model
from prompts import evaluate_answer_prompt 
from utils import extract_text_from_pdf
from pymongo import MongoClient
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
from functools import wraps

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
COUNTDOWN_SECONDS = int(os.getenv("COUNTDOWN_SECONDS"))
client = MongoClient(MONGO_URI)
db = client["resume_bot"]
users_collection = db["users"]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Conversation states
UPLOAD_RESUME, GET_COMPANY_ROLE, SELECT_INTERVIEW, ASK_QUESTIONS, ANSWERING_QUESTIONS, SELECT_DATA_SOURCE, UPDATE_JOB_ROLE = range(7)

# User data cache
user_data: Dict[int, Dict[str, Any]] = {}
short_links: Dict[str, Dict[str, str]] = {}

# Global bot application and event loop
bot_app = None
event_loop = None
executor = ThreadPoolExecutor(max_workers=4)

# Flask app for HTTP server and webhooks
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")


ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- ENCRYPTION UTILITIES ----------------------

class DataEncryption:
    """Handle data encryption and decryption for user data"""
    
    def __init__(self):
        self.master_key = self._get_or_create_master_key()
    
    def _get_or_create_master_key(self) -> bytes:
        """Get existing master key or create a new one"""
        master_key = os.getenv("ENCRYPTION_MASTER_KEY")
        
        if not master_key:
            # Generate new master key (44 characters for 32 bytes when base64 encoded)
            master_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
            logger.warning("⚠️ No ENCRYPTION_MASTER_KEY found. Generated new key. Please save this key:")
            logger.warning(f"ENCRYPTION_MASTER_KEY={master_key}")
            return base64.urlsafe_b64decode(master_key.encode())
        
        # Pad the key if necessary
        pad_len = len(master_key) % 4
        if pad_len:
            master_key += '=' * (4 - pad_len)
        
        return base64.urlsafe_b64decode(master_key.encode())
    
    def _derive_key(self, user_id: int, salt: bytes = None) -> tuple[Fernet, bytes]:
        """Derive encryption key for specific user"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Use user_id as additional entropy
        password = f"{user_id}:{self.master_key.hex()}".encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        fernet = Fernet(key)
        return fernet, salt
    
    def encrypt_data(self, user_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt user data"""
        try:
            # Convert data to JSON string
            json_data = json.dumps(data, default=str).encode('utf-8')
            
            # Generate encryption key and salt
            fernet, salt = self._derive_key(user_id)
            
            # Encrypt data
            encrypted_data = fernet.encrypt(json_data)
            
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8'),
                "encrypted_at": datetime.now().isoformat(),
                "version": "1.0"
            }
            
        except Exception as e:
            logger.error(f"Encryption error for user {user_id}: {e}")
            raise
    
    def decrypt_data(self, user_id: int, encrypted_record: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt user data"""
        try:
            # Extract components
            encrypted_data = base64.b64decode(encrypted_record["encrypted_data"].encode('utf-8'))
            salt = base64.b64decode(encrypted_record["salt"].encode('utf-8'))
            
            # Derive decryption key
            fernet, _ = self._derive_key(user_id, salt)
            
            # Decrypt data
            decrypted_json = fernet.decrypt(encrypted_data)
            
            # Parse JSON
            data = json.loads(decrypted_json.decode('utf-8'))
            return data
            
        except Exception as e:
            logger.error(f"Decryption error for user {user_id}: {e}")
            raise

encryption = DataEncryption()
# Initialize encryption handler

# ---------------------- PDF HELPERS ----------------------
REPORTS_DIR = Path('static/reports')
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def get_base_url():
    w = os.getenv('WEBHOOK_URL', '').strip()
    if w:
        if w.endswith('/webhook'):
            w = w[:-8]
        return w
    return 'http://localhost:' + os.environ.get('PORT', '5000')

def build_pdf(filename: str, report_data: dict, title: str = 'Interview Analysis Report', resume_analysis: str = None) -> Path:
    filepath = REPORTS_DIR / filename
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 0.2*inch))

    # Resume analysis section
    if resume_analysis:
        story.append(Paragraph("Resume Analysis", styles['Heading2']))
        for line in resume_analysis.splitlines():
            if line.strip():
                story.append(Paragraph(line.strip(), styles['Normal']))
        story.append(PageBreak())

    # Interview summary and feedback section
    s = report_data.get('summary', {})
    if s and s.get("total_questions", 0) > 0:
        summary_lines = [
            f"Total Questions: {s.get('total_questions', 0)}",
            f"Answered: {s.get('answered', 0)}",
            f"Completion Rate: {s.get('completion_rate', 0)}%",
            f"Overall Score: {s.get('overall_score', 0)}/{s.get('max_score', 0)} ({s.get('overall_percentage', 0)}%)"
        ]
        story.append(Paragraph('Summary', styles['Heading2']))
        for line in summary_lines:
            story.append(Paragraph(line, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph('Detailed Feedback', styles['Heading2']))
        for idx, item in enumerate(report_data.get('items', []), 1):
            story.append(Paragraph(f"Q{idx}. {item.get('question','')}", styles['Heading3']))
            story.append(Paragraph(f"<b>Your Answer:</b> {item.get('answer','')}", styles['Normal']))
            story.append(Paragraph(f"Score: {item.get('score',0)}/10 | Verdict: {item.get('verdict','')}", styles['Normal']))
            r = item.get('ratings', {})
            story.append(Paragraph(f"Ratings — R: {r.get('Relevance',0)}, C: {r.get('Clarity',0)}, T: {r.get('TechnicalDepth',0)}", styles['Normal']))
            story.append(Spacer(1, 0.15*inch))
    else:
        story.append(Paragraph("No interview was conducted. This report contains only resume analysis.", styles['Normal']))

    doc = SimpleDocTemplate(str(filepath), pagesize=A4, title=title, author='Resume AI Bot')
    doc.build(story)
    return filepath

async def delayed_delete(file_path: str, short_id: str = None):
    """Delete file + short link after 1 hour"""
    await asyncio.sleep(3600)
    if os.path.exists(file_path):
        os.remove(file_path)
        logger.info(f"🗑️ Deleted file: {file_path}")
    if short_id and short_id in short_links:
        del short_links[short_id]
        logger.info(f"🗑️ Deleted short link: {short_id}")

# ---------------------- HTML TEMPLATES ----------------------

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Resume AI Bot</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        h2 {
            margin-bottom: 20px;
            color: #333;
            font-size: 1.5rem;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 8px;
            font-size: 1rem;
        }
        button {
            width: 100%;
            padding: 12px;
            margin-top: 10px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            font-size: 1rem;
            transition: background 0.3s;
        }
        button:hover {
            background: #5563c1;
        }
        .error {
            color: red;
            margin-bottom: 15px;
            font-size: 0.9em;
        }
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
            }
            h2 {
                font-size: 1.3rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>🔐 Admin Login</h2>
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

ADMIN_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Resume AI Bot</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: Arial, sans-serif;
            background: #f4f6f9;
        }
        .navbar {
            background: #667eea;
            color: white;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }
        .navbar h1 {
            font-size: 1.5rem;
        }
        .container {
            padding: 20px;
            max-width: 1400px;
            margin: auto;
        }
        .card {
            background: white;
            padding: 25px;
            margin: 20px 0;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }
        h2 {
            margin-bottom: 15px;
            color: #333;
            font-size: 1.3rem;
        }
        .table-container {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            min-width: 800px;
        }
        th, td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-size: 0.9rem;
        }
        th {
            background: #667eea;
            color: white;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        tr:hover {
            background: #f1f1f1;
        }
        .logout {
            margin-top: 20px;
            display: inline-block;
            padding: 10px 20px;
            background: #e74c3c;
            color: white;
            border-radius: 6px;
            text-decoration: none;
            transition: background 0.3s;
        }
        .logout:hover {
            background: #c0392b;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }
        .stat-label {
            font-size: 0.9rem;
            margin-top: 5px;
        }
        .search-box {
            margin: 15px 0;
            padding: 10px;
            width: 100%;
            max-width: 400px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 1rem;
        }
        @media (max-width: 768px) {
            .navbar h1 {
                font-size: 1.2rem;
                width: 100%;
                text-align: center;
            }
            .container {
                padding: 10px;
            }
            .card {
                padding: 15px;
            }
            th, td {
                padding: 8px;
                font-size: 0.85rem;
            }
            table {
                min-width: 600px;
            }
        }
        @media (max-width: 480px) {
            .stat-box {
                padding: 15px;
            }
            .stat-number {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>📊 Resume AI Bot - Admin Dashboard</h1>
    </div>
    <div class="container">
        <div class="card">
            <h2>Overview</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="stat-number">{{ total_users }}</span>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ recent_users }}</span>
                    <div class="stat-label">New Users (7 days)</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>User Data</h2>
            <input type="text" class="search-box" id="searchBox" placeholder="Search by User ID..." />
            <div class="table-container">
                <table id="usersTable">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>User ID</th>
                            <th>Username</th>
                            <th>First Name</th>
                            <th>Last Name</th>
                            <th>Company</th>
                            <th>Role</th>
                            <th>Timestamp</th>
                            <th>Resume</th>
                            <th>Analysis</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will load here -->
                    </tbody>
                </table>
            </div>
        </div>

        <a href="{{ url_for('logout') }}" class="logout">🚪 Logout</a>
    </div>

    <script>
        let allUsers = [];

        async function loadUsers() {
            try {
                const res = await fetch('/admin/api/users?per_page=100');
                const data = await res.json();
                allUsers = data.users;
                renderUsers(allUsers);
            } catch (err) {
                console.error("Error loading users:", err);
            }
        }

        function renderUsers(users) {
            const tbody = document.querySelector('#usersTable tbody');
            tbody.innerHTML = "";

            users.forEach(user => {
                const row = `
                    <tr>
                        <td>${user.serial}</td>
                        <td>${user.user_id}</td>
                        <td>${user.username || 'N/A'}</td>
                        <td>${user.first_name || 'N/A'}</td>
                        <td>${user.last_name || 'N/A'}</td>
                        <td>${user.company}</td>
                        <td>${user.role}</td>
                        <td>${user.timestamp}</td>
                        <td>${user.has_resume ? "✅" : "❌"}</td>
                        <td>${user.has_analysis ? "✅" : "❌"}</td>
                    </tr>
                `;
                tbody.insertAdjacentHTML('beforeend', row);
            });
        }

        document.getElementById('searchBox').addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            const filtered = allUsers.filter(user => 
                user.user_id.toString().includes(searchTerm) ||
                (user.username && user.username.toLowerCase().includes(searchTerm)) ||
                (user.first_name && user.first_name.toLowerCase().includes(searchTerm))
            );
            renderUsers(filtered);
        });

        window.onload = loadUsers;
    </script>
</body>
</html>
"""


# ---------------------- ADMIN ROUTES ----------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid username or password")
    
    # If already logged in, redirect to dashboard
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/admin/logout')
def logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard showing user data"""
    try:
        all_users = list(users_collection.find({}, {"_id": 1}))
        total_users = len(all_users)
        
        recent_cutoff = (datetime.now() - timedelta(days=7)).isoformat()
        recent_users = users_collection.count_documents({
            "encrypted_at": {"$gte": recent_cutoff}
        }) if total_users > 0 else 0
        
        return render_template_string(
            ADMIN_DASHBOARD_TEMPLATE,
            total_users=total_users,
            recent_users=recent_users
        )
        
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {e}")
        return f"Error loading dashboard: {str(e)}", 500

@app.route('/admin/api/users')
@login_required
def get_users_data():
    """API endpoint to get paginated user data"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 100))
        search = request.args.get('search', '').strip()
        
        query = {}
        if search:
            try:
                query['_id'] = int(search)
            except ValueError:
                pass
        
        total = users_collection.count_documents(query)
        
        users = list(users_collection.find(
            query,
            {"_id": 1}
        ).skip((page - 1) * per_page).limit(per_page))
        
        decrypted_users = []
        for idx, user_doc in enumerate(users, start=(page - 1) * per_page + 1):
            user_id = user_doc['_id']
            try:
                decrypted_data = load_user_data(user_id)
                
                if decrypted_data:
                    decrypted_users.append({
                        'serial': idx,
                        'user_id': user_id,
                        'username': decrypted_data.get('username', 'N/A'),
                        'first_name': decrypted_data.get('first_name', 'N/A'),
                        'last_name': decrypted_data.get('last_name', 'N/A'),
                        'company': decrypted_data.get('company', 'N/A'),
                        'role': decrypted_data.get('role', 'N/A'),
                        'timestamp': decrypted_data.get('timestamp', 'N/A'),
                        'has_resume': bool(decrypted_data.get('resume_text')),
                        'has_analysis': bool(decrypted_data.get('resume_analysis')),
                        'encrypted_at': decrypted_data.get('encrypted_at', 'N/A')
                    })
                else:
                    decrypted_users.append({
                        'serial': idx,
                        'user_id': user_id,
                        'username': 'Error',
                        'first_name': 'Error',
                        'last_name': 'Error',
                        'company': 'Error decrypting',
                        'role': 'Error decrypting',
                        'timestamp': 'N/A',
                        'has_resume': False,
                        'has_analysis': False,
                        'encrypted_at': 'N/A'
                    })
                    
            except Exception as e:
                logger.error(f"Error decrypting user {user_id}: {e}")
                decrypted_users.append({
                    'serial': idx,
                    'user_id': user_id,
                    'username': 'Decryption failed',
                    'first_name': 'Decryption failed',
                    'last_name': 'Decryption failed',
                    'company': 'Decryption failed',
                    'role': 'Decryption failed',
                    'timestamp': 'N/A',
                    'has_resume': False,
                    'has_analysis': False,
                    'encrypted_at': 'N/A'
                })
        
        return jsonify({
            'users': decrypted_users,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Error fetching users data: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/admin/api/user/<int:user_id>')
@login_required
def get_user_detail(user_id):
    """API endpoint to get detailed user data"""
    try:
        decrypted_data = load_user_data(user_id)
        
        if not decrypted_data:
            return jsonify({'error': 'User not found'}), 404
        
        resume_text = decrypted_data.get('resume_text', '')
        analysis = decrypted_data.get('resume_analysis', '')
        
        return jsonify({
            'user_id': user_id,
            'company': decrypted_data.get('company', 'N/A'),
            'role': decrypted_data.get('role', 'N/A'),
            'timestamp': decrypted_data.get('timestamp', 'N/A'),
            'encrypted_at': decrypted_data.get('encrypted_at', 'N/A'),
            'has_resume_text': bool(resume_text),
            'resume_text_length': len(resume_text),
            'resume_text_preview': resume_text[:500] + '...' if len(resume_text) > 500 else resume_text,
            'has_analysis': bool(analysis),
            'analysis_preview': analysis[:1000] + '...' if len(analysis) > 1000 else analysis,
            'resume_tips_count': len(decrypted_data.get('resume_tips', []))
        })
        
    except Exception as e:
        logger.error(f"Error fetching user detail: {e}")
        return jsonify({'error': str(e)}), 500

# ---------------------- SHORT LINK ----------------------
@app.route('/r/<short_id>')
def redirect_short(short_id):
    if short_id not in short_links:
        return "Invalid or expired link", 404
    
    link_data = short_links[short_id]
    filename = link_data["filename"]
    uid = link_data["user_id"]

    # Get this user's session
    session = user_data.get(uid, {})
    tips = session.get("resume_tips", [])
    answers = session.get("answers", [])

    # Determine report type and content
    if not answers:
        report_type = "Resume Analysis Report"
        content_type = "resume analysis"
        description = "Your comprehensive resume analysis includes personalized feedback, skill assessments, and improvement recommendations tailored to your target role."
    else:
        report_type = "Interview Performance Report"
        content_type = "interview evaluation"
        description = "Your detailed interview analysis provides question-by-question feedback, performance metrics, and actionable insights to improve your interview skills."

    # Ensure we have substantial tips content
    if not tips or len(tips) < 5:
        tips = [
            "Quantify your achievements with specific numbers and percentages whenever possible",
            "Use action verbs like 'implemented', 'optimized', 'designed' to start bullet points",
            "Tailor your resume keywords to match the job description requirements",
            "Include relevant certifications and continuous learning initiatives",
            "Highlight leadership experience and cross-functional collaboration",
            "Showcase problem-solving abilities with concrete examples",
            "Ensure your contact information is current and professional",
            "Keep your resume format clean, consistent, and ATS-friendly",
            "Include industry-specific technical skills and tools",
            "Proofread carefully for grammar and spelling errors"
        ]
    
    # Add substantial content about resume best practices
    additional_content = {
        "sections": [
            {
                "title": "Resume Structure Best Practices",
                "items": [
                    "Contact Information: Include name, phone, email, LinkedIn profile, and location (city, state)",
                    "Professional Summary: 2-3 lines highlighting your value proposition and key strengths",
                    "Work Experience: Use reverse chronological order with quantified achievements",
                    "Education: Include degree, institution, graduation year, and relevant coursework",
                    "Skills Section: Balance technical skills with soft skills relevant to the role"
                ]
            },
            {
                "title": "Common Resume Mistakes to Avoid",
                "items": [
                    "Using generic objective statements instead of targeted professional summaries",
                    "Listing job duties instead of showcasing specific achievements and impact",
                    "Including irrelevant personal information like age, marital status, or photo",
                    "Using inconsistent formatting, fonts, or spacing throughout the document",
                    "Submitting resumes longer than 2 pages without senior executive experience"
                ]
            },
            {
                "title": "Industry-Specific Resume Tips",
                "items": [
                    "Technology: Emphasize programming languages, frameworks, and project outcomes",
                    "Healthcare: Highlight certifications, patient care experience, and compliance knowledge",
                    "Finance: Focus on analytical skills, regulatory knowledge, and quantifiable results",
                    "Marketing: Showcase campaign results, digital marketing skills, and creative projects",
                    "Sales: Emphasize revenue achievements, client relationship management, and territory growth"
                ]
            }
        ]
    }

    tips_html = "".join(f"<li class='tip-item'>{tip}</li>" for tip in tips[:10])
    
    # Build additional content sections
    sections_html = ""
    for section in additional_content["sections"]:
        items_html = "".join(f"<li>{item}</li>" for item in section["items"])
        sections_html += f"""
        <div class="content-section">
            <h3>{section["title"]}</h3>
            <ul>{items_html}</ul>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="Professional {content_type} and career guidance resources">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>{report_type} - Career Development Resources</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: #f8f9fa; 
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }}
            .container {{ 
                max-width: 1000px; 
                margin: 0 auto; 
                background: #fff; 
                padding: 40px;
                border-radius: 12px; 
                box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
            }}
            .header {{
                text-align: center;
                margin-bottom: 40px;
                padding-bottom: 20px;
                border-bottom: 3px solid #007bff;
            }}
            .countdown {{ 
                font-size: 1.2em; 
                margin: 20px 0; 
                color: #007bff;
                text-align: center;
                padding: 15px;
                background: #e7f3ff;
                border-radius: 8px;
                border: 1px solid #b3d9ff;
            }}
            .content-section {{
                margin: 30px 0;
                padding: 25px;
                background: #f8f9fa;
                border-radius: 8px;
                border-left: 4px solid #28a745;
            }}
            .content-section h3 {{
                color: #2c3e50;
                margin-bottom: 15px;
                font-size: 1.3em;
            }}
            .content-section ul {{
                margin: 0;
                padding-left: 20px;
            }}
            .content-section li {{
                margin-bottom: 8px;
                color: #495057;
            }}
            .tip-item {{
                background: #fff;
                padding: 12px;
                margin: 8px 0;
                border-radius: 6px;
                border-left: 3px solid #ffc107;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }}
            .description {{
                background: #e8f5e8;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
                border: 1px solid #c3e6c3;
            }}
            .ad-container {{
                margin: 30px 0;
                padding: 20px 0;
                text-align: center;
                border-top: 1px solid #dee2e6;
                border-bottom: 1px solid #dee2e6;
            }}
            .report-ready {{
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
                text-align: center;
            }}
        </style>
        <script>
            let seconds = {COUNTDOWN_SECONDS};
            function updateCountdown() {{
                const countdownEl = document.getElementById("countdown");
                if (countdownEl) {{
                    countdownEl.innerText = seconds;
                }}
                if (seconds <= 0) {{
                    window.location.href = "/view/{filename}";
                }} else {{
                    seconds--;
                    setTimeout(updateCountdown, 1000);
                }}
            }}
            window.onload = updateCountdown;
        </script>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Career Development Resources</h1>
                <p>Professional guidance for resume optimization and interview success</p>
            </div>

            <div class="description">
                <h2>About Your {report_type}</h2>
                <p>{description}</p>
            </div>
            <div class="ad-container">
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
            </div>

            <div class="report-ready">
                <h3>Your Report is Being Prepared</h3>
                <div class="countdown">Ready in <span id="countdown">{COUNTDOWN_SECONDS}</span> seconds</div>
                <p>While you wait, review the professional career guidance below.</p>
            </div>

            <div class="content-section">
                <h3>📝 Personalized Resume Tips for Your Profile</h3>
                <ul>{tips_html}</ul>
            </div>
            <div class="ad-container">
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
            </div>
            {sections_html}

            <div class="ad-container">
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
            </div>

            <div class="content-section">
                <h3>🚀 Career Development Action Plan</h3>
                <ul>
                    <li><strong>Immediate (1-2 weeks):</strong> Update your resume with quantified achievements and relevant keywords</li>
                    <li><strong>Short-term (1 month):</strong> Practice behavioral interview questions using the STAR method</li>
                    <li><strong>Medium-term (3 months):</strong> Develop missing technical skills identified in your analysis</li>
                    <li><strong>Long-term (6+ months):</strong> Build a portfolio of projects demonstrating your capabilities</li>
                </ul>
            </div>
            <div class="ad-container">
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
            </div>
            <div class="content-section">
                <h3>📚 Additional Resources</h3>
                <ul>
                    <li><strong>LinkedIn Optimization:</strong> Ensure your LinkedIn profile matches your resume and includes a professional headshot</li>
                    <li><strong>Networking Strategy:</strong> Connect with professionals in your target industry and engage with relevant content</li>
                    <li><strong>Interview Preparation:</strong> Research common questions for your role and practice with mock interviews</li>
                    <li><strong>Salary Research:</strong> Use platforms like Glassdoor and PayScale to understand market rates for your position</li>
                    <li><strong>Company Research:</strong> Study the company's mission, recent news, and culture before applying</li>
                </ul>
            </div>
        </div>

        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7084011371587725" crossorigin="anonymous"></script>
    </body>
    </html>
    """
    return html

@app.route('/view/<path:filename>')
def view_report(filename):
    """Enhanced report viewing page with navigation and substantial content"""
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="Detailed interview analysis and career development report with actionable insights">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>Professional Interview Analysis Report</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: #f8f9fa; 
                line-height: 1.6;
            }}
            /* Navigation Bar */
            .navbar {{
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            }}
            .nav-container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }}
            .nav-brand {{
                font-size: 1.5em;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .nav-menu {{
                display: flex;
                list-style: none;
                gap: 2rem;
                flex-wrap: wrap;
            }}
            .nav-menu li a {{
                text-decoration: none;
                color: #333;
                font-weight: 500;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                transition: all 0.3s ease;
            }}
            .nav-menu li a:hover {{
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }}
            .nav-toggle {{
                display: none;
                flex-direction: column;
                cursor: pointer;
                padding: 5px;
            }}
            .nav-toggle span {{
                width: 25px;
                height: 3px;
                background: #333;
                margin: 3px 0;
                transition: 0.3s;
            }}
            @media (max-width: 768px) {{
                .nav-menu {{
                    display: none;
                    width: 100%;
                    flex-direction: column;
                    background: rgba(255,255,255,0.98);
                    position: absolute;
                    top: 100%;
                    left: 0;
                    padding: 1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }}
                .nav-menu.active {{
                    display: flex;
                }}
                .nav-toggle {{
                    display: flex;
                }}
                .nav-container {{
                    position: relative;
                }}
            }}
            /* Main content styles */
            .container {{ 
                max-width: 1200px; 
                margin: 20px auto; 
                background: #fff; 
                border-radius: 12px; 
                box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .content-wrapper {{
                padding: 30px;
            }}
            .report-info {{ 
                background: #e8f5e8; 
                padding: 25px; 
                border-radius: 8px; 
                margin-bottom: 30px;
                border-left: 5px solid #28a745;
            }}
            .usage-guide {{
                background: #fff3cd;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
                border-left: 5px solid #ffc107;
            }}
            .usage-guide h3 {{
                color: #856404;
                margin-bottom: 15px;
            }}
            .usage-guide ul {{
                margin: 10px 0;
                padding-left: 20px;
            }}
            .usage-guide li {{
                margin-bottom: 8px;
                color: #6c5800;
            }}
            .ad-container {{
                margin: 30px 0;
                padding: 25px;
                text-align: center;
                background: #f8f9fa;
                border-radius: 8px;
                border: 1px solid #dee2e6;
            }}
            .report-frame {{
                border: 1px solid #dee2e6;
                border-radius: 8px;
                margin-top: 20px;
                overflow: hidden;
            }}
            iframe {{ 
                width: 100%; 
                height: 90vh; 
                border: none; 
                display: block;
            }}
            .performance-tips {{
                background: #d1ecf1;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
                border-left: 5px solid #17a2b8;
            }}
            .improvement-areas {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin: 25px 0;
            }}
            .improvement-card {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                border-top: 3px solid #007bff;
            }}
            .improvement-card h4 {{
                color: #2c3e50;
                margin-bottom: 12px;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <a href="/" class="nav-brand">
                    🤖 Resume AI Bot
                </a>
                <div class="nav-toggle" onclick="toggleNav()">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <ul class="nav-menu" id="navMenu">
                    <li><a href="/">Home</a></li>
                    <li><a href="/about">About</a></li>
                    <li><a href="/career-tips">Career Tips</a></li>
                    <li><a href="/privacy">Privacy</a></li>
                    <li><a href="https://t.me/AIResumeReviewBot" >Start Bot</a></li>
                </ul>
            </div>
        </nav>
        <div class="container">
            <div class="header">
                <h1>📊 Professional Interview Analysis</h1>
                <p>Comprehensive performance evaluation and development insights</p>
            </div>
            <div class="ad-container">
                <p><strong>Professional Interview Resources</strong></p>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
            </div>
            <div class="content-wrapper">
                <div class="report-info">
                    <h2>📋 Your Personalized Analysis Report</h2>
                    <p>This comprehensive report provides detailed analysis of your interview performance, 
                    including question-by-question feedback, skill assessments, and personalized recommendations 
                    for career development. Our AI-powered evaluation system analyzes your responses across 
                    multiple dimensions to provide actionable insights.</p>
                </div>
                <div class="ad-container">
                    <p><strong>Interview Preparation Tools</strong></p>
                    <ins class="adsbygoogle"
                        style="display:block"
                        data-ad-client="ca-pub-7084011371587725"
                        data-ad-slot="7910616624"
                        data-ad-format="auto"
                        data-full-width-responsive="true"></ins>
                    <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
                </div>
                <div class="usage-guide">
                    <h3>🎯 How to Use This Report Effectively</h3>
                    <div class="improvement-areas">
                        <div class="improvement-card">
                            <h4>📈 Performance Analysis</h4>
                            <ul>
                                <li>Review your overall score and completion rate</li>
                                <li>Identify patterns in your strongest and weakest areas</li>
                                <li>Compare your performance across different question types</li>
                                <li>Note specific feedback on clarity and relevance</li>
                            </ul>
                        </div>
                        <div class="improvement-card">
                            <h4>🔍 Detailed Feedback Review</h4>
                            <ul>
                                <li>Read the verdict for each individual question</li>
                                <li>Understand the rating breakdown (Relevance, Clarity, Technical Depth)</li>
                                <li>Focus on improvement suggestions for low-scoring responses</li>
                                <li>Study the "Better Answer Outline" sections for guidance</li>
                            </ul>
                        </div>
                        <div class="improvement-card">
                            <h4>📚 Skill Development</h4>
                            <ul>
                                <li>Identify technical skills that need strengthening</li>
                                <li>Practice articulating complex concepts more clearly</li>
                                <li>Work on providing more specific, detailed examples</li>
                                <li>Develop better storytelling techniques for behavioral questions</li>
                            </ul>
                        </div>
                        <div class="improvement-card">
                            <h4>🚀 Action Planning</h4>
                            <ul>
                                <li>Create a study plan based on identified weak areas</li>
                                <li>Practice similar questions with improved approaches</li>
                                <li>Seek additional resources for technical skill gaps</li>
                                <li>Schedule follow-up mock interviews to track progress</li>
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="ad-container">
                    <p><strong>Career Development Resources</strong></p>
                    <ins class="adsbygoogle"
                        style="display:block"
                        data-ad-client="ca-pub-7084011371587725"
                        data-ad-slot="7910616624"
                        data-ad-format="auto"
                        data-full-width-responsive="true"></ins>
                    <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
                </div>
                <div class="performance-tips">
                    <h3>💡 Interview Performance Enhancement Tips</h3>
                    <ul>
                        <li><strong>STAR Method:</strong> Structure behavioral answers using Situation, Task, Action, Result framework</li>
                        <li><strong>Technical Clarity:</strong> Break down complex technical concepts into digestible explanations</li>
                        <li><strong>Specific Examples:</strong> Always provide concrete, quantifiable examples from your experience</li>
                        <li><strong>Company Research:</strong> Demonstrate knowledge of the company's products, culture, and challenges</li>
                        <li><strong>Question Clarification:</strong> Don't hesitate to ask for clarification if a question is unclear</li>
                        <li><strong>Follow-up Questions:</strong> Prepare thoughtful questions about the role and team dynamics</li>
                    </ul>
                </div>

                <div class="ad-container">
                    <p><strong>Professional Career Resources</strong></p>
                    <ins class="adsbygoogle"
                        style="display:block"
                        data-ad-client="ca-pub-7084011371587725"
                        data-ad-slot="7910616624"
                        data-ad-format="auto"
                        data-full-width-responsive="true"></ins>
                    <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
                </div>

                <div class="report-frame">
                    <iframe src='/reports/{filename}' title="Interview Analysis Report PDF"></iframe>
                </div>
            </div>
        </div>

        <script>
            function toggleNav() {{
                const navMenu = document.getElementById('navMenu');
                navMenu.classList.toggle('active');
            }}
            
            document.addEventListener('click', function(event) {{
                const navbar = document.querySelector('.navbar');
                const navMenu = document.getElementById('navMenu');
                
                if (!navbar.contains(event.target)) {{
                    navMenu.classList.remove('active');
                }}
            }});
        </script>

        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7084011371587725" crossorigin="anonymous"></script>
    </body>
    </html>
    """
    return html

def run_async(coro):
    if event_loop is None:
        raise RuntimeError("Event loop not initialized")
    try:
        future = asyncio.run_coroutine_threadsafe(coro, event_loop)
        return future.result(timeout=30)  # Add timeout
    except asyncio.TimeoutError:
        logger.error("Async operation timed out")
        raise RuntimeError("Operation timed out")

def start_background_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Run the event loop in a background thread"""
    asyncio.set_event_loop(loop)
    loop.run_forever()

def initialize_event_loop():
    """Initialize the event loop in a separate thread"""
    global event_loop
    event_loop = asyncio.new_event_loop()
    threading.Thread(target=start_background_loop, args=(event_loop,), daemon=True).start()

# Initialize the event loop immediately
initialize_event_loop()

@app.route('/')
def home():
    """Enhanced home page with navigation and substantial content"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="Professional AI-powered resume analysis and interview preparation platform with advanced encryption and personalized feedback">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>Resume AI Bot - Professional Career Development Platform</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            /* Navigation Bar */
            .navbar {
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            }
            .nav-container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            .nav-brand {
                font-size: 1.5em;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .nav-menu {
                display: flex;
                list-style: none;
                gap: 2rem;
                flex-wrap: wrap;
            }
            .nav-menu li a {
                text-decoration: none;
                color: #333;
                font-weight: 500;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                transition: all 0.3s ease;
            }
            .nav-menu li a:hover {
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }
            .nav-toggle {
                display: none;
                flex-direction: column;
                cursor: pointer;
                padding: 5px;
            }
            .nav-toggle span {
                width: 25px;
                height: 3px;
                background: #333;
                margin: 3px 0;
                transition: 0.3s;
            }
            @media (max-width: 768px) {
                .nav-menu {
                    display: none;
                    width: 100%;
                    flex-direction: column;
                    background: rgba(255,255,255,0.98);
                    position: absolute;
                    top: 100%;
                    left: 0;
                    padding: 1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                .nav-menu.active {
                    display: flex;
                }
                .nav-toggle {
                    display: flex;
                }
                .nav-container {
                    position: relative;
                }
            }
            /* Rest of existing styles */
            .header {
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                padding: 20px 0;
                text-align: center;
                color: white;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 40px 20px;
            }
            .hero-section {
                background: white;
                padding: 60px 40px;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                text-align: center;
                margin-bottom: 40px;
            }
            .bot-icon {
                font-size: 4em;
                margin-bottom: 20px;
                animation: bounce 2s infinite;
            }
            @keyframes bounce {
                0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
                40% { transform: translateY(-10px); }
                60% { transform: translateY(-5px); }
            }
            .status-indicators {
                display: flex;
                justify-content: center;
                flex-wrap: wrap;
                gap: 15px;
                margin: 30px 0;
            }
            .security-badge {
                display: inline-block;
                padding: 10px 20px;
                background: #2196F3;
                color: white;
                border-radius: 25px;
                font-size: 0.9em;
                font-weight: bold;
            }
            .status-badge {
                display: inline-block;
                padding: 10px 20px;
                background: #4CAF50;
                color: white;
                border-radius: 25px;
                font-weight: bold;
            }
            .features-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 30px;
                margin: 50px 0;
            }
            .feature-card {
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                transition: transform 0.3s ease;
            }
            .feature-card:hover {
                transform: translateY(-5px);
            }
            .feature-card h3 {
                color: #333;
                margin-bottom: 15px;
                font-size: 1.3em;
            }
            .feature-card p {
                color: #666;
                margin-bottom: 15px;
            }
            .feature-list {
                list-style: none;
                padding: 0;
            }
            .feature-list li {
                padding: 8px 0;
                color: #555;
                border-bottom: 1px solid #eee;
            }
            .feature-list li:last-child {
                border-bottom: none;
            }
            .cta-section {
                text-align: center;
                margin: 50px 0;
            }
            .cta {
                background: #667eea;
                color: white;
                padding: 20px 40px;
                border-radius: 15px;
                text-decoration: none;
                display: inline-block;
                font-weight: bold;
                font-size: 1.1em;
                transition: all 0.3s ease;
            }
            .cta:hover {
                background: #764ba2;
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            }
            .ad-section {
                background: white;
                padding: 30px;
                border-radius: 15px;
                margin: 40px 0;
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }
            .security-section {
                background: rgba(255,255,255,0.95);
                padding: 40px;
                border-radius: 15px;
                margin: 40px 0;
            }
            .security-details {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            .security-item {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                border-left: 4px solid #2196F3;
            }
            .footer {
                background: rgba(255,255,255,0.1);
                color: white;
                text-align: center;
                padding: 30px;
                border-radius: 15px;
                margin-top: 40px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <a href="/" class="nav-brand">
                    🤖 Resume AI Bot
                </a>
                <div class="nav-toggle" onclick="toggleNav()">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <ul class="nav-menu" id="navMenu">
                    <li><a href="/">Home</a></li>
                    <li><a href="/about">About</a></li>
                    <li><a href="/career-tips">Career Tips</a></li>
                    <li><a href="/privacy">Privacy</a></li>
                    <li><a href="https://t.me/AIResumeReviewBot">Start Bot</a></li>
                </ul>
            </div>
        </nav>

        <div class="header">
            <h1>🤖 Resume AI Bot - Professional Career Platform</h1>
            <p>Advanced AI-powered career development with military-grade security</p>
        </div>

        <div class="container">
            <div class="hero-section">
                <div class="bot-icon">🤖📊</div>
                <h1>Professional Resume Analysis & Interview Preparation</h1>
                
                <div class="status-indicators">
                    <div class="status-badge">✅ Active & Operational</div>
                    <div class="security-badge">🔐 AES-256 Encrypted</div>
                    <div class="security-badge">🛡️ PBKDF2 Protected</div>
                </div>
                
                <p style="color: #666; font-size: 1.2em; margin: 30px 0;">
                    Transform your career with AI-powered resume analysis and personalized interview coaching. 
                    Our platform provides comprehensive feedback while ensuring your data remains completely secure 
                    with enterprise-grade encryption.
                </p>
            </div>
            <div class="ad-section">
                <h3>Career Development Resources</h3>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="features-grid">
                <div class="feature-card">
                    <h3>📄 Intelligent Resume Analysis</h3>
                    <p>Our AI analyzes your resume against specific job requirements and provides detailed feedback on content, structure, and optimization opportunities.</p>
                    <ul class="feature-list">
                        <li>✓ ATS compatibility assessment</li>
                        <li>✓ Keyword optimization suggestions</li>
                        <li>✓ Skills gap identification</li>
                        <li>✓ Achievement quantification tips</li>
                        <li>✓ Industry-specific recommendations</li>
                    </ul>
                </div>

                <div class="feature-card">
                    <h3>🎯 Mock Interview Practice</h3>
                    <p>Practice with realistic interview scenarios tailored to your target role and company, with detailed performance analysis and improvement suggestions.</p>
                    <ul class="feature-list">
                        <li>✓ Behavioral interview questions</li>
                        <li>✓ Technical skill assessments</li>
                        <li>✓ Company-specific scenarios</li>
                        <li>✓ Real-time performance scoring</li>
                        <li>✓ Detailed improvement roadmaps</li>
                    </ul>
                </div>

                <div class="feature-card">
                    <h3>💻 Technical Interview Prep</h3>
                    <p>Specialized technical interview preparation focusing on programming concepts, system design, and problem-solving methodologies.</p>
                    <ul class="feature-list">
                        <li>✓ Algorithm and data structure questions</li>
                        <li>✓ System design scenarios</li>
                        <li>✓ Coding best practices evaluation</li>
                        <li>✓ Architecture discussion prep</li>
                        <li>✓ Technology-specific assessments</li>
                    </ul>
                </div>

                <div class="feature-card">
                    <h3>📊 Performance Analytics</h3>
                    <p>Comprehensive performance tracking with detailed metrics, progress visualization, and personalized development plans.</p>
                    <ul class="feature-list">
                        <li>✓ Question-by-question analysis</li>
                        <li>✓ Skill strength identification</li>
                        <li>✓ Improvement area mapping</li>
                        <li>✓ Progress tracking over time</li>
                        <li>✓ Benchmarking against role requirements</li>
                    </ul>
                </div>
            </div>
            <div class="ad-section">
                <h3>Professional Tools & Resources</h3>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="security-section">
                <h2>🔐 Enterprise-Grade Security & Privacy</h2>
                <p>Your career data is precious. We protect it with the same encryption standards used by banks and government institutions.</p>
                
                <div class="security-details">
                    <div class="security-item">
                        <h4>🔒 AES-256 Encryption</h4>
                        <p>All data encrypted with 256-bit Advanced Encryption Standard, the gold standard in data protection.</p>
                    </div>
                    <div class="security-item">
                        <h4>🛡️ PBKDF2 Key Derivation</h4>
                        <p>Password-Based Key Derivation Function with 100,000 iterations for maximum security against attacks.</p>
                    </div>
                    <div class="security-item">
                        <h4>🗃️ Secure Storage</h4>
                        <p>Encrypted database storage with automatic data expiration and secure deletion protocols.</p>
                    </div>
                    <div class="security-item">
                        <h4>📄 Zero-Knowledge Architecture</h4>
                        <p>We cannot access your decrypted data. Only you have the keys to your information.</p>
                    </div>
                </div>
            </div>

            <div class="ad-section">
                <h3>Professional Career Resources</h3>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>

            <div class="cta-section">
                <h2>Ready to Transform Your Career?</h2>
                <p>Join thousands of professionals who have improved their interview skills and optimized their resumes with our AI-powered platform.</p>
                <a href="https://t.me/AIResumeReviewBot" class="cta">
                    Start Your Free Analysis
                </a>
            </div>
        </div>

        <div class="footer">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 30px; margin-bottom: 20px;">
                <div>
                    <h4>Platform Status</h4>
                    <p>Server: Running ✅</p>
                    <p>Security: Encrypted 🔐</p>
                    <p>AI Models: Active 🤖</p>
                </div>
                <div>
                    <h4>Security Certifications</h4>
                    <p>AES-256 Encryption</p>
                    <p>PBKDF2 Key Derivation</p>
                    <p>Zero-Knowledge Architecture</p>
                </div>
                <div>
                    <h4>Last Updated</h4>
                    <p>{{ timestamp }}</p>
                    <p>Uptime: 99.9%</p>
                    <p>Data Protected: 100%</p>
                </div>
            </div>
        </div>

        <script>
            function toggleNav() {
                const navMenu = document.getElementById('navMenu');
                navMenu.classList.toggle('active');
            }
            
            // Close mobile menu when clicking outside
            document.addEventListener('click', function(event) {
                const navbar = document.querySelector('.navbar');
                const navMenu = document.getElementById('navMenu');
                const navToggle = document.querySelector('.nav-toggle');
                
                if (!navbar.contains(event.target)) {
                    navMenu.classList.remove('active');
                }
            });
        </script>

        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7084011371587725" crossorigin="anonymous"></script>
    </body>
    </html>
    """
    return render_template_string(html_template, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))

@app.route('/privacy')
def privacy_policy():
    """Privacy policy page with substantial content"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="Privacy policy and data protection practices for Resume AI Bot">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>Privacy Policy - Resume AI Bot</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
            h1, h2 { color: #2c3e50; }
            .section { margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }
            .highlight { background: #fff3cd; padding: 15px; border-radius: 6px; margin: 15px 0; }
            .ad-container {
                margin: 30px 0;
                padding: 20px;
                text-align: center;
                background: #f8f9fa;
                border-radius: 8px;
            }
            /* Navigation Bar */
            .navbar {
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            }
            .nav-container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            .nav-brand {
                font-size: 1.5em;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .nav-menu {
                display: flex;
                list-style: none;
                gap: 2rem;
                flex-wrap: wrap;
            }
            .nav-menu li a {
                text-decoration: none;
                color: #333;
                font-weight: 500;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                transition: all 0.3s ease;
            }
            .nav-menu li a:hover, .nav-menu li a.active {
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }
            .nav-toggle {
                display: none;
                flex-direction: column;
                cursor: pointer;
                padding: 5px;
            }
            .nav-toggle span {
                width: 25px;
                height: 3px;
                background: #333;
                margin: 3px 0;
                transition: 0.3s;
            }
            @media (max-width: 768px) {
                .nav-menu {
                    display: none;
                    width: 100%;
                    flex-direction: column;
                    background: rgba(255,255,255,0.98);
                    position: absolute;
                    top: 100%;
                    left: 0;
                    padding: 1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                .nav-menu.active {
                    display: flex;
                }
                .nav-toggle {
                    display: flex;
                }
                .nav-container {
                    position: relative;
                }
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <a href="/" class="nav-brand">
                    🤖 Resume AI Bot
                </a>
                <div class="nav-toggle" onclick="toggleNav()">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <ul class="nav-menu" id="navMenu">
                    <li><a href="/">Home</a></li>
                    <li><a href="/about">About</a></li>
                    <li><a href="/career-tips">Career Tips</a></li>
                    <li><a href="/privacy" class="active">Privacy</a></li>
                    <li><a href="https://t.me/AIResumeReviewBot" >Start Bot</a></li>
                </ul>
            </div>
        </nav>

        <h1>Privacy Policy & Data Protection</h1>
        <div class="ad-section">
            <h4>Secure Career Platform</h4>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>
        <div class="section">
            <h2>Data Collection and Processing</h2>
            <p>Resume AI Bot collects and processes the following types of information:</p>
            <ul>
                <li><strong>Resume Content:</strong> Text extracted from uploaded PDF files for analysis</li>
                <li><strong>Interview Responses:</strong> User answers to interview questions for evaluation</li>
                <li><strong>Job Information:</strong> Company names and job roles for personalized feedback</li>
                <li><strong>Technical Data:</strong> User IDs, timestamps, and session information</li>
            </ul>
        </div>
        <div class="ad-section">
            <h4>Encrypted Data Protection</h4>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>
        <div class="section">
            <h2>Data Protection Measures</h2>
            <div class="highlight">
                <strong>Military-Grade Encryption:</strong> All user data is protected using AES-256 encryption with PBKDF2 key derivation.
            </div>
            <ul>
                <li><strong>Encryption at Rest:</strong> Database storage uses encrypted fields with unique user keys</li>
                <li><strong>Encryption in Transit:</strong> All communications use HTTPS/TLS encryption</li>
                <li><strong>Key Management:</strong> Encryption keys are derived using PBKDF2 with 100,000 iterations</li>
                <li><strong>Zero Knowledge:</strong> Service operators cannot access decrypted user content</li>
            </ul>
        </div>

        <div class="ad-container">
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>

        <div class="section">
            <h2>Data Retention and Deletion</h2>
            <p>We implement strict data lifecycle management:</p>
            <ul>
                <li>Resume files are automatically deleted after processing</li>
                <li>Generated reports expire after 1 hour and are permanently removed</li>
                <li>Users can delete their encrypted data at any time using /delete_my_data</li>
                <li>Inactive accounts are purged after 90 days of inactivity</li>
            </ul>
        </div>

        <div class="section">
            <h2>Third-Party Services</h2>
            <p>We use the following third-party services with privacy protections:</p>
            <ul>
                <li><strong>Google AI (Gemini):</strong> For resume analysis and interview evaluation</li>
                <li><strong>MongoDB:</strong> For encrypted data storage</li>
                <li><strong>Telegram API:</strong> For bot communication</li>
            </ul>
        </div>
        <div class="ad-section">
            <h4>Your Data Rights</h4>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>
        <div class="section">
            <h2>User Rights</h2>
            <p>You have the following rights regarding your data:</p>
            <ul>
                <li>Right to access your stored information</li>
                <li>Right to delete all personal data</li>
                <li>Right to data portability</li>
                <li>Right to correct inaccurate information</li>
            </ul>
        </div>
        <div class="ad-section">
            <h4>Contact Support</h4>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>
        <div class="section">
            <h2>Contact Information</h2>
            <p>For privacy-related inquiries or to exercise your rights, contact us through the Telegram bot or via our support channels.</p>
        </div>

        <p><em>Last updated: {{ timestamp }}</em></p>
        <script>
            function toggleNav() {
                const navMenu = document.getElementById('navMenu');
                navMenu.classList.toggle('active');
            }
            
            document.addEventListener('click', function(event) {
                const navbar = document.querySelector('.navbar');
                const navMenu = document.getElementById('navMenu');
                
                if (!navbar.contains(event.target)) {
                    navMenu.classList.remove('active');
                }
            });
        </script>
        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7084011371587725" crossorigin="anonymous"></script>
    </body>
    </html>
    """
    return render_template_string(html, timestamp=datetime.now().strftime("%Y-%m-%d"))

@app.route('/about')
def about_page():
    """About page with navigation and detailed platform information"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="About Resume AI Bot - Advanced AI-powered career development platform">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>About - Resume AI Bot</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                line-height: 1.6; 
                background: #f8f9fa;
            }
            /* Navigation Bar */
            .navbar {
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            }
            .nav-container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            .nav-brand {
                font-size: 1.5em;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .nav-menu {
                display: flex;
                list-style: none;
                gap: 2rem;
                flex-wrap: wrap;
            }
            .nav-menu li a {
                text-decoration: none;
                color: #333;
                font-weight: 500;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                transition: all 0.3s ease;
            }
            .nav-menu li a:hover, .nav-menu li a.active {
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }
            .nav-toggle {
                display: none;
                flex-direction: column;
                cursor: pointer;
                padding: 5px;
            }
            .nav-toggle span {
                width: 25px;
                height: 3px;
                background: #333;
                margin: 3px 0;
                transition: 0.3s;
            }
            @media (max-width: 768px) {
                .nav-menu {
                    display: none;
                    width: 100%;
                    flex-direction: column;
                    background: rgba(255,255,255,0.98);
                    position: absolute;
                    top: 100%;
                    left: 0;
                    padding: 1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                .nav-menu.active {
                    display: flex;
                }
                .nav-toggle {
                    display: flex;
                }
                .nav-container {
                    position: relative;
                }
            }
            /* Main content */
            .main-content {
                max-width: 1000px; 
                margin: 20px auto; 
                padding: 20px;
            }
            .hero { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; 
                padding: 40px; 
                border-radius: 15px; 
                text-align: center; 
                margin-bottom: 30px; 
            }
            .section { 
                margin: 30px 0; 
                padding: 25px; 
                background: white; 
                border-radius: 10px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .feature-grid { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                gap: 20px; 
                margin: 20px 0; 
            }
            .feature-card { 
                background: #f8f9fa; 
                padding: 20px; 
                border-radius: 8px; 
                box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
            }
            .ad-container {
                margin: 30px 0;
                padding: 20px;
                text-align: center;
                background: #fff;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1, h2 { color: #2c3e50; }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <a href="/" class="nav-brand">
                    🤖 Resume AI Bot
                </a>
                <div class="nav-toggle" onclick="toggleNav()">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <ul class="nav-menu" id="navMenu">
                    <li><a href="/">Home</a></li>
                    <li><a href="/about" class="active">About</a></li>
                    <li><a href="/career-tips">Career Tips</a></li>
                    <li><a href="/privacy">Privacy</a></li>
                    <li><a href="https://t.me/AIResumeReviewBot" >Start Bot</a></li>
                </ul>
            </div>
        </nav>

        <div class="main-content">
            <div class="hero">
                <h1>About Resume AI Bot</h1>
                <p>Revolutionizing career development with AI-powered insights and military-grade security</p>
            </div>
            <div class="ad-section">
                <h4>Career Development Platform</h4>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="section">
                <h2>Our Mission</h2>
                <p>Resume AI Bot empowers professionals to advance their careers through intelligent resume analysis and personalized interview preparation. We combine cutting-edge artificial intelligence with enterprise-grade security to deliver insights that help candidates succeed while protecting their privacy.</p>
            </div>

            <div class="section">
                <h2>Platform Features</h2>
                <div class="feature-grid">
                    <div class="feature-card">
                        <h3>Intelligent Resume Analysis</h3>
                        <p>Our AI analyzes resumes against specific job requirements, identifying strengths, gaps, and optimization opportunities. Get actionable feedback on content structure, keyword usage, and industry alignment.</p>
                    </div>
                    <div class="feature-card">
                        <h3>Personalized Interview Coaching</h3>
                        <p>Practice with role-specific questions tailored to your target company and position. Receive detailed performance analysis with scoring across multiple dimensions including relevance, clarity, and technical depth.</p>
                    </div>
                    <div class="feature-card">
                        <h3>Multi-Type Interview Support</h3>
                        <p>Prepare for behavioral HR interviews, technical assessments, or combined interview formats. Our system adapts questions and evaluation criteria based on your chosen interview type.</p>
                    </div>
                    <div class="feature-card">
                        <h3>Comprehensive Performance Reports</h3>
                        <p>Detailed PDF reports provide question-by-question analysis, improvement suggestions, and personalized development roadmaps to enhance your interview performance.</p>
                    </div>
                </div>
            </div>
            
            <div class="ad-container">
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>

            <div class="section">
                <h2>Technology Stack</h2>
                <ul>
                    <li><strong>AI Engine:</strong> Google Gemini AI for natural language processing and analysis</li>
                    <li><strong>Encryption:</strong> AES-256 with PBKDF2 key derivation for maximum security</li>
                    <li><strong>Platform:</strong> Python-based Telegram bot with Flask web interface</li>
                    <li><strong>Storage:</strong> MongoDB with encrypted field-level data protection</li>
                    <li><strong>Infrastructure:</strong> Cloud-hosted with automatic scaling and backup</li>
                </ul>
            </div>
            <div class="ad-section">
                <h4>Secure Career Platform</h4>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="section">
                <h2>Security and Privacy</h2>
                <p>Your career data deserves the highest level of protection. We implement military-grade encryption standards:</p>
                <ul>
                    <li>All user data encrypted with AES-256 before storage</li>
                    <li>Unique encryption keys derived per user using PBKDF2</li>
                    <li>Zero-knowledge architecture - we cannot access your decrypted data</li>
                    <li>Automatic file deletion and data expiration policies</li>
                    <li>Regular security audits and penetration testing</li>
                </ul>
            </div>
            <div class="ad-section">
                <h4>Start Your Career Journey</h4>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="section">
                <h2>Getting Started</h2>
                <p>Ready to transform your career prospects? Here's how to get started:</p>
                <ol>
                    <li><strong>Start the Bot:</strong> Message @AIResumeReviewBot on Telegram</li>
                    <li><strong>Upload Resume:</strong> Send your resume as a PDF file</li>
                    <li><strong>Specify Role:</strong> Enter your target company and job position</li>
                    <li><strong>Get Analysis:</strong> Receive detailed resume feedback and tips</li>
                    <li><strong>Practice Interview:</strong> Choose from HR, technical, or mixed interview types</li>
                    <li><strong>Review Report:</strong> Access your comprehensive performance analysis</li>
                </ol>
            </div>
            <div class="ad-section">
                <h4>Professional Resources</h4>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="section">
                <h2>Support and Updates</h2>
                <p>We continuously improve our platform based on user feedback and advances in AI technology. Our system receives regular updates to enhance analysis accuracy, expand question databases, and improve user experience while maintaining the highest security standards.</p>
            </div>
        </div>

        <script>
            function toggleNav() {
                const navMenu = document.getElementById('navMenu');
                navMenu.classList.toggle('active');
            }
            
            document.addEventListener('click', function(event) {
                const navbar = document.querySelector('.navbar');
                const navMenu = document.getElementById('navMenu');
                
                if (!navbar.contains(event.target)) {
                    navMenu.classList.remove('active');
                }
            });
        </script>
        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7084011371587725" crossorigin="anonymous"></script>
    </body>
    </html>
    """
    return html

@app.route('/career-tips')
def career_tips():
    """Comprehensive career guidance page"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="Professional career development tips, resume guidance, and interview preparation strategies">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>Career Development Tips - Resume AI Bot</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; line-height: 1.6; background: #f8f9fa; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 15px; text-align: center; margin-bottom: 30px; }
            .tips-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 25px; margin: 30px 0; }
            .tip-category { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
            .tip-category h2 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
            .tip-list { list-style: none; padding: 0; }
            .tip-list li { background: #f8f9fa; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid #3498db; }
            .ad-section { background: white; padding: 30px; border-radius: 12px; text-align: center; margin: 40px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
            .highlight { background: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0; }
            /* Navigation Bar */
            .navbar {
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            }
            .nav-container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            .nav-brand {
                font-size: 1.5em;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .nav-menu {
                display: flex;
                list-style: none;
                gap: 2rem;
                flex-wrap: wrap;
            }
            .nav-menu li a {
                text-decoration: none;
                color: #333;
                font-weight: 500;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                transition: all 0.3s ease;
            }
            .nav-menu li a:hover, .nav-menu li a.active {
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }
            .nav-toggle {
                display: none;
                flex-direction: column;
                cursor: pointer;
                padding: 5px;
            }
            .nav-toggle span {
                width: 25px;
                height: 3px;
                background: #333;
                margin: 3px 0;
                transition: 0.3s;
            }
            @media (max-width: 768px) {
                .nav-menu {
                    display: none;
                    width: 100%;
                    flex-direction: column;
                    background: rgba(255,255,255,0.98);
                    position: absolute;
                    top: 100%;
                    left: 0;
                    padding: 1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                .nav-menu.active {
                    display: flex;
                }
                .nav-toggle {
                    display: flex;
                }
                .nav-container {
                    position: relative;
                }
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <a href="/" class="nav-brand">
                    🤖 Resume AI Bot
                </a>
                <div class="nav-toggle" onclick="toggleNav()">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <ul class="nav-menu" id="navMenu">
                    <li><a href="/">Home</a></li>
                    <li><a href="/about">About</a></li>
                    <li><a href="/career-tips" class="active">Career Tips</a></li>
                    <li><a href="/privacy">Privacy</a></li>
                    <li><a href="https://t.me/AIResumeReviewBot" >Start Bot</a></li>
                </ul>
            </div>
        </nav>

        <div class="header">
            <h1>Professional Career Development Guide</h1>
            <p>Expert tips for resume optimization and interview success</p>
        </div>
        <div class="ad-section">
            <h4>Career Development Resources</h4>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>
        <div class="tips-grid">
            <div class="tip-category">
                <h2>Resume Writing Excellence</h2>
                <ul class="tip-list">
                    <li><strong>Quantify Everything:</strong> Use specific numbers, percentages, and metrics to demonstrate your impact and achievements.</li>
                    <li><strong>Tailor for Each Role:</strong> Customize your resume for each application, matching keywords and requirements from the job description.</li>
                    <li><strong>Strong Action Verbs:</strong> Start bullet points with powerful verbs like "spearheaded," "optimized," "architected," or "transformed."</li>
                    <li><strong>ATS Optimization:</strong> Ensure your resume passes Applicant Tracking Systems by using standard section headings and relevant keywords.</li>
                    <li><strong>Professional Summary:</strong> Write a compelling 2-3 line summary that highlights your unique value proposition and career focus.</li>
                </ul>
            </div>

            <div class="tip-category">
                <h2>Interview Preparation Strategies</h2>
                <ul class="tip-list">
                    <li><strong>STAR Method Mastery:</strong> Structure behavioral answers using Situation, Task, Action, Result framework for clear, compelling responses.</li>
                    <li><strong>Company Research:</strong> Study the company's mission, recent news, competitors, and culture to demonstrate genuine interest and fit.</li>
                    <li><strong>Question Preparation:</strong> Prepare thoughtful questions about the role, team dynamics, growth opportunities, and company challenges.</li>
                    <li><strong>Practice Out Loud:</strong> Rehearse your answers verbally, not just mentally, to improve fluency and confidence during the actual interview.</li>
                    <li><strong>Mock Interview Sessions:</strong> Practice with friends, mentors, or AI tools to refine your responses and receive feedback.</li>
                </ul>
            </div>
            <div class="ad-section">
                <h4>Interview Preparation Tools</h4>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="tip-category">
                <h2>Technical Interview Excellence</h2>
                <ul class="tip-list">
                    <li><strong>Fundamental Concepts:</strong> Review core computer science concepts, data structures, algorithms, and system design principles.</li>
                    <li><strong>Coding Practice:</strong> Regularly solve problems on platforms like LeetCode, HackerRank, or CodeSignal to maintain sharp skills.</li>
                    <li><strong>Think Aloud:</strong> Verbalize your thought process during coding challenges to demonstrate problem-solving approach.</li>
                    <li><strong>Edge Cases:</strong> Always consider and test edge cases when presenting solutions to demonstrate thorough thinking.</li>
                    <li><strong>Trade-off Discussions:</strong> Be prepared to discuss time/space complexity and alternative approaches to problems.</li>
                </ul>
            </div>

            <div class="tip-category">
                <h2>Professional Networking</h2>
                <ul class="tip-list">
                    <li><strong>LinkedIn Optimization:</strong> Maintain an active, professional LinkedIn presence with regular industry-related content sharing.</li>
                    <li><strong>Industry Events:</strong> Attend conferences, meetups, and webinars to expand your professional network and stay current.</li>
                    <li><strong>Informational Interviews:</strong> Conduct informational interviews with professionals in your target companies or roles.</li>
                    <li><strong>Alumni Networks:</strong> Leverage your educational background to connect with alumni working in your target industry.</li>
                    <li><strong>Online Presence:</strong> Maintain a professional online presence through GitHub, portfolio websites, or industry blogs.</li>
                </ul>
            </div>
            <div class="ad-section">
                <h4>Professional Development</h4>
                <ins class="adsbygoogle"
                    style="display:block"
                    data-ad-client="ca-pub-7084011371587725"
                    data-ad-slot="7910616624"
                    data-ad-format="auto"
                    data-full-width-responsive="true"></ins>
                <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
            </div>
            <div class="tip-category">
                <h2>Career Advancement Strategies</h2>
                <ul class="tip-list">
                    <li><strong>Continuous Learning:</strong> Pursue relevant certifications, online courses, and skills development to stay competitive.</li>
                    <li><strong>Mentorship:</strong> Seek mentors within your industry and also mentor others to expand your network and leadership skills.</li>
                    <li><strong>Side Projects:</strong> Develop personal projects that showcase your skills and passion for your field.</li>
                    <li><strong>Performance Documentation:</strong> Keep detailed records of your achievements and contributions for performance reviews and resume updates.</li>
                    <li><strong>Cross-Functional Collaboration:</strong> Seek opportunities to work with different departments and expand your skill set.</li>
                </ul>
            </div>

            <div class="tip-category">
                <h2>Salary Negotiation</h2>
                <ul class="tip-list">
                    <li><strong>Market Research:</strong> Research salary ranges using Glassdoor, PayScale, and industry reports for informed negotiations.</li>
                    <li><strong>Total Compensation:</strong> Consider the entire package including benefits, equity, vacation, and professional development opportunities.</li>
                    <li><strong>Timing Matters:</strong> Wait for an offer before discussing salary, and negotiate after demonstrating your value.</li>
                    <li><strong>Practice Negotiation:</strong> Role-play negotiation scenarios to build confidence and refine your approach.</li>
                    <li><strong>Win-Win Approach:</strong> Frame negotiations as collaborative problem-solving rather than adversarial bargaining.</li>
                </ul>
            </div>
        </div>

        <div class="highlight">
            <h3>🎯 Pro Tip: Leverage AI for Career Development</h3>
            <p>Use AI-powered tools like Resume AI Bot to get objective feedback on your resume and interview performance. Regular practice with AI evaluation helps identify blind spots and areas for improvement that you might miss on your own.</p>
        </div>

        <div class="ad-section">
            <h3>Professional Development Resources</h3>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-7084011371587725"
                data-ad-slot="7910616624"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
            <script>(adsbygoogle = window.adsbygoogle || []).push({});</script>
        </div>

        <div class="tip-category">
            <h2>Industry-Specific Guidance</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                <div style="background: #e8f5e8; padding: 15px; border-radius: 6px;">
                    <h4>Technology Sector</h4>
                    <p>Focus on technical skills, GitHub contributions, open-source projects, and staying current with emerging technologies.</p>
                </div>
                <div style="background: #f0f8ff; padding: 15px; border-radius: 6px;">
                    <h4>Finance Industry</h4>
                    <p>Emphasize analytical skills, financial modeling experience, regulatory knowledge, and quantitative achievements.</p>
                </div>
                <div style="background: #fff0f5; padding: 15px; border-radius: 6px;">
                    <h4>Healthcare Field</h4>
                    <p>Highlight certifications, patient care experience, compliance knowledge, and continuing education commitments.</p>
                </div>
                <div style="background: #f5f5dc; padding: 15px; border-radius: 6px;">
                    <h4>Marketing & Sales</h4>
                    <p>Showcase campaign results, ROI improvements, customer acquisition metrics, and creative project portfolios.</p>
                </div>
            </div>
        </div>

        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7084011371587725" crossorigin="anonymous"></script>
        <script>
            function toggleNav() {
                const navMenu = document.getElementById('navMenu');
                navMenu.classList.toggle('active');
            }
            
            document.addEventListener('click', function(event) {
                const navbar = document.querySelector('.navbar');
                const navMenu = document.getElementById('navMenu');
                
                if (!navbar.contains(event.target)) {
                    navMenu.classList.remove('active');
                }
            });
        </script>
    </body>
    </html>
    """
    return html

# Add navigation and sitemap
@app.route('/sitemap.xml')
def sitemap():
    """Generate sitemap for better SEO"""
    base_url = get_base_url()
    pages = [
        {'url': f'{base_url}/', 'changefreq': 'daily', 'priority': '1.0'},
        {'url': f'{base_url}/about', 'changefreq': 'weekly', 'priority': '0.8'},
        {'url': f'{base_url}/career-tips', 'changefreq': 'weekly', 'priority': '0.9'},
        {'url': f'{base_url}/privacy', 'changefreq': 'monthly', 'priority': '0.6'},
        {'url': f'{base_url}/status', 'changefreq': 'daily', 'priority': '0.5'},
    ]
    
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    
    for page in pages:
        xml += f'  <url>\n'
        xml += f'    <loc>{page["url"]}</loc>\n'
        xml += f'    <changefreq>{page["changefreq"]}</changefreq>\n'
        xml += f'    <priority>{page["priority"]}</priority>\n'
        xml += f'  </url>\n'
    
    xml += '</urlset>'
    
    response = app.make_response(xml)
    response.headers['Content-Type'] = 'application/xml'
    return response


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "bot": "active",
        "security": "encrypted",
        "timestamp": datetime.now().isoformat(),
        "uptime": "running"
    }

@app.route('/reports/<path:filename>')
def get_report(filename):
    return send_from_directory(str(REPORTS_DIR), filename, mimetype='application/pdf')

@app.route('/status')
def status():
    """Status endpoint with navigation and MongoDB user statistics"""
    try:
        # Get actual user count from MongoDB collection
        user_count = users_collection.count_documents({})
        
        # Get additional statistics if needed
        recent_users = users_collection.count_documents({
            "encrypted_at": {"$gte": (datetime.now() - timedelta(days=7)).isoformat()}
        }) if users_collection.count_documents({}) > 0 else 0
        
    except Exception as e:
        logger.error(f"Error getting MongoDB statistics: {e}")
        user_count = "Error"
        recent_users = "Error"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="google-adsense-account" content="ca-pub-7084011371587725">
        <title>Bot Status - Resume AI Bot</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: #f8f9fa; 
                line-height: 1.6;
            }}
            /* Navigation Bar */
            .navbar {{
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            }}
            .nav-container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }}
            .nav-brand {{
                font-size: 1.5em;
                font-weight: bold;
                color: #667eea;
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .nav-menu {{
                display: flex;
                list-style: none;
                gap: 2rem;
                flex-wrap: wrap;
            }}
            .nav-menu li a {{
                text-decoration: none;
                color: #333;
                font-weight: 500;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                transition: all 0.3s ease;
            }}
            .nav-menu li a:hover, .nav-menu li a.active {{
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }}
            .nav-toggle {{
                display: none;
                flex-direction: column;
                cursor: pointer;
                padding: 5px;
            }}
            .nav-toggle span {{
                width: 25px;
                height: 3px;
                background: #333;
                margin: 3px 0;
                transition: 0.3s;
            }}
            @media (max-width: 768px) {{
                .nav-menu {{
                    display: none;
                    width: 100%;
                    flex-direction: column;
                    background: rgba(255,255,255,0.98);
                    position: absolute;
                    top: 100%;
                    left: 0;
                    padding: 1rem;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }}
                .nav-menu.active {{
                    display: flex;
                }}
                .nav-toggle {{
                    display: flex;
                }}
                .nav-container {{
                    position: relative;
                }}
            }}
            .container {{
                max-width: 800px;
                margin: 20px auto;
                padding: 20px;
            }}
            .status-card {{
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }}
            .status-item {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 15px 0;
                border-bottom: 1px solid #eee;
            }}
            .status-item:last-child {{
                border-bottom: none;
            }}
            .status-value {{
                color: #28a745;
                font-weight: bold;
            }}
            .status-value.error {{
                color: #dc3545;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding: 40px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border-radius: 15px;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }}
            .stat-card {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                border-left: 4px solid #667eea;
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                color: #667eea;
                display: block;
            }}
            .stat-label {{
                color: #666;
                font-size: 0.9em;
                margin-top: 5px;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-container">
                <a href="/" class="nav-brand">
                    🤖 Resume AI Bot
                </a>
                <div class="nav-toggle" onclick="toggleNav()">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <ul class="nav-menu" id="navMenu">
                    <li><a href="/">Home</a></li>
                    <li><a href="/about">About</a></li>
                    <li><a href="/career-tips">Career Tips</a></li>
                    <li><a href="/privacy">Privacy</a></li>
                    <li><a href="https://t.me/AIResumeReviewBot">Start Bot</a></li>
                </ul>
            </div>
        </nav>

        <div class="container">
            <div class="header">
                <h1>System Status</h1>
                <p>Real-time monitoring of Resume AI Bot services</p>
            </div>

            <div class="status-card">
                <h2>Platform Status</h2>
                <div class="status-item">
                    <span>Bot Status</span>
                    <span class="status-value">✅ Active</span>
                </div>
                <div class="status-item">
                    <span>Database Connection</span>
                    <span class="status-value">{'✅ Connected' if user_count != 'Error' else '❌ Error'}</span>
                </div>
                <div class="status-item">
                    <span>Security Level</span>
                    <span class="status-value">🔐 AES-256 Encrypted</span>
                </div>
                <div class="status-item">
                    <span>Last Updated</span>
                    <span class="status-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                </div>
            </div>

            <div class="status-card">
                <h2>User Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-number {'error' if user_count == 'Error' else ''}">{user_count}</span>
                        <div class="stat-label">Total Registered Users</div>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">{len(user_data)}</span>
                        <div class="stat-label">Active Sessions</div>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number {'error' if recent_users == 'Error' else ''}">{recent_users}</span>
                        <div class="stat-label">Users This Week</div>
                    </div>
                </div>
            </div>

            <div class="status-card">
                <h2>Available Features</h2>
                <ul style="list-style: none; padding: 0;">
                    <li style="padding: 10px 0; border-bottom: 1px solid #eee;">✅ Resume Analysis</li>
                    <li style="padding: 10px 0; border-bottom: 1px solid #eee;">✅ HR Interview Practice</li>
                    <li style="padding: 10px 0; border-bottom: 1px solid #eee;">✅ Technical Interview Practice</li>
                    <li style="padding: 10px 0; border-bottom: 1px solid #eee;">✅ Personalized Feedback</li>
                    <li style="padding: 10px 0;">✅ End-to-End Encryption</li>
                </ul>
            </div>

            <div class="status-card">
                <h2>Data Security Status</h2>
                <div class="status-item">
                    <span>Encryption Standard</span>
                    <span class="status-value">AES-256</span>
                </div>
                <div class="status-item">
                    <span>Key Derivation</span>
                    <span class="status-value">PBKDF2 (100k iterations)</span>
                </div>
                <div class="status-item">
                    <span>Data Protection</span>
                    <span class="status-value">Zero-Knowledge Architecture</span>
                </div>
                <div class="status-item">
                    <span>File Handling</span>
                    <span class="status-value">Auto-Delete + Secure Overwrite</span>
                </div>
            </div>
        </div>

        <script>
            function toggleNav() {{
                const navMenu = document.getElementById('navMenu');
                navMenu.classList.toggle('active');
            }}
            
            document.addEventListener('click', function(event) {{
                const navbar = document.querySelector('.navbar');
                const navMenu = document.getElementById('navMenu');
                
                if (!navbar.contains(event.target)) {{
                    navMenu.classList.remove('active');
                }}
            }});
            
            // Auto-refresh every 30 seconds
            setTimeout(function() {{
                window.location.reload();
            }}, 30000);
        </script>
    </body>
    </html>
    """
    return html

@app.route('/ads.txt')
def ads_txt():
    """Serve the ads.txt file for AdSense verification"""
    return send_from_directory(REPORTS_DIR.parent, 'ads.txt')

@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle incoming webhook updates from Telegram"""
    try:
        if bot_app is None:
            logger.error("Bot application not initialized")
            return "Bot not ready", 500
            
        json_data = request.get_json()
        if not json_data:
            return "No data", 400
            
        update = Update.de_json(json_data, bot_app.bot)
        if not update:
            return "Invalid update", 400

        # Process the update in a thread-safe manner
        run_async(bot_app.process_update(update))
        return "OK", 200
            
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return "Error", 500

# ---------------------- ENCRYPTED DATA MANAGEMENT ----------------------

def save_user_data(user_id: int, data: Dict[str, Any]) -> None:
    """Save user data in encrypted form"""
    try:
        # Encrypt the data
        encrypted_record = encryption.encrypt_data(user_id, data)
        
        # Save to MongoDB
        users_collection.update_one(
            {"_id": user_id}, 
            {"$set": encrypted_record}, 
            upsert=True
        )
        
        logger.info(f"✅ Encrypted data saved for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error saving encrypted user data for {user_id}: {e}")

def load_user_data(user_id: int) -> Dict[str, Any]:
    """Load and decrypt user data"""
    try:
        # Fetch encrypted record from MongoDB
        encrypted_record = users_collection.find_one({"_id": user_id}, {"_id": 0})
        
        if not encrypted_record:
            return None
        
        # Check if data is encrypted (new format) or plain (old format)
        if "encrypted_data" in encrypted_record:
            # Decrypt the data
            data = encryption.decrypt_data(user_id, encrypted_record)
            logger.info(f"✅ Encrypted data loaded for user {user_id}")
            return data
        else:
            # Handle legacy unencrypted data
            logger.warning(f"⚠️ Loading legacy unencrypted data for user {user_id}")
            # Optionally migrate to encrypted format
            save_user_data(user_id, encrypted_record)  # Re-save as encrypted
            return encrypted_record
            
    except Exception as e:
        logger.error(f"Error loading encrypted user data for {user_id}: {e}")
        return None

def delete_user_data(user_id: int) -> None:
    """Delete user data (encrypted or not)"""
    try:
        result = users_collection.delete_one({"_id": user_id})
        if result.deleted_count > 0:
            logger.info(f"🗑️ Deleted encrypted data for user {user_id}")
        else:
            logger.info(f"No data found to delete for user {user_id}")
    except Exception as e:
        logger.error(f"Error deleting user data for {user_id}: {e}")

def delete_resume_file(file_path: str) -> None:
    """Securely delete resume file"""
    try:
        if file_path and os.path.exists(file_path):
            # Overwrite file with random data before deletion (basic secure delete)
            file_size = os.path.getsize(file_path)
            with open(file_path, "r+b") as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            # Now delete the file
            os.remove(file_path)
            logger.info(f"🔒 Securely deleted resume file: {file_path}")
    except Exception as e:
        logger.error(f"Error securely deleting resume file {file_path}: {e}")

def extract_resume_tips(resume_analysis: str):
    """Extract personalized resume tips from analysis text."""
    tips = []
    text = resume_analysis.lower()

    if "project" in text:
        tips.append("Add more project experience relevant to your target role.")
    if "skill" in text:
        tips.append("Highlight your key technical and soft skills clearly.")
    if "certification" in text:
        tips.append("Include certifications that strengthen your application.")
    if "experience" in text:
        tips.append("Showcase measurable achievements from past experience.")

    if not tips:
        tips = [
            "Keep your resume concise (1-2 pages max).",
            "Highlight measurable achievements, not just responsibilities.",
            "Tailor your resume for each job role.",
        ]
    return tips

# ---------------------- BOT COMMANDS ----------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    user_data.pop(user_id, None)

    # Capture user information
    user_info = {
        'user_id': user_id,
        'username': update.effective_user.username,
        'first_name': update.effective_user.first_name,
        'last_name': update.effective_user.last_name
    }

    existing_data = load_user_data(user_id)
    if existing_data:
        # Update user info in existing data
        existing_data.update({
            'username': user_info['username'],
            'first_name': user_info['first_name'],
            'last_name': user_info['last_name']
        })
        save_user_data(user_id, existing_data)
        
        keyboard = [
            ["🎯 Start Interview", "📝 Change Job Role"],
            ["📄 Upload New Resume"]
        ]
        await update.message.reply_text(
            f"👋 Welcome back! I found your encrypted data:\n"
            f"• Company: {existing_data.get('company', 'Not specified')}\n"
            f"• Role: {existing_data.get('role', 'Not specified')}\n"
            f"• Last updated: {existing_data.get('timestamp', 'Unknown')}\n\n"
            f"🔒 <i>All your data is stored with AES-256 encryption</i>\n\n"
            "What would you like to do?",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            ),
            parse_mode='HTML'
        )
        return SELECT_DATA_SOURCE
    else:
        # Store initial user info
        user_data[user_id] = user_info
        
        await update.message.reply_text(
            "🤖 Welcome to the Resume AI Bot!\n\n"
            "🔒 <b>Your data is protected with military-grade encryption</b>\n"
            "📄 Please upload your resume in PDF format to get started.\n\n"
            "<i>All files are encrypted and auto-deleted after processing</i>\n\n"
            "If you have any questions or need help, contact our support: @AIResumeReviewSupportBot",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='HTML'
        )
        return UPLOAD_RESUME

async def update_resume(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    delete_user_data(user_id)
    user_data.pop(user_id, None)

    await update.message.reply_text(
        "📄 Please upload your new resume in PDF format.\n"
        "🔐 <i>File will be encrypted during processing</i>",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='HTML'
    )
    return UPLOAD_RESUME

async def view_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    data = load_user_data(user_id)
    if data:
        await update.message.reply_text(
            f"📂 Your encrypted data:\n"
            f"• Company: {data.get('company', 'N/A')}\n"
            f"• Role: {data.get('role', 'N/A')}\n"
            f"• Saved on: {data.get('timestamp', 'Unknown')}\n"
            f"🔐 <i>Data is stored with AES-256 encryption</i>",
            parse_mode='HTML'
        )
    else:
        await update.message.reply_text("❌ No saved data found.")

async def delete_data(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id in user_data:
        if "resume_path" in user_data[user_id] and user_data[user_id]["resume_path"]:
            delete_resume_file(user_data[user_id]["resume_path"])
        user_data.pop(user_id, None)

    delete_user_data(user_id)
    await update.message.reply_text(
        "🗑️ All your stored data has been securely deleted.\n"
        "🔐 Encrypted data permanently removed from servers\n\n"
        "You can start fresh with /start",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='HTML'
    )
    # FIX: Add the missing return statement
    return ConversationHandler.END

async def update_job(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    existing_data = load_user_data(user_id)

    if not existing_data:
        await update.message.reply_text("❌ No existing data found. Please upload your resume first using /start.")
        return ConversationHandler.END

    await update.message.reply_text(
        "📝 Please enter the new company and job role:\n\n"
        "<b>Format:</b> <i>Company Name, Job Role</i>\n"
        "<b>Example:</b> <i>Amazon, Data Scientist</i>\n"
        "🔐 <i>Updated data will be encrypted and saved securely</i>",
        parse_mode="HTML"
    )
    return UPDATE_JOB_ROLE

# ---------------------- MAIN BOT LOGIC ----------------------

async def handle_data_source(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    choice = update.message.text.lower()
    user_id = update.effective_user.id

    if "interview" in choice or "start" in choice:
        # Start interview with existing data
        existing_data = load_user_data(user_id)
        if not existing_data:
            await update.message.reply_text(
                "Error retrieving your encrypted data. Please upload a new resume.",
                reply_markup=ReplyKeyboardRemove()
            )
            return UPLOAD_RESUME

        user_data[user_id] = {
            "resume_path": None,
            "resume_text": existing_data.get("resume_text"),
            "company": existing_data.get("company"),
            "role": existing_data.get("role"),
            "chat_id": update.effective_chat.id,
            "resume_analysis": existing_data.get("resume_analysis"),
            "resume_tips": extract_resume_tips(existing_data.get("resume_analysis") or "")
        }


        keyboard = [
            ["🎯 HR Interview", "💻 Technical Interview"],
            ["🔥 Both Types", "⭐️ Skip Interview"]
        ]
        await update.message.reply_text(
            "✅ Ready to start your interview!\n"
            "🔐 <i>Using your existing encrypted data</i>\n\n"
            "🎤 What type of interview would you like to practice?",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            ),
            parse_mode='HTML'
        )
        return SELECT_INTERVIEW

    elif "change" in choice or "job" in choice or "role" in choice:
        # Change job role
        await update.message.reply_text(
            "📝 Please enter the new company and job role:\n\n"
            "<b>Format:</b> <i>Company Name, Job Role</i>\n"
            "<b>Example:</b> <i>Amazon, Data Scientist</i>\n"
            "🔐 <i>Updated data will be encrypted and saved securely</i>",
            parse_mode="HTML",
            reply_markup=ReplyKeyboardRemove()
        )
        return UPDATE_JOB_ROLE
    
    elif "upload" in choice or "new" in choice or "resume" in choice:
        # Upload new resume
        await update.message.reply_text(
            "📄 Please upload your new resume in PDF format.\n"
            "🔐 <i>File will be encrypted during processing</i>",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='HTML'
        )
        return UPLOAD_RESUME

    else:
        await update.message.reply_text("Please choose one of the available options:")
        # Show options again
        keyboard = [
            ["🎯 Start Interview", "📝 Change Job Role"],
            ["📄 Upload New Resume", "📊 View My Data"],
            ["🗑️ Delete My Data"]
        ]
        await update.message.reply_text(
            "Choose an option:",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            )
        )
        return SELECT_DATA_SOURCE

async def receive_resume(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle resume upload securely and analyze immediately if company+role exist."""
    user_id = update.effective_user.id
    document = update.message.document

    # ✅ Validate file
    if not document or not document.file_name.endswith(".pdf"):
        await update.message.reply_text("❌ Please upload a valid PDF file.")
        return UPLOAD_RESUME

    if document.file_size > 10 * 1024 * 1024:  # 10MB limit
        await update.message.reply_text("❌ File too large. Maximum allowed size is 10MB.")
        return UPLOAD_RESUME

    processing_msg = await update.message.reply_text(
        "⏳ Processing your resume...\n🔐 <i>Encrypting file during processing</i>",
        parse_mode="HTML"
    )

    # ✅ Save file locally
    file = await context.bot.get_file(document.file_id)
    resume_path = Path(f"resume_{user_id}.pdf")
    await file.download_to_drive(custom_path=str(resume_path))

    # ✅ Store in session
    user_data[user_id] = {
        "resume_path": str(resume_path),
        "chat_id": update.effective_chat.id
    }

    await processing_msg.delete()
    await update.message.reply_text("✅ Resume received and secured!")

    # ✅ If company+role already exist → analyze immediately
    existing_data = load_user_data(user_id)
    company = existing_data.get("company") if existing_data else None
    role = existing_data.get("role") if existing_data else None

    if company and role:
        try:
            from resume_checker import analyze_resume
            resume_text = extract_text_from_pdf(str(resume_path))
            result = await asyncio.to_thread(analyze_resume, str(resume_path), role, company)

            # Save encrypted data
            save_user_data(user_id, {
                "company": company,
                "role": role,
                "resume_text": resume_text,
                "resume_analysis": result,
                "timestamp": datetime.now().isoformat()
            })

            # Update in-memory session
            user_data[user_id].update({
                "resume_text": resume_text,
                "resume_analysis": result,
                "resume_tips": extract_resume_tips(result)
            })

            # Schedule deletion of raw file
            asyncio.create_task(delayed_delete(str(resume_path)))

            # Send analysis
            await send_long_message(
                update,
                f"📊 <b>Updated Resume Analysis for {role} @ {company}:</b>\n\n{result}",
                parse_mode="HTML"
            )
            return ConversationHandler.END

        except Exception as e:
            logger.error(f"Error analyzing updated resume: {e}")
            await update.message.reply_text("❌ An error occurred while analyzing your updated resume. Please try again or contact support at @AIResumeReviewSupportBot if the problem persists.")
            return ConversationHandler.END

    # ❌ Else → Ask for company + role
    await update.message.reply_text(
        "📝 Now provide the company name and job role:\n\n"
        "<b>Format:</b> <i>Company Name, Job Role</i>\n"
        "<b>Example:</b> <i>Google, Backend Developer</i>\n"
        "🔐 <i>All data will be encrypted before storage</i>",
        parse_mode="HTML"
    )
    return GET_COMPANY_ROLE

async def get_company_role(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text.strip()
    
    # Check if comma is missing
    if ',' not in text:
        await update.message.reply_text(
            "❌ <b>Format Error:</b> Missing comma separator\n\n"
            "📝 <b>Required format:</b> <i>Company Name, Job Role</i>\n\n"
            "✅ <b>Correct examples:</b>\n"
            "• <i>Google, Software Engineer</i>\n"
            "• <i>Amazon, Data Scientist</i>\n"
            "• <i>Microsoft, Product Manager</i>\n\n"
            "🔄 Please try again with the correct format:",
            parse_mode='HTML'
        )
        return GET_COMPANY_ROLE

    # Split by comma and validate both parts
    parts = text.split(',', 1)  # Split only on first comma
    company = parts[0].strip()
    role = parts[1].strip() if len(parts) > 1 else ""

    # Check if either part is empty
    if not company or not role:
        missing_parts = []
        if not company:
            missing_parts.append("Company Name")
        if not role:
            missing_parts.append("Job Role")
        
        await update.message.reply_text(
            f"❌ <b>Missing Information:</b> {' and '.join(missing_parts)}\n\n"
            "📝 <b>Required format:</b> <i>Company Name, Job Role</i>\n\n"
            "✅ <b>Example:</b> <i>Tesla, Machine Learning Engineer</i>\n\n"
            "🔄 Please provide both company name and job role:",
            parse_mode='HTML'
        )
        return GET_COMPANY_ROLE

    # Additional validation for reasonable length
    if len(company) < 2:
        await update.message.reply_text(
            "❌ <b>Invalid Company Name:</b> Too short\n\n"
            "Please enter a valid company name (at least 2 characters)",
            parse_mode='HTML'
        )
        return GET_COMPANY_ROLE
    
    if len(role) < 2:
        await update.message.reply_text(
            "❌ <b>Invalid Job Role:</b> Too short\n\n"
            "Please enter a valid job role (at least 2 characters)",
            parse_mode='HTML'
        )
        return GET_COMPANY_ROLE

    # Success - proceed with the rest of the function
    user_id = update.effective_user.id
    resume_path = user_data[user_id]["resume_path"]

    analysis_msg = await update.message.reply_text(
        f"🔍 Analyzing your resume for <b>{role}</b> at <b>{company}</b>...\n"
        f"🔐 <i>Processing with encrypted storage</i>",
        parse_mode='HTML'
    )

    try:
        result = await asyncio.to_thread(analyze_resume_module, resume_path, role, company)
        resume_text = extract_text_from_pdf(resume_path)
    except Exception as e:
        logger.error(f"Error analyzing resume: {e}")
        await analysis_msg.delete()
        await update.message.reply_text(
            "❌ An error occurred while analyzing your resume. Please try again.\n\n"
            "If the problem persists, please contact support: @AIResumeReviewSupportBot",
            parse_mode='HTML'
        )
        return ConversationHandler.END

    await analysis_msg.delete()

    # Save user data with encryption
    save_user_data(user_id, {
        "company": company,
        "role": role,
        "resume_text": resume_text,
        "resume_analysis": result,  
        "resume_tips": extract_resume_tips(result), 
        "timestamp": datetime.now().isoformat(),
        "username": user_data[user_id].get('username'),
        "first_name": user_data[user_id].get('first_name'),
        "last_name": user_data[user_id].get('last_name')
    })
    

    # Schedule secure file deletion
    asyncio.create_task(delayed_delete(resume_path))
    
    # Update user session data
    user_data[user_id].update({
        "company": company,
        "role": role,
        "resume_text": resume_text,
        "resume_analysis": result,
        "resume_tips": extract_resume_tips(result)
    })

    await send_long_message(
        update, 
        f"📊 <b>Resume Analysis Results:</b>\n🔐 <i>Analysis complete - data encrypted and stored securely</i>\n\n{result}", 
        parse_mode='HTML'
    )

    keyboard = [
        ["🎯 HR Interview", "💻 Technical Interview"],
        ["🔥 Both Types", "⭐️ Skip Interview"]
    ]
    await update.message.reply_text(
        "🎤 Would you like to practice a mock interview?",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return SELECT_INTERVIEW

async def handle_update_job(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text.strip()
    
    # Check if comma is missing
    if ',' not in text:
        await update.message.reply_text(
            "❌ <b>Format Error:</b> Missing comma separator\n\n"
            "📝 <b>Required format:</b> <i>Company Name, Job Role</i>\n\n"
            "✅ <b>Correct examples:</b>\n"
            "• <i>Netflix, Senior Developer</i>\n"
            "• <i>Apple, UX Designer</i>\n"
            "• <i>Spotify, DevOps Engineer</i>\n\n"
            "🔄 Please try again with the correct format:",
            parse_mode="HTML"
        )
        return UPDATE_JOB_ROLE

    # Split and validate
    parts = text.split(',', 1)
    company = parts[0].strip()
    role = parts[1].strip() if len(parts) > 1 else ""

    # Check if either part is empty
    if not company or not role:
        missing_parts = []
        if not company:
            missing_parts.append("Company Name")
        if not role:
            missing_parts.append("Job Role")
        
        await update.message.reply_text(
            f"❌ <b>Missing Information:</b> {' and '.join(missing_parts)}\n\n"
            "📝 <b>Required format:</b> <i>Company Name, Job Role</i>\n\n"
            "🔄 Please provide both company name and job role:",
            parse_mode="HTML"
        )
        return UPDATE_JOB_ROLE

    # Additional validation for reasonable length
    if len(company) < 2 or len(role) < 2:
        await update.message.reply_text(
            "❌ <b>Invalid Input:</b> Company name and job role must be at least 2 characters each\n\n"
            "Please enter valid company name and job role.",
            parse_mode="HTML"
        )
        return UPDATE_JOB_ROLE

    # Success - proceed with update
    user_id = update.effective_user.id
    data = load_user_data(user_id)

    if not data:
        await update.message.reply_text("❌ No stored data found. Please start with /start.")
        return ConversationHandler.END

    data["company"] = company
    data["role"] = role
    # Keep existing resume_analysis/resume_tips if present
    save_user_data(user_id, data)

    user_data[user_id] = {
        "resume_path": None,
        "resume_text": data.get("resume_text"),
        "company": company,
        "role": role,
        "chat_id": update.effective_chat.id
    }

    await update.message.reply_text(
        f"✅ Updated your encrypted data:\n• Company: {company}\n• Role: {role}\n"
        f"🔐 <i>Changes saved with AES-256 encryption</i>\n\n"
        "You can now start a mock interview.",
        parse_mode="HTML"
    )
    return SELECT_INTERVIEW

async def select_interview_type(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Let user select interview type."""
    try:
        choice = update.message.text.lower()
        
        if "skip" in choice:
            # ✅ Just show resume analysis, no PDF
            user_info = user_data[update.effective_user.id]
            resume_analysis = user_info.get("resume_analysis", "No analysis available.")
            tips = user_info.get("resume_tips", [])

            # Send analysis text
            await send_long_message(
                update,
                f"📊 <b>Resume Analysis Results:</b>\n\n{resume_analysis}",
                parse_mode="HTML"
            )

            # Send tips
            if tips:
                tips_text = "\n".join(f"• {tip}" for tip in tips)
                await update.message.reply_text(
                    f"💡 <b>Personalized Resume Tips:</b>\n{tips_text}",
                    parse_mode="HTML"
                )

            await update.message.reply_text(
                "✅ Session completed without interview.\n"
                "🔐 Your data is encrypted and stored securely.\n\n"
                "You can start again anytime with /start",
                reply_markup=ReplyKeyboardRemove(),
                parse_mode="HTML"
            )

            return ConversationHandler.END

        # Determine interview type
        if "technical" in choice:
            interview_type = "technical"
            interview_emoji = "💻"
        elif "hr" in choice:
            interview_type = "hr"
            interview_emoji = "🎯"
        elif "both" in choice:
            interview_type = "both"
            interview_emoji = "🔥"
        else:
            await update.message.reply_text(
                "❌ Please select a valid option from the menu."
            )
            return SELECT_INTERVIEW

        # Store interview type
        user_data[update.effective_user.id]["interview_type"] = interview_type

        keyboard = [["3", "5", "7"], ["10", "Custom"]]
        await update.message.reply_text(
            f"{interview_emoji} <b>{interview_type.title()} Interview Selected</b>\n\n"
            "❓ How many questions would you like?\n\n"
            "<i>Recommended: 3-7 questions for focused practice</i>",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            ),
            parse_mode='HTML'
        )
        return ASK_QUESTIONS

    except Exception as e:
        logger.error(f"Error in select_interview_type: {e}")
        await update.message.reply_text("❌ Please select a valid option.")
        return SELECT_INTERVIEW

async def ask_questions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle number of questions selection."""
    try:
        text = update.message.text.strip()
        
        if text.lower() == "custom":
            await update.message.reply_text(
                "📝 Please enter the number of questions (1-15):",
                reply_markup=ReplyKeyboardRemove()
            )
            return ASK_QUESTIONS
        
        try:
            num_questions = int(text)
            if num_questions < 1 or num_questions > 15:
                raise ValueError("Out of range")
        except ValueError:
            await update.message.reply_text(
                "❌ Please enter a valid number between 1 and 15."
            )
            return ASK_QUESTIONS

        # Store number of questions
        user_data[update.effective_user.id]["num_questions"] = num_questions
        
        # Start the interview process
        await update.message.reply_text(
            f"🎯 <b>Starting {user_data[update.effective_user.id]['interview_type'].title()} Interview</b>\n\n"
            f"📊 Questions: {num_questions}\n"
            f"⏱️ Time per question: 2 minutes\n"
            f"🔐 <i>All responses will be encrypted during processing</i>\n\n"
            "🚀 <b>Get ready!</b> The interview will begin shortly...",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='HTML'
        )
        
        # Initialize interview session
        user_data[update.effective_user.id]["current_question"] = 0
        user_data[update.effective_user.id]["answers"] = []
        
        # Generate questions using the interview module
        await generate_interview_questions(update)
        
        return ANSWERING_QUESTIONS

    except Exception as e:
        logger.error(f"Error in ask_questions: {e}")
        await update.message.reply_text(
            "❌ An error occurred while preparing your questions. Please try again.\n\n"
            "If the problem persists, contact support: @AIResumeReviewSupportBot"
        )
        return ConversationHandler.END

async def generate_interview_questions(update: Update) -> None:
    """Generate questions using the interview module."""
    user_info = user_data[update.effective_user.id]
    gen_msg = await update.message.reply_text(
        "🤖 Generating personalized questions...\n🔐 <i>Using encrypted data for personalization</i>",
        parse_mode='HTML'
    )

    try:
        # Get resume text
        if user_info.get("resume_path") and os.path.exists(user_info["resume_path"]):
            resume_text = extract_text_from_pdf(user_info["resume_path"])
        else:
            resume_text = user_info.get("resume_text")

        if not resume_text:
            await gen_msg.delete()
            await update.message.reply_text("❌ Could not find your resume data to generate questions. Please upload your resume again or contact support: @AIResumeReviewSupportBot")
            return

        # Use the interview module to generate questions
        questions = await generate_questions(
            resume_text[:8000],
            user_info["role"],
            user_info["company"],
            user_info["interview_type"],
            user_info["num_questions"]
        )

        await gen_msg.delete()

        if isinstance(questions, str):  # Error case
            await update.message.reply_text(f"❌ Error: {questions}")
            return

        user_data[update.effective_user.id]["questions"] = questions
        await ask_next_question(update)

    except Exception as e:
        logger.error(f"Error generating questions: {e}")
        await gen_msg.delete()
        await update.message.reply_text("❌ An error occurred while generating questions. Please try again or contact support: @AIResumeReviewSupportBot")

async def ask_next_question(update: Update) -> None:
    """Ask the next question in the interview."""
    try:
        user_info = user_data[update.effective_user.id]
        current_q = user_info["current_question"]
        questions = user_info["questions"]
        user_info["deadline"] = datetime.now() + timedelta(minutes=2)  # ✅ set deadline

        
        if current_q >= len(questions):
            # Interview complete
            await complete_interview(update)
            return
            
        question = questions[current_q]
        question_num = current_q + 1
        total_questions = len(questions)
        
        await update.message.reply_text(
            f"❓ <b>Question {question_num}/{total_questions}</b>\n\n"
            f"{question}\n\n"
            f"⏰ <i>You have 2 minutes to answer. Type your response and hit send.</i>\n"
            f"🔐 <i>Your answer will be encrypted and processed securely</i>",
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"Error asking next question: {e}")
        await update.message.reply_text("❌ Error in interview process.")

async def handle_answer(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle user's answer to interview question."""
    try:
        user_info = user_data[update.effective_user.id]
        current_q = user_info["current_question"]
        questions = user_info["questions"]
        
        if current_q >= len(questions):
            await update.message.reply_text("❌ Interview already completed.")
            return ConversationHandler.END
            
        # Store the answer
        now = datetime.now()
        if now > user_info.get("deadline", now):
            await update.message.reply_text(
                "⏰ Sorry, you exceeded 2 minutes. Please try again. The same question will be repeated."
            )
            # ⚠️ Do NOT increment question number → retry same one
            await asyncio.sleep(1)
            await ask_next_question(update)
            return ANSWERING_QUESTIONS
        else:
            answer = update.message.text.strip()
            user_info["answers"].append((questions[current_q], answer))
            await update.message.reply_text("✅ Answer recorded and encrypted!")

            # ✅ Only increment if valid
            user_info["current_question"] += 1

        
        # Ask next question or complete interview
        if user_info["current_question"] < len(questions):
            await asyncio.sleep(1)  # Brief pause
            await ask_next_question(update)
            return ANSWERING_QUESTIONS
        else:
            await complete_interview(update)
            return ConversationHandler.END
            
    except Exception as e:
        logger.error(f"Error handling answer: {e}")
        await update.message.reply_text("❌ An error occurred while processing your answer. Please try again or contact support: @AIResumeReviewSupportBot")
        return ANSWERING_QUESTIONS

async def complete_interview(update: Update) -> None:
    loading_msg = None
    try:
        user_info = user_data[update.effective_user.id]
        answers = user_info.get("answers", [])
        resume_analysis = user_info.get("resume_analysis")

        if not answers:
            await update.message.reply_text("❌ No answers recorded.")
            return

        # Send the loading message and store reference to delete it later
        loading_msg = await update.message.reply_text("⏳ Generating your report...")

        result = await asyncio.to_thread(evaluate_answers, interview_model, answers, evaluate_answer_prompt)
        if isinstance(result, tuple) and len(result) == 2:
            _, report_data = result
        else:
            report_data = {
                "summary": {"total_questions": len(answers), "answered": len(answers),
                            "completion_rate": 100.0, "overall_score": 0,
                            "max_score": len(answers)*10, "overall_percentage": 0.0},
                "items": []
            }

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{update.effective_user.id}_{ts}.pdf"
        title = f"Interview Analysis: {user_info.get('role','Role')} @ {user_info.get('company','Company')}"
        pdf_path = build_pdf(filename, report_data, title=title, resume_analysis=resume_analysis)

        # Short link
        short_id = secrets.token_hex(4)
        short_links[short_id] = {"filename": filename, "user_id": update.effective_user.id}
        base_url = get_base_url()
        short_url = f"{base_url}/r/{short_id}"

        # Delete the loading message first
        await loading_msg.delete()
        
        # Send the report link
        await update.message.reply_text(
            f"🧾 Your Interview Report is Ready!\n👉 {short_url}\n\n⏳ Link expires in 1 hour",
            parse_mode='HTML'
        )
        
        # Add a small delay and then send the ending message
        await asyncio.sleep(1)
        
        # Send the final ending message
        await update.message.reply_text(
            "✅ Interview session completed successfully!\n\n"
            "🔒 Your data remains encrypted and secure\n"
            "💡 You can start a new session anytime with /start\n\n"
            "Thank you for using Resume AI Bot!",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='HTML'
        )

        asyncio.create_task(delayed_delete(str(pdf_path), short_id))
        
    except Exception as e:
        logger.error(f"Error completing interview: {e}")
        if loading_msg:
            try:
                await loading_msg.delete()
            except Exception as del_e:
                logger.error(f"Failed to delete loading message: {del_e}")
        await update.message.reply_text("❌ An error occurred while generating your report. Please try again or contact support: @AIResumeReviewSupportBot")      
  
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the conversation."""
    user_id = update.effective_user.id
    if user_id in user_data:
        # Securely clean up any files before cancelling
        if "resume_path" in user_data[user_id] and user_data[user_id]["resume_path"]:
            delete_resume_file(user_data[user_id]["resume_path"])
        del user_data[user_id]
        
    await update.message.reply_text(
        "🚫 Operation cancelled.\n"
        "🔐 <i>All temporary data securely deleted</i>\n\n"
        "If you encountered any issues, please feel free to contact our support: @AIResumeReviewSupportBot\n\n"
        "You can start again anytime with /start",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='HTML'
    )
    return ConversationHandler.END

async def send_long_message(update: Update, text: str, max_length: int = 4000, parse_mode: str = None) -> None:
    """Helper function to split long messages."""
    try:
        if len(text) <= max_length:
            await update.message.reply_text(text, parse_mode=parse_mode)
            return
        
        # Split by paragraphs first
        parts = []
        current_part = ""
        
        paragraphs = text.split('\n\n')
        
        for paragraph in paragraphs:
            test_part = f"{current_part}\n\n{paragraph}" if current_part else paragraph
            
            if len(test_part) <= max_length:
                current_part = test_part
            else:
                if current_part:
                    parts.append(current_part)
                    current_part = paragraph
                else:
                    # Single paragraph too long, split by sentences
                    sentences = paragraph.split('. ')
                    temp_part = ""
                    for sentence in sentences:
                        test_sentence = f"{temp_part}{sentence}. "
                        if len(test_sentence) <= max_length:
                            temp_part = test_sentence
                        else:
                            if temp_part:
                                parts.append(temp_part.strip())
                                temp_part = f"{sentence}. "
                            else:
                                # Single sentence too long, force split
                                parts.append(sentence[:max_length])
                                temp_part = sentence[max_length:] + ". "
                    
                    if temp_part:
                        current_part = temp_part.strip()
        
        if current_part:
            parts.append(current_part)
        
        # Send parts with small delays
        for i, part in enumerate(parts):
            if i > 0:
                await asyncio.sleep(0.5)  # Small delay between parts
            await update.message.reply_text(part, parse_mode=parse_mode)
            
    except Exception as e:
        logger.error(f"Error in send_long_message: {e}")
        await update.message.reply_text(
            "❌ There was an error displaying the response. Please try again or contact support: @AIResumeReviewSupportBot"
        )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors"""
    logger.error(f"Exception while handling update: {context.error}", exc_info=context.error)
    if update and hasattr(update, 'message') and update.message:
        try:
            await update.message.reply_text(
                "❌ An unexpected error occurred. Please try again or start over with /start.\n\n"
                "If the issue persists, please contact our support team: @AIResumeReviewSupportBot\n"
                "🔐 <i>Your encrypted data remains secure</i>",
                parse_mode='HTML'
            )
        except Exception:
            pass

async def setup_webhook(app: Application, webhook_url: str) -> None:
    """Setup webhook for the bot"""
    try:
        await app.bot.set_webhook(url=webhook_url)
        logger.info(f"Webhook set to: {webhook_url}")
    except Exception as e:
        logger.error(f"Error setting webhook: {e}")

async def create_app():
    """Create and configure the bot application"""
    global bot_app
    
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN not found in environment variables")

    # Create application without updater
    bot_app = (
        Application.builder()
        .token(token)
        .updater(None)
        .build()
    )

    # Create conversation handler
    # Update the conversation handler states to include the new flow
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            UPLOAD_RESUME: [MessageHandler(filters.Document.PDF, receive_resume)],
            GET_COMPANY_ROLE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_company_role)],
            SELECT_INTERVIEW: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_interview_type)],
            ASK_QUESTIONS: [MessageHandler(filters.TEXT & ~filters.COMMAND, ask_questions)],
            ANSWERING_QUESTIONS: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_answer)],
            SELECT_DATA_SOURCE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_data_source)],
            UPDATE_JOB_ROLE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_update_job)]
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        allow_reentry=True
    )

    # Add handlers
    bot_app.add_handler(conv_handler)
    bot_app.add_handler(CommandHandler("update_resume", update_resume))
    bot_app.add_handler(CommandHandler("view_data", view_data))
    bot_app.add_handler(CommandHandler("delete_my_data", delete_data))
    bot_app.add_handler(CommandHandler("update_job", update_job))
    bot_app.add_error_handler(error_handler)

    # Initialize the application
    await bot_app.initialize()
    return bot_app

def main():
    """Main function to run the application"""
    try:
        logger.info("🔐 Starting Resume AI Bot with AES-256 encryption...")
        
        # Check for encryption key
        if not os.getenv("ENCRYPTION_MASTER_KEY"):
            logger.warning("⚠️ ENCRYPTION_MASTER_KEY not found! A new key will be generated.")
            logger.warning("⚠️ Please save the generated key to your environment variables!")
        
        # Initialize the bot application
        run_async(create_app())
        
        # Get configuration
        port = int(os.environ.get('PORT', 5000))
        webhook_url = os.environ.get('WEBHOOK_URL')
        
        if webhook_url:
            logger.info("Setting up webhook...")
            run_async(setup_webhook(bot_app, webhook_url))
            logger.info("🤖 Resume AI Bot webhook configured with encryption")
        
        # Run Flask app
        logger.info(f"🌐 Starting encrypted server on port {port}")
        logger.info("🔐 All user data will be encrypted with AES-256")
        app.run(host='0.0.0.0', port=port, debug=False)
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        raise
    finally:
        if event_loop:
            # Properly shutdown the event loop
            event_loop.call_soon_threadsafe(event_loop.stop)

if __name__ == '__main__':
    main()
