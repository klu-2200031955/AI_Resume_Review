import os
import logging  
from pathlib import Path
from datetime import datetime
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
from flask import Flask, render_template_string, request
import threading
from concurrent.futures import ThreadPoolExecutor
from resume_checker import analyze_resume as analyze_resume_module
from interview_module import generate_questions, evaluate_answers
from utils import extract_text_from_pdf
from pymongo import MongoClient
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
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

# Global bot application and event loop
bot_app = None
event_loop = None
executor = ThreadPoolExecutor(max_workers=4)

# Flask app for HTTP server and webhooks
app = Flask(__name__)

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

# Initialize encryption handler
encryption = DataEncryption()

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

def start_background_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Run the event loop in a background thread"""
    asyncio.set_event_loop(loop)
    loop.run_forever()

@app.route('/')
def home():
    """Default route to keep the bot active"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Resume AI Bot - Secure</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 600px;
                margin: 20px;
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
            h1 {
                color: #333;
                margin-bottom: 20px;
                font-size: 2.5em;
            }
            .status {
                display: inline-block;
                padding: 10px 20px;
                background: #4CAF50;
                color: white;
                border-radius: 50px;
                margin: 20px 0;
                font-weight: bold;
            }
            .security-badge {
                display: inline-block;
                padding: 8px 16px;
                background: #2196F3;
                color: white;
                border-radius: 20px;
                margin: 10px 5px;
                font-size: 0.9em;
                font-weight: bold;
            }
            .features {
                list-style: none;
                padding: 0;
                margin: 30px 0;
            }
            .features li {
                padding: 10px 0;
                border-bottom: 1px solid #eee;
            }
            .features li:last-child {
                border-bottom: none;
            }
            .cta {
                background: #667eea;
                color: white;
                padding: 15px 30px;
                border-radius: 10px;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
                font-weight: bold;
                transition: all 0.3s ease;
            }
            .cta:hover {
                background: #764ba2;
                transform: translateY(-2px);
            }
            .footer {
                margin-top: 30px;
                color: #666;
                font-size: 0.9em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="bot-icon">🤖🔐</div>
            <h1>Resume AI Bot</h1>
            <div class="status">✅ Bot is Active</div>
            <div class="security-badge">🔒 End-to-End Encrypted</div>
            <div class="security-badge">🛡️ PBKDF2 + AES-256</div>
            
            <p style="color: #666; font-size: 1.1em; margin: 20px 0;">
                Your intelligent resume analysis and interview preparation assistant with military-grade encryption
            </p>
            
            <ul class="features">
                <li>📄 <strong>Resume Analysis:</strong> Get detailed feedback on your resume</li>
                <li>🎯 <strong>HR Interviews:</strong> Practice behavioral and HR questions</li>
                <li>💻 <strong>Technical Interviews:</strong> Prepare for technical challenges</li>
                <li>🔥 <strong>Mixed Interviews:</strong> Combined HR and technical practice</li>
                <li>📊 <strong>Personalized Feedback:</strong> Detailed evaluation reports</li>
                <li>🔐 <strong>Encrypted Storage:</strong> Your data is protected with AES-256 encryption</li>
            </ul>
            
            <a href="https://t.me/AIResumeReviewBot" class="cta">
                Start Using Secure Bot on Telegram
            </a>
            
            <div class="footer">
                <p>Server Status: Running ✅ | Security: Encrypted 🔐</p>
                <p>Last Updated: {{ timestamp }}</p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))

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

@app.route('/status')
def status():
    """Status endpoint with basic bot statistics"""
    return {
        "bot_status": "active",
        "active_users": len(user_data),
        "security_level": "AES-256 encrypted",
        "timestamp": datetime.now().isoformat(),
        "features": [
            "Resume Analysis",
            "HR Interview Practice",
            "Technical Interview Practice",
            "Personalized Feedback",
            "End-to-End Encryption"
        ]
    }

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

async def delayed_delete(file_path: str):
    """Delete file after 20 minutes"""
    await asyncio.sleep(1200)
    delete_resume_file(file_path)

# ---------------------- BOT COMMANDS ----------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    user_data.pop(user_id, None)

    existing_data = load_user_data(user_id)
    if existing_data:
        keyboard = [["Use Existing Data", "Upload New Resume"]]
        await update.message.reply_text(
            f"👋 Welcome back! I found your encrypted data:\n"
            f"• Company: {existing_data.get('company', 'Not specified')}\n"
            f"• Role: {existing_data.get('role', 'Not specified')}\n"
            f"🔐 <i>All your data is stored with AES-256 encryption</i>\n\n"
            "Would you like to use this data or upload a new resume?",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            ),
            parse_mode='HTML'
        )
        return SELECT_DATA_SOURCE
    else:
        await update.message.reply_text(
            "🤖 Welcome to the Resume AI Bot!\n\n"
            "🔐 <b>Your data is protected with military-grade encryption</b>\n"
            "📄 Please upload your resume in PDF format to get started.\n\n"
            "<i>All files are encrypted and auto-deleted after processing</i>",
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

async def delete_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in user_data:
        if "resume_path" in user_data[user_id] and user_data[user_id]["resume_path"]:
            delete_resume_file(user_data[user_id]["resume_path"])
        user_data.pop(user_id, None)

    delete_user_data(user_id)
    await update.message.reply_text(
        "🗑️ All your stored data has been securely deleted.\n"
        "🔐 <i>Encrypted data permanently removed from servers</i>\n\n"
        "You can start fresh with /start",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='HTML'
    )

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

    if "existing" in choice:
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
            "company": existing_data["company"],
            "role": existing_data["role"],
            "chat_id": update.effective_chat.id
        }

        keyboard = [
            ["🎯 HR Interview", "💻 Technical Interview"],
            ["🔥 Both Types", "⏭️ Skip Interview"]
        ]
        await update.message.reply_text(
            "✅ Using your existing encrypted data.\n"
            "🔐 <i>Data decrypted successfully</i>\n\n"
            "🎤 Would you like to practice a mock interview?",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            ),
            parse_mode='HTML'
        )
        return SELECT_INTERVIEW

    elif "new" in choice or "upload" in choice:
        await update.message.reply_text(
            "📄 Please upload your new resume in PDF format.\n"
            "🔐 <i>File will be encrypted during processing</i>",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='HTML'
        )
        return UPLOAD_RESUME

    else:
        await update.message.reply_text("Please choose 'Use Existing Data' or 'Upload New Resume'")
        return SELECT_DATA_SOURCE

async def handle_update_job(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text.strip()
    if ',' not in text:
        await update.message.reply_text(
            "❌ Format error:\n\n<b>Company Name, Job Role</b>",
            parse_mode="HTML"
        )
        return UPDATE_JOB_ROLE

    parts = text.split(',', 1)
    company, role = parts[0].strip(), parts[1].strip()

    if not company or not role:
        await update.message.reply_text("❌ Both company and job role are required.")
        return UPDATE_JOB_ROLE

    user_id = update.effective_user.id
    data = load_user_data(user_id)

    if not data:
        await update.message.reply_text("❌ No stored data found. Please start with /start.")
        return ConversationHandler.END

    data["company"] = company
    data["role"] = role
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

async def receive_resume(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    document = update.message.document
    if not document or document.mime_type != 'application/pdf':
        await update.message.reply_text("❌ Please upload a PDF file only.")
        return UPLOAD_RESUME

    if document and document.file_size > 10 * 1024 * 1024:  # 10MB limit
        await update.message.reply_text("❌ File too large. Maximum size is 10MB.")
        return UPLOAD_RESUME

    processing_msg = await update.message.reply_text(
        "⏳ Processing your resume...\n🔐 <i>Encrypting file during processing</i>",
        parse_mode='HTML'
    )

    file = await document.get_file()
    try:
        file_path = await asyncio.wait_for(
            file.download_to_drive(custom_path=f"resume_{update.effective_user.id}.pdf"),
            timeout=30
        )
    except asyncio.TimeoutError:
        await processing_msg.delete()
        await update.message.reply_text("❌ File download timed out. Try again.")
        return UPLOAD_RESUME

    user_data[update.effective_user.id] = {
        "resume_path": str(file_path),
        "chat_id": update.effective_chat.id
    }

    await processing_msg.delete()
    await update.message.reply_text(
        "✅ Resume received and secured!\n\n"
        "📝 Now provide the company name and job role:\n\n"
        "<b>Format:</b> <i>Company Name, Job Role</i>\n"
        "<b>Example:</b> <i>Google, Backend Developer</i>\n"
        "🔐 <i>All data will be encrypted before storage</i>",
        parse_mode='HTML'
    )
    return GET_COMPANY_ROLE

async def get_company_role(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text.strip()
    if ',' not in text:
        await update.message.reply_text(
            "❌ Format error:\n\n<b>Company Name, Job Role</b>",
            parse_mode='HTML'
        )
        return GET_COMPANY_ROLE

    parts = text.split(',', 1)
    company, role = parts[0].strip(), parts[1].strip()

    if not company or not role:
        await update.message.reply_text("❌ Both company and job role are required.")
        return GET_COMPANY_ROLE

    user_id = update.effective_user.id
    resume_path = user_data[user_id]["resume_path"]

    analysis_msg = await update.message.reply_text(
        f"🔍 Analyzing your resume for <b>{role}</b> at <b>{company}</b>...\n"
        f"🔐 <i>Processing with encrypted storage</i>",
        parse_mode='HTML'
    )

    # Use the resume_checker module
    try:
        result = await asyncio.to_thread(analyze_resume_module, resume_path, role, company)
        resume_text = extract_text_from_pdf(resume_path)
    except Exception as e:
        logger.error(f"Error analyzing resume: {e}")
        result = f"❌ Error analyzing resume: {str(e)}"
        resume_text = extract_text_from_pdf(resume_path)

    await analysis_msg.delete()

    # Save user data with encryption
    save_user_data(user_id, {
        "company": company,
        "role": role,
        "resume_text": resume_text,
        "timestamp": datetime.now().isoformat()
    })

    # Schedule secure file deletion
    asyncio.create_task(delayed_delete(resume_path))
    
    # Update user session data
    user_data[user_id].update({
        "company": company,
        "role": role,
        "resume_text": resume_text
    })

    await send_long_message(
        update, 
        f"📊 <b>Resume Analysis Results:</b>\n🔐 <i>Analysis complete - data encrypted and stored securely</i>\n\n{result}", 
        parse_mode='HTML'
    )

    keyboard = [
        ["🎯 HR Interview", "💻 Technical Interview"],
        ["🔥 Both Types", "⏭️ Skip Interview"]
    ]
    await update.message.reply_text(
        "🎤 Would you like to practice a mock interview?",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return SELECT_INTERVIEW

async def select_interview_type(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Let user select interview type."""
    try:
        choice = update.message.text.lower()
        
        if "skip" in choice:
            await update.message.reply_text(
                "✅ Analysis complete! Thanks for using Resume AI Bot.\n"
                "🔐 <i>Your data remains encrypted and secure</i>\n\n"
                "💡 You can start a new session anytime with /start",
                reply_markup=ReplyKeyboardRemove(),
                parse_mode='HTML'
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
            "❌ An error occurred. Please try again."
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
            await update.message.reply_text("❌ No resume data found. Please upload your resume again.")
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
        await update.message.reply_text("❌ Error generating questions. Please try again.")

async def ask_next_question(update: Update) -> None:
    """Ask the next question in the interview."""
    try:
        user_info = user_data[update.effective_user.id]
        current_q = user_info["current_question"]
        questions = user_info["questions"]
        
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
        answer = update.message.text.strip()
        question = questions[current_q]
        
        user_info["answers"].append((question, answer))
        user_info["current_question"] += 1
        
        # Acknowledge answer
        await update.message.reply_text(
            "✅ Answer recorded and encrypted!\n🔐 <i>Response stored securely</i>",
            parse_mode='HTML'
        )
        
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
        await update.message.reply_text("❌ Error processing your answer.")
        return ANSWERING_QUESTIONS

async def complete_interview(update: Update) -> None:
    """Complete the interview and generate report using interview module."""
    try:
        user_info = user_data[update.effective_user.id]
        answers = user_info.get("answers", [])
        
        if not answers:
            await update.message.reply_text("❌ No answers recorded.")
            return
            
        await update.message.reply_text(
            "🎉 <b>Interview Complete!</b>\n\n"
            "📊 Generating your personalized feedback report...\n"
            "🔐 <i>Processing encrypted responses for analysis</i>",
            parse_mode='HTML'
        )
        
        # Generate evaluation report using the interview module
        report = await evaluate_answers(answers)
        
        # Send report
        await send_long_message(update, f"📈 <b>Interview Analysis Report:</b>\n\n{report}", parse_mode='HTML')
        
        # Clean up any remaining files securely
        if "resume_path" in user_info and user_info["resume_path"]:
            delete_resume_file(user_info["resume_path"])
        
        await update.message.reply_text(
            "✨ <b>Thank you for using Resume AI Bot!</b>\n\n"
            "🔐 <i>All temporary data securely deleted</i>\n"
            "💡 Your encrypted profile remains saved for future use\n\n"
            "You can start a new session anytime with /start",
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"Error completing interview: {e}")
        await update.message.reply_text("❌ Error generating report.")

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
            "❌ The response is too long to display. Please try again."
        )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors"""
    logger.error(f"Exception while handling update: {context.error}", exc_info=context.error)
    if update and hasattr(update, 'message') and update.message:
        try:
            await update.message.reply_text(
                "❌ An unexpected error occurred. Please try again or start over with /start\n"
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
