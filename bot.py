import os
import logging
import json
from pathlib import Path
from datetime import datetime
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    CommandHandler,
    MessageHandler,
    filters,
    ConversationHandler
)
from dotenv import load_dotenv
from resume_checker import analyze_resume
from interview_module import generate_questions, evaluate_answers
from utils import extract_text_from_pdf
from typing import Dict, Any
import asyncio
from flask import Flask, render_template_string
import threading

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

UPLOAD_RESUME, GET_COMPANY_ROLE, SELECT_INTERVIEW, ASK_QUESTIONS, ANSWERING_QUESTIONS, SELECT_DATA_SOURCE, UPDATE_JOB_ROLE = range(7)

# User data cache
user_data: Dict[int, Dict[str, Any]] = {}

# Storage configuration
USER_DATA_DIR = Path("user_data")
USER_DATA_DIR.mkdir(exist_ok=True)

# Flask app for HTTP server
app = Flask(__name__)

@app.route('/')
def home():
    """Default route to keep the bot active"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Resume AI Bot</title>
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
            <div class="bot-icon">🤖</div>
            <h1>Resume AI Bot</h1>
            <div class="status">✅ Bot is Active</div>
            
            <p style="color: #666; font-size: 1.1em; margin: 20px 0;">
                Your intelligent resume analysis and interview preparation assistant
            </p>
            
            <ul class="features">
                <li>📄 <strong>Resume Analysis:</strong> Get detailed feedback on your resume</li>
                <li>🎯 <strong>HR Interviews:</strong> Practice behavioral and HR questions</li>
                <li>💻 <strong>Technical Interviews:</strong> Prepare for technical challenges</li>
                <li>🔥 <strong>Mixed Interviews:</strong> Combined HR and technical practice</li>
                <li>📊 <strong>Personalized Feedback:</strong> Detailed evaluation reports</li>
            </ul>
            
            <a href="https://t.me/AIResumeReviewBot" class="cta">
                Start Using Bot on Telegram
            </a>
            
            <div class="footer">
                <p>Server Status: Running ✅</p>
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
        "timestamp": datetime.now().isoformat(),
        "uptime": "running"
    }

@app.route('/status')
def status():
    """Status endpoint with basic bot statistics"""
    return {
        "bot_status": "active",
        "active_users": len(user_data),
        "timestamp": datetime.now().isoformat(),
        "features": [
            "Resume Analysis",
            "HR Interview Practice",
            "Technical Interview Practice",
            "Personalized Feedback"
        ]
    }

def run_flask():
    """Run Flask server in a separate thread"""
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

def save_user_data(user_id: int, data: Dict[str, Any]) -> None:
    try:
        file_path = USER_DATA_DIR / f"{user_id}.json"
        with open(file_path, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logger.error(f"Error saving user data for {user_id}: {e}")


def load_user_data(user_id: int) -> Dict[str, Any]:
    try:
        file_path = USER_DATA_DIR / f"{user_id}.json"
        if file_path.exists():
            with open(file_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading user data for {user_id}: {e}")
    return None


def delete_user_data(user_id: int) -> None:
    try:
        file_path = USER_DATA_DIR / f"{user_id}.json"
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        logger.error(f"Error deleting user data for {user_id}: {e}")


def delete_resume_file(file_path: str) -> None:
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted resume file: {file_path}")
    except Exception as e:
        logger.error(f"Error deleting resume file {file_path}: {e}")


async def delayed_delete(file_path: str):
    await asyncio.sleep(1200)  # 20 minutes
    delete_resume_file(file_path)

# ---------------------- BOT COMMANDS ----------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    user_data.pop(user_id, None)

    existing_data = load_user_data(user_id)
    if existing_data:
        keyboard = [["Use Existing Data", "Upload New Resume"]]
        await update.message.reply_text(
            f"👋 Welcome back! I found your previous data:\n"
            f"• Company: {existing_data.get('company', 'Not specified')}\n"
            f"• Role: {existing_data.get('role', 'Not specified')}\n\n"
            "Would you like to use this data or upload a new resume?",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            )
        )
        return SELECT_DATA_SOURCE
    else:
        await update.message.reply_text(
            "🤖 Welcome to the Resume AI Bot!\n\n"
            "📄 Please upload your resume in PDF format to get started.",
            reply_markup=ReplyKeyboardRemove()
        )
        return UPLOAD_RESUME


async def update_resume(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    delete_user_data(user_id)
    user_data.pop(user_id, None)

    await update.message.reply_text(
        "📄 Please upload your new resume in PDF format.",
        reply_markup=ReplyKeyboardRemove()
    )
    return UPLOAD_RESUME


async def view_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    data = load_user_data(user_id)
    if data:
        await update.message.reply_text(
            f"📂 Your stored data:\n"
            f"• Company: {data.get('company', 'N/A')}\n"
            f"• Role: {data.get('role', 'N/A')}\n"
            f"• Saved on: {data.get('timestamp', 'Unknown')}"
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
        "🗑️ All your stored data has been deleted.\n\nYou can start fresh with /start",
        reply_markup=ReplyKeyboardRemove()
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
        "<b>Example:</b> <i>Amazon, Data Scientist</i>",
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
                "Error retrieving your data. Please upload a new resume.",
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
            "✅ Using your existing data.\n\n"
            "🎤 Would you like to practice a mock interview?",
            reply_markup=ReplyKeyboardMarkup(
                keyboard,
                one_time_keyboard=True,
                resize_keyboard=True
            )
        )
        return SELECT_INTERVIEW

    elif "new" in choice or "upload" in choice:
        await update.message.reply_text(
            "📄 Please upload your new resume in PDF format.",
            reply_markup=ReplyKeyboardRemove()
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
        f"✅ Updated your data:\n• Company: {company}\n• Role: {role}\n\nYou can now start a mock interview.",
        parse_mode="HTML"
    )
    return SELECT_INTERVIEW

async def receive_resume(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    document = update.message.document
    if not document or document.mime_type != 'application/pdf':
        await update.message.reply_text("❌ Please upload a PDF file only.")
        return UPLOAD_RESUME

    processing_msg = await update.message.reply_text("⏳ Processing your resume...")

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
        "✅ Resume received successfully!\n\n"
        "📝 Now provide the company name and job role:\n\n"
        "<b>Format:</b> <i>Company Name, Job Role</i>\n"
        "<b>Example:</b> <i>Google, Backend Developer</i>",
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
        f"🔍 Analyzing your resume for <b>{role}</b> at <b>{company}</b>...",
        parse_mode='HTML'
    )

    result = analyze_resume(resume_path, company, role)
    resume_text = extract_text_from_pdf(resume_path)

    await analysis_msg.delete()

    save_user_data(user_id, {
        "company": company,
        "role": role,
        "resume_text": resume_text,
        "timestamp": datetime.now().isoformat()
    })

    asyncio.create_task(delayed_delete(resume_path))
    user_data[user_id]["resume_path"] = resume_path
    user_data[user_id]["company"] = company
    user_data[user_id]["role"] = role
    user_data[user_id]["resume_text"] = resume_text

    await send_long_message(update, f"📊 <b>Resume Analysis Results:</b>\n\n{result}", parse_mode='HTML')

    keyboard = [
        ["🎯 HR Interview", "💻 Technical Interview"],
        ["🔥 Both Types", "⏭️ Skip Interview"]
    ]
    await update.message.reply_text(
        "🎤 Would you like to practice a mock interview?",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return SELECT_INTERVIEW


async def generate_interview_questions(update: Update) -> None:
    user_info = user_data[update.effective_user.id]
    gen_msg = await update.message.reply_text("🤖 Generating personalized questions...")

    if user_info.get("resume_path") and os.path.exists(user_info["resume_path"]):
        resume_text = extract_text_from_pdf(user_info["resume_path"])
    else:
        resume_text = user_info.get("resume_text")

    if not resume_text:
        await gen_msg.delete()
        await update.message.reply_text("❌ No resume data found. Please upload your resume again.")
        return

    questions = await generate_questions(
        resume_text[:8000],
        user_info["role"],
        user_info["company"],
        user_info["interview_type"],
        user_info["num_questions"]
    )

    await gen_msg.delete()

    if isinstance(questions, str):
        await update.message.reply_text(f"❌ Error: {questions}")
        return

    user_data[update.effective_user.id]["questions"] = questions
    await ask_next_question(update)

async def select_interview_type(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Let user select interview type."""
    try:
        choice = update.message.text.lower()
        
        if "skip" in choice:
            await update.message.reply_text(
                "✅ Analysis complete! Thanks for using Resume AI Bot.\n\n"
                "💡 You can start a new session anytime with /start",
                reply_markup=ReplyKeyboardRemove()
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
            f"⏱️ Time per question: 2 minutes\n\n"
            "🚀 <b>Get ready!</b> The interview will begin shortly...",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='HTML'
        )
        
        # Initialize interview session
        user_data[update.effective_user.id]["current_question"] = 0
        user_data[update.effective_user.id]["answers"] = []
        
        # Generate questions
        await generate_interview_questions(update)
        
        return ANSWERING_QUESTIONS

    except Exception as e:
        logger.error(f"Error in ask_questions: {e}")
        await update.message.reply_text(
            "❌ An error occurred. Please try again."
        )
        return ConversationHandler.END

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
            f"⏰ <i>You have 2 minutes to answer. Type your response and hit send.</i>",
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
        await update.message.reply_text("✅ Answer recorded!")
        
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
    """Complete the interview and generate report."""
    try:
        user_info = user_data[update.effective_user.id]
        answers = user_info.get("answers", [])
        
        if not answers:
            await update.message.reply_text("❌ No answers recorded.")
            return
            
        await update.message.reply_text(
            "🎉 <b>Interview Complete!</b>\n\n"
            "📊 Generating your personalized feedback report...",
            parse_mode='HTML'
        )
        
        # Generate evaluation report
        report = await evaluate_answers(answers)
        
        # Send report
        await send_long_message(update, report)
        
        # Clean up any remaining files
        if "resume_path" in user_info and user_info["resume_path"]:
            delete_resume_file(user_info["resume_path"])
        
        await update.message.reply_text(
            "✨ <b>Thank you for using Resume AI Bot!</b>\n\n"
            "💡 You can start a new session anytime with /start",
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"Error completing interview: {e}")
        await update.message.reply_text("❌ Error generating report.")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the conversation."""
    user_id = update.effective_user.id
    if user_id in user_data:
        # Clean up any files before cancelling
        if "resume_path" in user_data[user_id] and user_data[user_id]["resume_path"]:
            delete_resume_file(user_data[user_id]["resume_path"])
        del user_data[user_id]
        
    await update.message.reply_text(
        "🚫 Operation cancelled.\n\n"
        "You can start again anytime with /start",
        reply_markup=ReplyKeyboardRemove()
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

def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN not found in environment variables")

    # Start Flask server in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("🌐 HTTP server started")

    # Build Telegram bot application
    telegram_app = ApplicationBuilder().token(token).build()

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

    telegram_app.add_handler(conv_handler)
    telegram_app.add_handler(CommandHandler("update_resume", update_resume))
    telegram_app.add_handler(CommandHandler("view_data", view_data))
    telegram_app.add_handler(CommandHandler("delete_my_data", delete_data))
    telegram_app.add_handler(CommandHandler("update_job", update_job))
    telegram_app.add_error_handler(error_handler)

    logger.info("🤖 Resume AI Bot starting...")
    telegram_app.run_polling(drop_pending_updates=True)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(f"Exception while handling update: {context.error}", exc_info=context.error)
    if update and hasattr(update, 'message') and update.message:
        try:
            await update.message.reply_text(
                "❌ An unexpected error occurred. Please try again or start over with /start"
            )
        except Exception:
            pass


if __name__ == '__main__':
    main()
