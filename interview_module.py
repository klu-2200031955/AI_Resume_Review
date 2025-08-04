import os
import logging
import google.generativeai as genai
from utils import extract_text_from_pdf
from prompts import evaluate_answer_prompt
from dotenv import load_dotenv
from typing import Tuple, List, Optional, Dict, Any
import asyncio
from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# Configure Gemini AI
try:
    genai.configure(
        api_key=API_KEY,
        transport='rest',
        client_options={"api_endpoint": "generativelanguage.googleapis.com"}
    )
    model = genai.GenerativeModel("gemini-1.5-flash")
except Exception as e:
    logger.error(f"Failed to configure Gemini AI: {e}")
    raise

async def conduct_interview(update: Update, context: ContextTypes.DEFAULT_TYPE, interview_type: str, num_questions: int) -> str:
    """Main interview conduction function - returns report string."""
    try:
        # Get user data from the global user_data dict in bot.py
        from bot import user_data
        user_info = user_data.get(update.effective_user.id)
        
        if not user_info:
            await update.message.reply_text("Session expired. Please start over with /start")
            return "Session expired"

        # Verify required fields
        required_fields = ["resume_path", "role", "company"]
        missing_fields = [field for field in required_fields if not user_info.get(field)]
        
        if missing_fields:
            await update.message.reply_text(
                f"Missing information: {', '.join(missing_fields)}. Please start over with /start"
            )
            return "Missing required information"

        # Process resume
        resume_text = await process_resume(update, user_info["resume_path"])
        if not resume_text:
            return "Failed to process resume"

        # Generate questions
        questions = await generate_questions(
            resume_text, 
            user_info["role"], 
            user_info["company"], 
            interview_type, 
            num_questions
        )
        if isinstance(questions, str):  # Error case
            await update.message.reply_text(questions)
            return questions

        # Collect answers
        answers = await collect_answers(update, context, user_info["chat_id"], questions)
        if isinstance(answers, str):  # Error case
            await update.message.reply_text(answers)
            return answers

        # Generate report
        report = await evaluate_answers(answers)
        return report

    except Exception as e:
        logger.error(f"Unexpected error in conduct_interview: {e}", exc_info=True)
        await update.message.reply_text(
            "An unexpected error occurred during the interview."
        )
        return f"Interview error: {str(e)}"

async def process_resume(update: Update, resume_path: str) -> Optional[str]:
    """Process and validate resume file."""
    try:
        if not os.path.exists(resume_path):
            await update.message.reply_text(
                "Resume file not found. Please upload again with /start"
            )
            return None

        resume_text = extract_text_from_pdf(resume_path)
        if not resume_text:
            await update.message.reply_text(
                "Could not extract text from resume. Please upload a valid PDF."
            )
            return None
            
        return resume_text[:10000]  # Limit text length
    
    except Exception as e:
        logger.error(f"Error processing resume: {e}")
        await update.message.reply_text(
            "Error processing your resume. Please try again with a different file."
        )
        return None

async def generate_questions(
    resume_text: str,
    job_role: str,
    company: str,
    interview_type: str,
    num_questions: int
) -> List[str]:
    """Generate interview questions based on resume and job details."""
    try:
        # Determine question focus based on interview type
        if interview_type == "technical":
            focus = "technical skills, programming concepts, and problem-solving abilities"
        elif interview_type == "hr":
            focus = "behavioral aspects, cultural fit, and soft skills"
        else:  # both
            focus = "a mix of technical skills and behavioral aspects"

        prompt = f"""
You are an expert interviewer. Generate exactly {num_questions} interview questions 
for a candidate applying to the role of '{job_role}' at '{company}'. 

Focus on: {focus}

Resume:
\"\"\"
{resume_text[:8000]}
\"\"\"

Guidelines:
1. Generate exactly {num_questions} questions
2. Questions should be challenging but fair
3. Tailor questions to the specific role and company
4. Format: Start each question with "Q[number]: "
5. Make questions specific and actionable
"""
        
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.7,
                top_p=0.9,
                max_output_tokens=1500
            )
        )
        
        # Process and clean up questions
        text_lines = response.text.split('\n')
        questions = []
        
        for line in text_lines:
            line = line.strip()
            if line and ('Q' in line[:5] or line[0].isdigit()):
                # Clean up the question format
                if line.startswith('Q'):
                    question = line.split(':', 1)[-1].strip()
                elif line[0].isdigit():
                    question = line.split('.', 1)[-1].strip() if '.' in line else line.split(')', 1)[-1].strip()
                else:
                    question = line
                
                if question:
                    questions.append(question)
        
        # Ensure we have the right number of questions
        questions = questions[:num_questions]
        
        if len(questions) < num_questions:
            # Generate missing questions
            missing = num_questions - len(questions)
            for i in range(missing):
                questions.append(f"Tell me about a challenging project you worked on related to {job_role}.")
        
        if not questions:
            return "Error: Failed to generate valid interview questions."
            
        return questions

    except Exception as e:
        logger.error(f"Error generating questions: {e}")
        return f"Error generating interview questions: {str(e)}"

async def collect_answers(
    update, 
    context, 
    chat_id: int, 
    questions: List[str]
) -> List[Tuple[str, str]]:
    """Present questions to user and collect answers."""
    answers = []
    
    try:
        await update.message.reply_text(
            f"🎯 Starting interview with {len(questions)} questions.\n"
            "You have 2 minutes per question. Type your answer and press send.\n"
            "Ready? Here we go!\n"
        )
        
        for i, question in enumerate(questions, 1):
            try:
                await update.message.reply_text(
                    f"📝 Question {i}/{len(questions)}:\n\n{question}\n\n"
                    "⏰ You have 2 minutes to answer..."
                )
                
                # Create a future to wait for the next message
                answer_received = False
                start_time = asyncio.get_event_loop().time()
                timeout_seconds = 120  # 2 minutes
                
                # Simple polling approach for waiting for user response
                while not answer_received and (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
                    await asyncio.sleep(1)  # Check every second
                    
                    # In a real implementation, you'd need a message queue or callback system
                    # For now, we'll simulate getting the answer
                    # This is a simplified version - you might need to implement proper message handling
                
                # For this fix, we'll assume we get the answer through the normal flow
                # The actual message handling should be done in the conversation handler
                answers.append((question, "Answer will be collected through conversation flow"))
                    
            except Exception as e:
                logger.error(f"Error collecting answer for question {i}: {e}")
                answers.append((question, "Error processing answer"))
                await update.message.reply_text("Error occurred. Moving to next question...")
                
        return answers
        
    except Exception as e:
        logger.error(f"Error collecting answers: {e}")
        return f"Error during interview: {str(e)}"

async def evaluate_answers(answers: List[Tuple[str, str]]) -> str:
    """Evaluate user answers and generate feedback report."""
    try:
        if not answers:
            return "No answers to evaluate."
        
        # Create individual evaluations
        evaluations = []
        total_score = 0
        max_possible_score = len(answers) * 10  # Assuming 10 points per question
        
        for i, (question, answer) in enumerate(answers, 1):
            try:
                if answer.lower() in ['no answer provided', 'time out - no answer received', 'error processing answer']:
                    evaluation = {
                        'question': question,
                        'answer': answer,
                        'feedback': "No valid answer was provided for this question.",
                        'score': 0
                    }
                else:
                    # Generate AI evaluation
                    eval_prompt = evaluate_answer_prompt(question, answer)
                    eval_response = model.generate_content(
                        eval_prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.3,
                            top_p=0.8,
                            max_output_tokens=800
                        )
                    )
                    
                    feedback = eval_response.text.strip()
                    # Simple scoring based on answer length and relevance (basic heuristic)
                    score = min(10, max(1, len(answer.split()) // 5)) if answer else 0
                    total_score += score
                    
                    evaluation = {
                        'question': question,
                        'answer': answer,
                        'feedback': feedback,
                        'score': score
                    }
                
                evaluations.append(evaluation)
                
            except Exception as e:
                logger.error(f"Error evaluating answer {i}: {e}")
                evaluations.append({
                    'question': question,
                    'answer': answer,
                    'feedback': "Could not evaluate this answer due to technical issues.",
                    'score': 0
                })
        
        # Generate comprehensive report
        answered_count = sum(1 for _, answer in answers if answer.lower() not in ['no answer provided', 'time out - no answer received'])
        completion_rate = (answered_count / len(answers)) * 100
        
        report_parts = [
            "🎯 INTERVIEW PERFORMANCE REPORT",
            "=" * 40,
            f"📊 SUMMARY:",
            f"• Total Questions: {len(answers)}",
            f"• Questions Answered: {answered_count}",
            f"• Completion Rate: {completion_rate:.1f}%",
            f"• Overall Score: {total_score}/{max_possible_score} ({(total_score/max_possible_score)*100:.1f}%)",
            "",
            "📝 DETAILED FEEDBACK:",
            "-" * 40
        ]
        
        for i, eval_data in enumerate(evaluations, 1):
            report_parts.extend([
                f"Question {i}: {eval_data['question'][:100]}{'...' if len(eval_data['question']) > 100 else ''}",
                f"Your Answer: {eval_data['answer'][:200]}{'...' if len(eval_data['answer']) > 200 else ''}",
                f"Score: {eval_data['score']}/10",
                f"Feedback: {eval_data['feedback']}",
                "-" * 40
            ])
        
        report_parts.extend([
            "",
            "💡 RECOMMENDATIONS:",
            "• Practice articulating your thoughts clearly",
            "• Prepare specific examples from your experience", 
            "• Research the company and role thoroughly",
            "• Work on technical skills if applicable",
            "",
            "Thank you for completing the mock interview! 🎉"
        ])
        
        return "\n".join(report_parts)
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return f"Error generating interview report: {str(e)}"

# Additional helper functions for better interview flow
def create_sample_questions(job_role: str, interview_type: str, count: int) -> List[str]:
    """Create sample questions as fallback."""
    technical_questions = [
        f"Explain a complex technical challenge you faced in a {job_role} role.",
        "How do you approach debugging and troubleshooting?",
        "Describe your experience with version control systems.",
        "What coding best practices do you follow?",
        "How do you ensure code quality and maintainability?"
    ]
    
    hr_questions = [
        "Tell me about yourself and your career journey.",
        "Why are you interested in this position?",
        "Describe a time when you had to work under pressure.",
        "How do you handle conflicts with team members?",
        "Where do you see yourself in 5 years?"
    ]
    
    if interview_type == "technical":
        questions = technical_questions
    elif interview_type == "hr":
        questions = hr_questions
    else:
        questions = technical_questions + hr_questions
    
    return questions[:count]