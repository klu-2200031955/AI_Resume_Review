import os
import logging
import google.generativeai as genai
from utils import extract_text_from_pdf
from prompts import evaluate_answer_prompt
from dotenv import load_dotenv
from typing import Tuple, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# Configure Gemini AI with error handling
try:
    genai.configure(
        api_key=API_KEY,
        transport='rest',
        client_options={"api_endpoint": "generativelanguage.googleapis.com"}
    )
    model = genai.GenerativeModel("gemini-1.5-flash")
except Exception as e:
    logger.error(f"Failed to configure Gemini AI: {e}")
    model = None

async def generate_questions(
    resume_text: str,
    job_role: str,
    company: str,
    interview_type: str,
    num_questions: int
) -> List[str]:
    """Generate interview questions based on resume and job details."""
    try:
        if not model:
            return ["Unable to generate questions - AI service unavailable"]
            
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
            # Add fallback questions
            fallback_questions = create_sample_questions(job_role, interview_type, num_questions - len(questions))
            questions.extend(fallback_questions)
        
        if not questions:
            return create_sample_questions(job_role, interview_type, num_questions)
            
        return questions

    except Exception as e:
        logger.error(f"Error generating questions: {e}")
        # Return fallback questions instead of error string
        return create_sample_questions(job_role, interview_type, num_questions)

async def evaluate_answers(answers: List[Tuple[str, str]]) -> str:
    """Evaluate user answers and generate feedback report."""
    try:
        if not answers:
            return "No answers to evaluate."
        
        if not model:
            return "AI evaluation service unavailable. Thank you for completing the interview!"
        
        # Create individual evaluations
        evaluations = []
        total_score = 0
        max_possible_score = len(answers) * 10
        
        for i, (question, answer) in enumerate(answers, 1):
            try:
                if not answer or answer.lower() in ['no answer provided', 'time out']:
                    evaluation = {
                        'question': question,
                        'answer': answer or "No answer provided",
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
                    # Basic scoring heuristic
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
                    'answer': answer or "No answer",
                    'feedback': "Could not evaluate this answer due to technical issues.",
                    'score': 5  # Give partial credit
                })
                total_score += 5
        
        # Generate comprehensive report
        answered_count = sum(1 for _, answer in answers if answer and answer.lower() not in ['no answer provided', 'time out'])
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
            "🔍 DETAILED FEEDBACK:",
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
        return f"Interview completed! Report generation encountered issues: {str(e)}"

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
