import os
import logging
import google.generativeai as genai
from utils import extract_text_from_pdf
from prompts import evaluate_answer_prompt
from dotenv import load_dotenv
from typing import Tuple, List, Optional
import math
import json as _json
import re as _re
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# Global model variable
model = None

def discover_available_models():
    """Dynamically discover what Gemini models are available"""
    if not API_KEY:
        logger.error("GEMINI_API_KEY not found in environment variables!")
        return []
    
    try:
        genai.configure(api_key=API_KEY)
        
        # List all available models
        available_models = []
        logger.info("Discovering available Gemini models...")
        
        for model_info in genai.list_models():
            model_name = model_info.name
            logger.info(f"Found model: {model_name}")
            
            # Filter for text generation capable models
            if 'generateContent' in model_info.supported_generation_methods:
                available_models.append(model_name)
                logger.info(f"✅ Model supports text generation: {model_name}")
        
        return available_models
        
    except Exception as e:
        logger.error(f"Error discovering models: {e}")
        return []

def initialize_best_model():
    """Initialize the best available Gemini model"""
    global model
    
    # Get available models
    available_models = discover_available_models()
    
    if not available_models:
        logger.error("No available models found")
        return None
    
    # Preferred model order (adjust based on what's actually available)
    preferred_models = [
        # Try various possible names for current models
        "models/gemini-2.0-flash-exp",
        "models/gemini-2.0-flash", 
        "models/gemini-2.5-flash",
        "models/gemini-2.5-pro",
        "models/gemini-1.5-flash",
        "models/gemini-1.5-pro",
        "models/gemini-pro",
        # Without models/ prefix
        "gemini-2.0-flash-exp",
        "gemini-2.0-flash",
        "gemini-2.5-flash", 
        "gemini-2.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-pro"
    ]
    
    logger.info(f"Available models: {available_models}")
    
    # Try to initialize models in order of preference
    for model_name in preferred_models:
        if model_name in available_models:
            try:
                test_model = genai.GenerativeModel(model_name)
                
                # Test the model
                response = test_model.generate_content(
                    "Reply with exactly: TEST SUCCESS",
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=10
                    )
                )
                
                if response and response.text:
                    logger.info(f"✅ Successfully initialized: {model_name}")
                    logger.info(f"Test response: {response.text.strip()}")
                    model = test_model
                    return model_name
                    
            except Exception as e:
                logger.warning(f"Failed to initialize {model_name}: {e}")
                continue
    
    # If no preferred models work, try the first available one
    for model_name in available_models:
        try:
            test_model = genai.GenerativeModel(model_name)
            
            response = test_model.generate_content(
                "Reply with exactly: FALLBACK SUCCESS", 
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=10
                )
            )
            
            if response and response.text:
                logger.info(f"✅ Fallback model initialized: {model_name}")
                model = test_model
                return model_name
                
        except Exception as e:
            logger.warning(f"Failed to initialize fallback {model_name}: {e}")
            continue
    
    logger.error("❌ Failed to initialize any available model")
    return None

# Initialize the model on import
active_model_name = initialize_best_model()
if active_model_name:
    logger.info(f"🤖 Using Gemini model: {active_model_name}")
else:
    logger.error("❌ No working Gemini model available")

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
            logger.error("❌ Model not available, returning fallback questions")
            return create_sample_questions(job_role, interview_type, num_questions)
            
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
{resume_text[:6000]}
\"\"\"

Requirements:
1. Generate exactly {num_questions} distinct questions
2. Questions should be challenging but fair
3. Tailor questions to the specific role and company
4. Format each question on a new line starting with "Q1:", "Q2:", etc.
5. Make questions specific and actionable
6. Avoid generic questions
"""
        
        logger.info(f"🤖 Generating {num_questions} {interview_type} questions using {active_model_name}...")
        
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.7,
                top_p=0.9,
                max_output_tokens=2000
            )
        )
        
        if not response or not response.text:
            logger.error("Empty response from Gemini")
            return create_sample_questions(job_role, interview_type, num_questions)
        
        logger.info(f"✅ Received response: {len(response.text)} characters")
        
        # Process and clean up questions
        text_lines = response.text.split('\n')
        questions = []
        
        for line in text_lines:
            line = line.strip()
            if not line:
                continue
                
            # Look for questions in various formats
            if any(line.lower().startswith(f'q{i}') for i in range(1, num_questions + 2)):
                # Format: Q1: question text
                if ':' in line:
                    question = line.split(':', 1)[1].strip()
                else:
                    question = line[2:].strip()  # Remove Q1, Q2, etc.
                    
            elif line[0].isdigit() and ('.' in line or ')' in line):
                # Format: 1. question text or 1) question text
                if '.' in line:
                    question = line.split('.', 1)[1].strip()
                else:
                    question = line.split(')', 1)[1].strip()
            elif line.startswith('**Q') or line.startswith('*Q'):
                # Markdown format
                question = line.split(':', 1)[1].strip() if ':' in line else line[3:].strip()
            elif len(line) > 20 and '?' in line:
                # Likely a question without numbering
                question = line
            else:
                continue
            
            if question and len(question) > 10:  # Valid question
                questions.append(question)
        
        # Ensure we have the right number of questions
        questions = questions[:num_questions]
        
        logger.info(f"📝 Extracted {len(questions)} questions from AI response")
        
        if len(questions) < num_questions:
            # Add fallback questions
            fallback_needed = num_questions - len(questions)
            logger.info(f"➕ Adding {fallback_needed} fallback questions")
            fallback_questions = create_sample_questions(job_role, interview_type, fallback_needed)
            questions.extend(fallback_questions)
        
        if not questions:
            logger.warning("No questions extracted, using all fallback questions")
            return create_sample_questions(job_role, interview_type, num_questions)
            
        return questions

    except Exception as e:
        logger.error(f"❌ Error generating questions: {e}")
        return create_sample_questions(job_role, interview_type, num_questions)

def _normalize_rating(val):
    """Normalize rating values to float between 0-10"""
    try:
        if isinstance(val, str):
            s = val.strip().lower()
            s = s.split('/')[0].split(' out of ')[0]
            s = ''.join(ch for ch in s if (ch.isdigit() or ch == '.' or ch == '-'))
            if s == '':
                raise ValueError("empty")
            rv = float(s)
        else:
            rv = float(val)
    except Exception:
        rv = 0.0
    return max(0.0, min(10.0, rv))

def evaluate_answers(model_instance, answers, evaluate_answer_prompt):
    """Evaluate interview answers using available Gemini model"""
    
    if not model_instance or not model:
        logger.warning("❌ AI evaluation service unavailable")
        answered_count = sum(1 for _, a in answers if a and a.lower() not in ['no answer provided', 'time out'])
        total_q = len(answers)
        completion_rate = round((answered_count / total_q) * 100, 1) if total_q else 0.0
        
        data = {
            "summary": {
                "total_questions": total_q,
                "answered": answered_count,
                "completion_rate": completion_rate,
                "overall_score": 0,
                "max_score": total_q * 10,
                "overall_percentage": 0.0
            },
            "items": [
                {
                    "question": q, 
                    "answer": a, 
                    "score": 0, 
                    "verdict": f"AI evaluation unavailable - using model: {active_model_name or 'None'}",
                    "ratings": {"Relevance": 0, "Clarity": 0, "TechnicalDepth": 0},
                    "strengths": [], 
                    "improvements": ["Ensure Gemini API is properly configured"], 
                    "better_outline": []
                }
                for q, a in answers
            ],
            "recommendations": [
                "Practice articulating your thoughts clearly",
                "Prepare specific examples from your experience", 
                "Research the company and role thoroughly"
            ]
        }
        return "AI evaluation service unavailable. Please check your API configuration.", data

    logger.info(f"🔍 Evaluating {len(answers)} answers using {active_model_name}...")
    
    total_score = 0
    evaluations = []
    
    for idx, (question, answer) in enumerate(answers, 1):
        logger.info(f"📊 Evaluating answer {idx}/{len(answers)}")
        
        entry = {
            'question': question,
            'answer': answer,
            'score': 0,
            'verdict': '',
            'ratings': {'Relevance': 0, 'Clarity': 0, 'TechnicalDepth': 0},
            'strengths': [],
            'improvements': [],
            'better_outline': []
        }
        
        if not answer or answer.lower() in ['no answer provided', 'time out']:
            entry['verdict'] = 'No answer provided'
            evaluations.append(entry)
            continue

        try:
            eval_prompt = evaluate_answer_prompt(question, answer)
            
            eval_response = model.generate_content(
                eval_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.2,
                    top_p=0.8,
                    max_output_tokens=800
                )
            )

            if not eval_response or not eval_response.text:
                raise Exception("Empty response from evaluation API")

            raw = eval_response.text.strip()
            logger.debug(f"Raw evaluation response: {raw[:200]}...")
            
            parsed = None
            try:
                parsed = _json.loads(raw)
            except Exception:
                json_match = _re.search(r'\{[\s\S]*\}', raw)
                if json_match:
                    try:
                        parsed = _json.loads(json_match.group(0))
                    except Exception:
                        logger.warning("Failed to parse JSON from evaluation response")

            if parsed and isinstance(parsed, dict):
                entry['verdict'] = str(parsed.get('verdict', 'No verdict provided')).strip()
                
                ratings = parsed.get('ratings', {})
                if isinstance(ratings, dict):
                    relevance = _normalize_rating(ratings.get('Relevance', 0))
                    clarity = _normalize_rating(ratings.get('Clarity', 0))
                    technical = _normalize_rating(ratings.get('TechnicalDepth', 0))

                    entry['ratings'] = {
                        "Relevance": int(round(relevance)),
                        "Clarity": int(round(clarity)),
                        "TechnicalDepth": int(round(technical))
                    }

                    avg = (relevance + clarity + technical) / 3.0
                    entry_score = int(math.floor(avg + 0.5))
                    entry['score'] = max(0, min(10, entry_score))

                entry['strengths'] = [str(x) for x in (parsed.get('strengths') or [])][:3]
                entry['improvements'] = [str(x) for x in (parsed.get('improvements') or [])][:3]
                entry['better_outline'] = [str(x) for x in (parsed.get('better_outline') or [])][:5]

                logger.info(f"✅ Answer {idx} evaluated: Score {entry['score']}/10")
            else:
                word_count = len(answer.split())
                entry['score'] = min(10, max(1, word_count // 8))
                entry['verdict'] = "Could not parse structured feedback from AI. Heuristic scoring applied."
                logger.warning(f"⚠️ Fallback scoring for answer {idx}: {entry['score']}/10")

        except Exception as e:
            logger.error(f"❌ Error evaluating answer {idx}: {str(e)}")
            word_count = len(answer.split()) if answer else 0
            entry['score'] = min(10, max(1, word_count // 8))
            entry['verdict'] = f"Evaluation error with {active_model_name}: {str(e)[:100]}..."

        total_score += entry['score']
        evaluations.append(entry)
        time.sleep(0.5)  # Rate limiting

    # Calculate summary
    total_q = len(answers)
    answered_count = sum(1 for _, a in answers if a and a.lower() not in ['no answer provided', 'time out'])
    completion_rate = round((answered_count / total_q) * 100, 1) if total_q else 0.0
    max_score = total_q * 10
    overall_percentage = round((total_score / max_score) * 100, 1) if max_score else 0.0

    summary = {
        'total_questions': total_q,
        'answered': answered_count,
        'completion_rate': completion_rate,
        'overall_score': total_score,
        'max_score': max_score,
        'overall_percentage': overall_percentage
    }

    recommendations = [
        'Practice articulating your thoughts clearly',
        'Prepare specific examples from your experience',
        'Research the company and role thoroughly',
        'Use the STAR method for behavioral questions',
        'Review technical concepts relevant to the role'
    ]

    logger.info(f"✅ Evaluation completed using {active_model_name}: {total_score}/{max_score} ({overall_percentage}%)")

    return f'Evaluation completed successfully using {active_model_name}.', {
        'summary': summary,
        'items': evaluations,
        'recommendations': recommendations
    }

def create_sample_questions(job_role: str, interview_type: str, count: int) -> List[str]:
    """Create sample questions as fallback."""
    
    tech_questions_by_role = {
        'software': [
            f"Explain a complex technical challenge you faced in a {job_role} role and how you solved it.",
            "How do you approach debugging and troubleshooting in production systems?",
            "Describe your experience with version control and collaborative development workflows.",
            "What coding best practices do you follow to ensure maintainable code?",
            "How do you handle database optimization and query performance issues?",
            "Explain your approach to API design and RESTful services.",
            "Describe a time when you had to refactor legacy code. What was your strategy?",
            "How do you ensure code quality through testing and code reviews?",
            "What's your experience with cloud platforms and containerization?",
            "Explain how you would design a scalable system for high traffic."
        ],
        'data': [
            f"Describe a complex data analysis project you worked on as a {job_role}.",
            "How do you handle missing or inconsistent data in your analysis?",
            "Explain your approach to feature engineering and selection.",
            "What machine learning algorithms have you implemented in production?",
            "How do you validate and test your data models?",
            "Describe your experience with big data processing frameworks.",
            "How do you communicate technical findings to non-technical stakeholders?",
            "What's your approach to data visualization and storytelling?",
            "How do you ensure data quality and integrity in your pipelines?",
            "Explain a time when you had to optimize a slow-running data process."
        ]
    }
    
    role_lower = job_role.lower()
    if any(keyword in role_lower for keyword in ['software', 'engineer', 'developer', 'sde', 'backend', 'frontend', 'full-stack']):
        tech_questions = tech_questions_by_role['software']
    elif any(keyword in role_lower for keyword in ['data', 'analyst', 'scientist', 'ml', 'ai']):
        tech_questions = tech_questions_by_role['data']
    else:
        tech_questions = tech_questions_by_role['software']
    
    hr_questions = [
        "Tell me about yourself and your career journey so far.",
        f"Why are you interested in the {job_role} position at this company?",
        "Describe a time when you had to work under pressure to meet a tight deadline.",
        "How do you handle conflicts or disagreements with team members?",
        "Tell me about a project you're particularly proud of and why.",
        "Describe a situation where you had to learn a new technology quickly.",
        "How do you stay current with industry trends and developments?",
        "Tell me about a time when you failed and what you learned from it.",
        "Where do you see yourself in your career in the next 5 years?",
        "Describe your ideal work environment and team culture."
    ]
    
    if interview_type == "technical":
        questions = tech_questions
    elif interview_type == "hr":
        questions = hr_questions  
    else:  # both
        half_count = count // 2
        questions = tech_questions[:half_count] + hr_questions[:count - half_count]
    
    selected_questions = questions[:count]
    while len(selected_questions) < count:
        remaining = count - len(selected_questions)
        selected_questions.extend(questions[:remaining])
    
    logger.info(f"📋 Created {len(selected_questions)} fallback questions for {interview_type} interview")
    return selected_questions[:count]

def test_api_connection():
    """Test the current API setup"""
    if not model:
        return False, f"No model initialized. Active model: {active_model_name}"
    
    try:
        response = model.generate_content(
            "Respond with exactly: 'API test successful'",
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=10
            )
        )
        
        if response and response.text:
            return True, f"Success with {active_model_name}: {response.text.strip()}"
        else:
            return False, f"Empty response from {active_model_name}"
            
    except Exception as e:
        return False, f"Error with {active_model_name}: {str(e)}"

# Test on import
if __name__ == "__main__":
    success, message = test_api_connection()
    print(f"Gemini API Test: {'✅ PASSED' if success else '❌ FAILED'} - {message}")
    
    if not success:
        print("\nAvailable models:")
        for model_name in discover_available_models():
            print(f"  - {model_name}")
