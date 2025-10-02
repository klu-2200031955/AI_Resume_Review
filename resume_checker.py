import google.generativeai as genai
from prompts import resume_analysis_prompt
from utils import extract_text_from_pdf
import os
from dotenv import load_dotenv
import time
import logging
from typing import List, Optional

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
active_model_name = None

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
    """Initialize the best available Gemini model for resume analysis"""
    global model, active_model_name
    
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
                    "Reply with exactly: RESUME ANALYSIS READY",
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=10
                    )
                )
                
                if response and response.text:
                    logger.info(f"✅ Successfully initialized resume analyzer with: {model_name}")
                    logger.info(f"Test response: {response.text.strip()}")
                    model = test_model
                    active_model_name = model_name
                    return model_name
                    
            except Exception as e:
                logger.warning(f"Failed to initialize {model_name}: {e}")
                continue
    
    # If no preferred models work, try the first available one
    for model_name in available_models:
        try:
            test_model = genai.GenerativeModel(model_name)
            
            response = test_model.generate_content(
                "Reply with exactly: FALLBACK RESUME ANALYSIS", 
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=10
                )
            )
            
            if response and response.text:
                logger.info(f"✅ Fallback model initialized for resume analysis: {model_name}")
                model = test_model
                active_model_name = model_name
                return model_name
                
        except Exception as e:
            logger.warning(f"Failed to initialize fallback {model_name}: {e}")
            continue
    
    logger.error("❌ Failed to initialize any available model for resume analysis")
    return None

# Initialize the model on import
active_model_name = initialize_best_model()
if active_model_name:
    logger.info(f"🤖 Using Gemini model for resume analysis: {active_model_name}")
else:
    logger.error("❌ No working Gemini model available for resume analysis")

def analyze_resume(resume_path, job_role, company):
    """Analyze resume using Gemini AI with improved error handling"""
    
    try:
        if not model:
            logger.error("❌ AI service unavailable for resume analysis")
            return (
                "AI resume analysis service is currently unavailable. "
                "Please check your GEMINI_API_KEY configuration and try again. "
                "Your resume has been received and encrypted securely."
            )
            
        if not os.path.exists(resume_path):
            logger.error(f"Resume file not found: {resume_path}")
            return "Error: Resume file not found. Please upload your resume again."
            
        logger.info(f"🔍 Analyzing resume for {job_role} at {company} using {active_model_name}")
        
        # Extract text from PDF
        resume_text = extract_text_from_pdf(resume_path)
        
        if not resume_text or len(resume_text.strip()) < 50:
            logger.warning("Resume text is too short or empty")
            return (
                "Warning: Could not extract sufficient text from your resume. "
                "Please ensure your PDF contains readable text (not just images) and try again."
            )
        
        # Truncate if too long
        if len(resume_text) > 12000:
            resume_text = resume_text[:12000] + "\n[Content truncated for analysis]"
            logger.info("Resume content truncated for analysis")
            
        prompt = f"""
Analyze this resume for the {job_role} position at {company}. Provide a comprehensive but concise analysis (max 2500 characters).

Focus on:
1. Key strengths relevant to the role
2. Potential gaps or areas for improvement
3. How well the candidate matches the job requirements
4. Specific recommendations for enhancement

Resume Content:
{resume_text}

Provide actionable, specific feedback that will help the candidate improve their application for this particular role at {company}.
"""
        
        logger.info(f"📊 Sending resume to Gemini AI ({active_model_name}) for analysis...")
        
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                top_p=0.8,
                max_output_tokens=1200
            )
        )
        
        if not response or not response.text:
            logger.error("Empty response from Gemini AI")
            return (
                "Error: Received empty response from AI analysis service. "
                "Please try again or contact support if the issue persists."
            )
        
        analysis_result = response.text.strip()
        
        if len(analysis_result) < 100:
            logger.warning(f"Analysis result seems too short: {len(analysis_result)} characters")
            return (
                f"Analysis completed but result seems incomplete: {analysis_result}\n\n"
                "Please try uploading your resume again or contact support if the issue persists."
            )
        
        logger.info(f"✅ Resume analysis completed using {active_model_name}: {len(analysis_result)} characters")
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error analyzing resume: {e}")
        error_msg = str(e)
        
        # Provide more specific error messages
        if "quota" in error_msg.lower():
            return (
                "Error: AI service quota exceeded. Please try again later or contact support. "
                "Your resume has been received and stored securely."
            )
        elif "api" in error_msg.lower():
            return (
                "Error: Issue connecting to AI analysis service. Please check your internet connection "
                "and try again. If the problem persists, contact support."
            )
        elif "permission" in error_msg.lower():
            return (
                "Error: API permission issue. Please contact support to resolve this configuration problem."
            )
        else:
            return (
                f"Error analyzing resume with {active_model_name}: {error_msg[:100]}... "
                "Please try again or contact support if the issue persists."
            )

def test_resume_analysis():
    """Test function to verify resume analysis is working"""
    if not model:
        return False, f"Model not initialized. Active model: {active_model_name}"
    
    try:
        # Create a simple test
        test_prompt = """
        Analyze this sample resume for a Software Engineer position at Google:
        
        John Doe
        Software Engineer
        Experience: 3 years Python development
        Skills: Python, JavaScript, SQL
        Education: BS Computer Science
        
        Provide a brief analysis.
        """
        
        response = model.generate_content(
            test_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=200
            )
        )
        
        if response and response.text and len(response.text) > 50:
            return True, f"Success with {active_model_name}: Generated {len(response.text)} character analysis"
        else:
            return False, f"Analysis too short or empty with {active_model_name}"
            
    except Exception as e:
        return False, f"Error with {active_model_name}: {str(e)}"

def test_api_connection():
    """Test the current API setup for resume analysis"""
    if not model:
        return False, f"No model initialized for resume analysis. Active model: {active_model_name}"
    
    try:
        response = model.generate_content(
            "Respond with exactly: 'RESUME API TEST SUCCESSFUL'",
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=10
            )
        )
        
        if response and response.text:
            return True, f"Resume analysis API success with {active_model_name}: {response.text.strip()}"
        else:
            return False, f"Empty response from {active_model_name}"
            
    except Exception as e:
        return False, f"Error with {active_model_name}: {str(e)}"

# Test on import
if __name__ == "__main__":
    success, message = test_api_connection()
    print(f"Resume Analysis API Test: {'✅ PASSED' if success else '❌ FAILED'} - {message}")
    
    if success:
        success, message = test_resume_analysis()
        print(f"Resume Analysis Test: {'✅ PASSED' if success else '❌ FAILED'} - {message}")
    
    if not success:
        print("\nAvailable models:")
        for model_name in discover_available_models():
            print(f"  - {model_name}")
