def resume_analysis_prompt(resume_text, job_role, company):
    return f"""
You are a career advisor. Analyze this resume for suitability for the job role '{job_role}' at '{company}'.

Resume:
\"\"\"
{resume_text}
\"\"\"

Evaluate the match and provide suggestions to improve the resume (skills, tools, certifications, projects).
"""

def evaluate_answer_prompt(question, answer):
    return f"""
You are an experienced interviewer.

Question: {question}
Candidate's Answer: {answer}

Evaluate this answer based on:
- Relevance
- Clarity
- Technical depth

Give constructive suggestions to improve it.
"""
