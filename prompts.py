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
    You are an experienced interviewer and assessor. Please provide a short, structured evaluation.

    Question: {question}
    Candidate's Answer: {answer}

    Requirements:
    1) Give a one-line verdict of the answer quality.
    2) Rate each dimension from 1-10: Relevance, Clarity, TechnicalDepth.
    3) List up to 3 concise strengths as bullet points.
    4) List up to 3 concise improvement suggestions as bullet points.
    5) Provide a brief "Better Answer Outline" (3-5 bullet points the candidate could follow).

    Output STRICTLY in this JSON schema (no extra text):
    {{
      "verdict": "<one line>",
      "ratings": {{"Relevance": <int>, "Clarity": <int>, "TechnicalDepth": <int>}},
      "strengths": ["...", "..."],
      "improvements": ["...", "..."],
      "better_outline": ["...", "...", "..."]
    }}
    """
