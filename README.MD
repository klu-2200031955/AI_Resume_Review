# Resume AI Bot 🤖

A Telegram bot that analyzes resumes, provides personalized improvement suggestions, and conducts mock interviews to help candidates prepare for their job applications.

## ✨ Features

* 📄 **Resume Upload** – Upload a PDF resume for instant analysis.
* 🧠 **AI-Powered Resume Analysis** – Get strengths, weaknesses, and recommendations.
* 🎤 **Mock Interviews** – Generate HR, technical, or mixed interview questions.
* ⏱ **Delayed Resume Deletion** – Automatically deletes resume files after 20 minutes for privacy.
* 💾 **Data Persistence** – Save and reuse resume data across sessions in JSON format.
* 🔄 **Update Options** – Update resume, company, or job role without starting over.
* 🗑 **Data Deletion** – Option to remove all saved data.

---

## 🚀 Commands

```
start - Start bot and reuse/upload resume
update_resume - Upload a new resume and replace old data
update_job - To update the Company and Job profile
view_data - View previously saved company, role, timestamp
delete_my_data - Delete all stored resume data
cancel - Cancel current operation
```

---

## 🛠 Installation

### 1. Clone the repository

```bash
git clone https://github.com/klu-2200031955/AI_Resume_Review.git
cd AI_Resume_Review
```

### 2. Create a virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # For Linux/Mac
venv\Scripts\activate     # For Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set environment variables

Create a `.env` file in the project root:

```env
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
GEMINI_API_KEY=your-gemini-api-key
```

---

## ▶️ Usage

Run the bot:

```bash
python bot.py
```

Open Telegram and start chatting with your bot.

---

## 📂 Project Structure

```
resume-ai-bot/
│
├── bot.py                  # Main bot logic and command handlers
├── interview_module.py     # Interview question generation and evaluation
├── resume_checker.py       # Resume analysis functions
├── prompts.py              # AI prompt templates
├── utils.py                # Helper utilities
├── user_data/              # Stores user JSON data
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

---

## 🔐 Privacy & Data Handling

* Resumes are stored temporarily and automatically deleted after **20 minutes**.
* Resume data (text, company, role) is stored in JSON format for re-use.
* Users can delete their data anytime using `/delete_my_data`.

---

## 🤝 Contributing

Contributions are welcome!

* Fork the repository
* Create a new branch (`feature/your-feature`)
* Commit your changes
* Create a pull request

---

## 📜 License

This project is licensed under the **MIT License**.