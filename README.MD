# Resume AI Bot 🤖🔐

A secure Telegram bot with **military-grade encryption** that analyzes resumes, provides personalized improvement suggestions, and conducts mock interviews to help candidates prepare for their job applications.

## 🔒 Security Features

* **🛡️ AES-256 Encryption** – All user data encrypted with military-grade encryption
* **🔐 PBKDF2 Key Derivation** – Secure key generation with 100,000 iterations
* **🗑️ Secure File Deletion** – Files overwritten with random data before deletion
* **⏰ Auto-Deletion** – Resume files automatically deleted after 20 minutes
* **🔄 End-to-End Security** – Data encrypted during processing and storage
* **🚫 No Browser Storage** – All data stored securely on encrypted servers

## ✨ Features

* 📄 **Resume Upload & Analysis** – Upload PDF resumes for instant AI-powered analysis
* 🧠 **Personalized Feedback** – Get detailed strengths, weaknesses, and improvement recommendations
* 🎤 **Mock Interviews** – Practice with HR, technical, or mixed interview questions (3-15 questions)
* 💾 **Encrypted Data Persistence** – Securely save and reuse resume data across sessions
* 🔄 **Flexible Updates** – Update resume, company, or job role without starting over
* 🌐 **Web Dashboard** – Beautiful web interface showing bot status and security features
* 📊 **Detailed Reports** – Comprehensive interview analysis and performance feedback

## 🎯 Interview Types

* **🎯 HR Interview** – Behavioral questions, company culture fit, soft skills
* **💻 Technical Interview** – Role-specific technical questions and challenges  
* **🔥 Mixed Interview** – Combined HR and technical questions for comprehensive practice
* **⏭️ Skip Interview** – Get resume analysis only

## 🚀 Commands

```
/start - Start bot and reuse existing encrypted data or upload new resume
/update_resume - Upload a new resume and replace old encrypted data
/update_job - Update company and job role while keeping resume data
/view_data - View previously saved encrypted company, role, and timestamp
/delete_my_data - Securely delete all stored encrypted data
/cancel - Cancel current operation and clean up temporary data
```

## 🛠 Installation

### 1. Clone the repository

```bash
git clone https://github.com/klu-2200031955/AI_Resume_Review.git
cd AI_Resume_Review
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set environment variables

Create a `.env` file in the project root:

```env
# Required
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
GEMINI_API_KEY=your-gemini-api-key
MONGO_URI=your-mongodb-connection-string

# Security (Auto-generated if not provided)
ENCRYPTION_MASTER_KEY=your-base64-encoded-encryption-key

# Optional - For webhook deployment
WEBHOOK_URL=https://your-app.herokuapp.com/webhook
PORT=5000
```

### 5. MongoDB Setup

The bot uses MongoDB for encrypted data storage. You can use:
* **MongoDB Atlas** (cloud) - Recommended for production
* **Local MongoDB** - For development

Example MongoDB Atlas connection string:
```
mongodb+srv://username:password@cluster.mongodb.net/resume_bot
```

## ▶️ Running the Bot

### Local Development
```bash
python bot.py
```

### Production Deployment (Webhook)
Set `WEBHOOK_URL` in your environment and deploy to platforms like:
* Heroku
* Railway
* Render
* Google Cloud Run

The bot will automatically configure webhooks and serve a web dashboard.

## 🌐 Web Dashboard

When running, the bot serves a beautiful web interface at:
* `http://localhost:5000/` - Main dashboard
* `http://localhost:5000/health` - Health check endpoint  
* `http://localhost:5000/status` - Bot statistics

## 📂 Project Structure

```
resume-ai-bot/
│
├── bot.py                  # Main bot logic with encryption
├── interview_module.py     # Interview question generation and evaluation
├── resume_checker.py       # Resume analysis functions
├── prompts.py              # AI prompt templates
├── utils.py                # Helper utilities (PDF processing)
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (create this)
└── README.md               # This documentation
```

## 🔐 Security Implementation Details

### Data Encryption
* **Algorithm**: AES-256 in CBC mode via Fernet (authenticated encryption)
* **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
* **Salt**: Unique 16-byte salt per user
* **Master Key**: Base64-encoded 256-bit key (auto-generated if not provided)

### File Security
* **Secure Deletion**: Files overwritten with random data before deletion
* **Temporary Storage**: Resume files deleted after 20 minutes maximum
* **No Browser Storage**: All data stored on secure encrypted servers

### Data Protection
* **Encryption at Rest**: All MongoDB data encrypted before storage
* **Processing Security**: Data encrypted during AI processing
* **Session Security**: Temporary data cleaned up after sessions

## 🚨 Important Security Notes

1. **Save Your Master Key**: If `ENCRYPTION_MASTER_KEY` is auto-generated, save it immediately
2. **Backup Keys**: Loss of master key means loss of all encrypted data
3. **Environment Security**: Keep your `.env` file secure and never commit it
4. **MongoDB Security**: Use MongoDB Atlas with proper authentication

## 📊 Usage Workflow

1. **Start** → `/start` command
2. **Upload** → Send PDF resume file (max 10MB)
3. **Company Info** → Enter "Company Name, Job Role"
4. **Analysis** → Get detailed resume feedback
5. **Interview** → Choose interview type and question count
6. **Practice** → Answer generated questions
7. **Report** → Receive detailed performance analysis

## 🔄 Data Management

* **Reuse Data**: Existing users can reuse encrypted data or upload new resume
* **Update Options**: Change company/role without re-uploading resume
* **Data Viewing**: Check saved encrypted data with timestamps
* **Secure Deletion**: Permanently delete all encrypted user data

## 🛡️ Privacy & Compliance

* **Zero Knowledge**: Bot operators cannot access user data without encryption keys
* **GDPR Compliant**: Users can view and delete their data anytime
* **Temporary Processing**: Resume files exist only during processing
* **Encrypted Storage**: All persistent data encrypted with AES-256
* **Audit Trail**: All security operations logged for monitoring

## 📋 Dependencies

```
python-telegram-bot>=20.0
google-generativeai>=0.3.0
PyPDF2>=3.0.0
python-dotenv>=1.0.0
pymongo>=4.0.0
cryptography>=41.0.0
flask>=2.0.0
aiofiles>=23.0.0
```

## 🤝 Contributing

We welcome contributions! Please:

1. **Fork** the repository
2. **Create** a feature branch (`feature/your-feature`)
3. **Follow** security best practices
4. **Test** encryption functionality
5. **Submit** a pull request

### Security Contributions
When contributing security features:
* Use established cryptographic libraries
* Follow OWASP guidelines
* Add appropriate logging
* Test edge cases thoroughly

## 🐛 Troubleshooting

### Common Issues
* **Encryption Errors**: Check if `ENCRYPTION_MASTER_KEY` is properly formatted
* **MongoDB Connection**: Verify `MONGO_URI` and network connectivity
* **File Upload**: Ensure PDF files are under 10MB limit
* **Webhook Issues**: Verify `WEBHOOK_URL` is accessible and HTTPS

### Logs
Check application logs for detailed error information. All security operations are logged with appropriate detail levels.

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

* **GitHub**: [Resume AI Bot Repository](https://github.com/klu-2200031955/AI_Resume_Review)
* **Telegram**: [@AIResumeReviewBot](https://t.me/AIResumeReviewBot) (replace with your bot username)
* **Issues**: [Report bugs or request features](https://github.com/klu-2200031955/AI_Resume_Review/issues)

## 🏆 Acknowledgments

* **Telegram Bot API** for seamless messaging interface
* **Google Gemini** for powerful AI analysis capabilities
* **MongoDB** for reliable encrypted data storage  
* **Cryptography Library** for secure encryption implementation

---

**⚠️ Security Notice**: This bot handles sensitive personal data (resumes). Always ensure proper environment configuration and keep encryption keys secure. Never share your `.env` file or encryption keys.
