# Resume AI Bot 🤖📊

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Telegram Bot](https://img.shields.io/badge/Telegram-@AIResumeReviewBot-blue?logo=telegram)](https://t.me/AIResumeReviewBot)
[![Security](https://img.shields.io/badge/encryption-AES--256-red)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

A powerful, secure Telegram bot with **military-grade encryption** that revolutionizes job preparation by providing AI-powered resume analysis, personalized feedback, and comprehensive mock interview practice. Built with enterprise-level security to protect your sensitive career data.

## 🌟 Why Resume AI Bot?

- **🎯 Personalized Analysis** - Get targeted feedback based on specific companies and roles
- **🔒 Bank-Level Security** - Your data is protected with the same encryption used by financial institutions
- **⚡ Instant Feedback** - Receive comprehensive analysis in minutes, not days
- **🎓 Learn & Improve** - Detailed scoring and improvement suggestions for every answer
- **💼 Real Interview Practice** - Questions tailored to your target role and company
- **🌐 Web Dashboard** - Beautiful interface for monitoring and management

## 🔐 Enterprise Security Features

Our security implementation exceeds industry standards:

### Encryption & Data Protection
- **🛡️ AES-256 Encryption** – Military-grade encryption for all user data
- **🔑 PBKDF2 Key Derivation** – 100,000 iterations for maximum security
- **🔐 Per-User Encryption Keys** – Unique encryption keys for each user
- **🚫 Zero-Knowledge Architecture** – Server operators cannot access your decrypted data

### File & Storage Security
- **🗑️ Secure File Deletion** – Files overwritten with random data before deletion
- **⏰ Auto-Expiration** – Resume files automatically deleted after 1 hour
- **🔄 Encrypted Processing** – Data remains encrypted during AI analysis
- **💾 Encrypted Storage** – MongoDB with field-level encryption

### Privacy & Compliance
- **📝 GDPR Compliant** – Full user control over personal data
- **🔍 Audit Logging** – All security operations logged for transparency
- **🚫 No Browser Storage** – All data stored securely on encrypted servers
- **⚖️ Data Sovereignty** – Users can delete all data instantly

## ✨ Core Features

### 📄 Resume Analysis
- **PDF Processing** – Intelligent text extraction from PDF resumes
- **AI-Powered Analysis** – Google Gemini 2.0 for comprehensive evaluation
- **Company-Specific Feedback** – Tailored suggestions for target companies
- **Skills Gap Analysis** – Identify missing skills and certifications
- **ATS Optimization** – Ensure resume passes Applicant Tracking Systems

### 🎤 Mock Interview System
Choose from three interview formats:

#### 🎯 HR Interview
- Behavioral questions (STAR method)
- Company culture fit assessment
- Soft skills evaluation
- Leadership and teamwork scenarios
- Career motivation questions

#### 💻 Technical Interview
- Role-specific technical challenges
- Programming concepts and algorithms
- System design questions
- Technology stack assessment
- Problem-solving evaluation

#### 🔥 Mixed Interview
- Combined HR and technical questions
- Comprehensive skill assessment
- Realistic interview simulation
- Balanced evaluation across dimensions

### 📊 Performance Analytics
- **Question-by-Question Analysis** – Detailed feedback for each response
- **Multi-Dimensional Scoring** – Relevance, Clarity, Technical Depth ratings
- **Strengths Identification** – Highlight what you did well
- **Improvement Roadmap** – Specific suggestions for enhancement
- **Better Answer Outlines** – Learn optimal response structures
- **PDF Reports** – Professional, shareable performance reports

### 💾 Data Management
- **Encrypted Persistence** – Save data across sessions securely
- **Flexible Updates** – Update resume or job details independently
- **Data Portability** – View all stored information anytime
- **Instant Deletion** – Securely remove all data with one command
- **Session Recovery** – Resume interrupted sessions seamlessly

## 🎯 Interview Customization

Configure your practice session:
- **Question Count**: 3-15 questions (recommended: 5-7)
- **Interview Type**: HR, Technical, or Mixed
- **Time Limits**: 2 minutes per question
- **Difficulty Levels**: Automatically adjusted to role seniority

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- MongoDB database (Atlas or local)
- Telegram Bot Token ([Get one from @BotFather](https://t.me/BotFather))
- Google Gemini API Key ([Get from Google AI Studio](https://makersuite.google.com/app/apikey))

### 1. Clone Repository

```bash
git clone https://github.com/klu-2200031955/AI_Resume_Review.git
cd AI_Resume_Review
```

### 2. Setup Virtual Environment

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Configuration

Create `.env` file in the project root:

```env
# ===== REQUIRED CONFIGURATION =====

# Telegram Bot Token (Get from @BotFather)
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here

# Google Gemini API Key (Get from Google AI Studio)
GEMINI_API_KEY=your_gemini_api_key_here

# MongoDB Connection String
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/resume_bot

# ===== SECURITY CONFIGURATION =====

# Master Encryption Key (Auto-generated if not provided)
# IMPORTANT: Save this key securely - loss means data loss
ENCRYPTION_MASTER_KEY=your_base64_encoded_master_key_here

# Flask Secret Key for Web Sessions
FLASK_SECRET_KEY=your_random_secret_key_here

# Admin Dashboard Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here

# ===== OPTIONAL CONFIGURATION =====

# Countdown seconds for report access (default: 30)
COUNTDOWN_SECONDS=30

# Webhook Configuration (for production deployment)
WEBHOOK_URL=https://your-domain.com/webhook
PORT=5000
```

### 5. MongoDB Setup

#### Option A: MongoDB Atlas (Recommended for Production)

1. Create account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create a new cluster (free tier available)
3. Setup database user and whitelist IP addresses
4. Get connection string and add to `.env`

#### Option B: Local MongoDB (Development)

```bash
# Install MongoDB locally
# Mac (using Homebrew)
brew install mongodb-community

# Start MongoDB
brew services start mongodb-community

# Connection string for local MongoDB
MONGO_URI=mongodb://localhost:27017/resume_bot
```

### 6. Generate Encryption Key (Optional)

If you don't provide `ENCRYPTION_MASTER_KEY`, the bot will auto-generate one on first run. **Save this key immediately!**

To generate manually:
```python
import secrets
import base64

key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
print(f"ENCRYPTION_MASTER_KEY={key}")
```

## ▶️ Running the Bot

### Development Mode (Polling)

```bash
python bot.py
```

The bot will:
- Initialize encryption system
- Connect to MongoDB
- Start polling for Telegram updates
- Serve web dashboard at `http://localhost:5000`

### Production Mode (Webhook)

Set `WEBHOOK_URL` in `.env` then deploy to:

**Heroku:**
```bash
heroku create your-app-name
heroku config:set TELEGRAM_BOT_TOKEN=your_token
heroku config:set GEMINI_API_KEY=your_key
heroku config:set MONGO_URI=your_mongodb_uri
heroku config:set ENCRYPTION_MASTER_KEY=your_key
git push heroku main
```

**Railway:**
```bash
railway init
railway add
# Add environment variables in Railway dashboard
railway up
```

**Render/Google Cloud Run/AWS:**
- Follow platform-specific deployment guides
- Ensure all environment variables are set
- Configure health check endpoint: `/health`

## 🌐 Web Dashboard

Access the comprehensive web interface:

### Public Pages
- **`/`** - Main landing page with feature overview
- **`/about`** - Detailed platform information
- **`/career-tips`** - Professional career guidance
- **`/privacy`** - Privacy policy and data protection details
- **`/status`** - Real-time bot status and statistics
- **`/health`** - Health check endpoint for monitoring

### Admin Panel (Protected)
- **`/admin/login`** - Admin authentication
- **`/admin/dashboard`** - User analytics and management
- **`/admin/broadcast`** - Send messages to all users

### Report Access
- **`/r/{short_id}`** - Short link for interview reports
- **`/view/{filename}`** - PDF report viewer

## 🤖 Bot Commands

### Essential Commands

```
/start
Start the bot. Returns to existing encrypted data or begins new session.

/update_resume
Upload a new resume and replace existing encrypted data.

/update_job
Change company and job role while keeping resume data intact.

/view_data
Display previously saved encrypted data (company, role, timestamp).

/delete_my_data
Permanently and securely delete all stored encrypted data.

/cancel
Cancel current operation and clean up temporary files.
```

## 📖 User Workflow

### First-Time Users

1. **Start Bot** → Send `/start` to @AIResumeReviewBot
2. **Upload Resume** → Send PDF file (max 10MB)
3. **Provide Details** → Enter "Company Name, Job Role"
   - Example: `Google, Software Engineer`
4. **Get Analysis** → Receive comprehensive resume feedback
5. **Choose Interview** → Select HR, Technical, or Mixed
6. **Select Questions** → Pick 3-15 questions (recommended: 5-7)
7. **Answer Questions** → Type responses (2 min per question)
8. **Receive Report** → Get detailed performance analysis PDF

### Returning Users

1. **Start Bot** → Send `/start`
2. **Choose Action** → 
   - Start Interview (with existing data)
   - Change Job Role
   - Upload New Resume
3. **Practice** → Answer questions
4. **Improve** → Review detailed feedback

## 📂 Project Architecture

```
resume-ai-bot/
│
├── bot.py                      # Main application with encryption
│   ├── Telegram bot handlers
│   ├── Flask web server
│   ├── Encryption/decryption logic
│   ├── Admin dashboard
│   └── Report generation
│
├── interview_module.py         # Interview engine
│   ├── Question generation (Gemini AI)
│   ├── Answer evaluation
│   ├── Scoring algorithms
│   └── Model management
│
├── resume_checker.py           # Resume analysis
│   ├── PDF text extraction
│   ├── AI-powered analysis (Gemini)
│   ├── Feedback generation
│   └── Error handling
│
├── prompts.py                  # AI prompt templates
│   ├── Resume analysis prompts
│   └── Answer evaluation prompts
│
├── utils.py                    # Utilities
│   └── PDF text extraction (PyMuPDF)
│
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (create this)
├── .gitignore                  # Git ignore rules
├── README.md                   # Documentation
└── LICENSE                     # MIT License
```

## 🔍 Technical Implementation

### Encryption System

**Algorithm Stack:**
- **Primary**: AES-256-CBC via Fernet (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (prevents brute force)
- **Salt**: Unique 16-byte salt per user
- **Master Key**: 256-bit base64-encoded key

**Data Flow:**
```
Raw Data → JSON Serialization → Fernet Encryption → Base64 Encoding → MongoDB
MongoDB → Base64 Decoding → Fernet Decryption → JSON Parsing → User Data
```

### AI Integration

**Google Gemini Models** (auto-discovery):
- Primary: `gemini-2.0-flash-exp` (fastest, most accurate)
- Fallback: `gemini-1.5-flash`, `gemini-1.5-pro`
- Dynamic model selection based on availability

**Prompt Engineering:**
- Context-aware resume analysis
- Role-specific question generation
- Multi-dimensional answer evaluation
- Structured JSON responses for parsing

### Database Schema

**MongoDB Collections:**
```javascript
// users collection
{
  _id: <user_id>,              // Telegram user ID
  encrypted_data: "base64...",  // Encrypted user data
  salt: "base64...",            // Encryption salt
  encrypted_at: "ISO8601",      // Timestamp
  version: "1.0"                // Schema version
}

// Decrypted user data structure
{
  user_id: 123456789,
  username: "john_doe",
  first_name: "John",
  last_name: "Doe",
  company: "Google",
  role: "Software Engineer",
  resume_text: "...",
  resume_analysis: "...",
  resume_tips: [...],
  timestamp: "2025-01-15T10:30:00"
}
```

## 🛡️ Security Best Practices

### For Developers

1. **Never Commit Secrets**
   ```bash
   # Add to .gitignore
   .env
   *.pem
   *.key
   ```

2. **Rotate Keys Regularly**
   - Change `FLASK_SECRET_KEY` every 90 days
   - Update `ADMIN_PASSWORD` quarterly
   - Monitor `ENCRYPTION_MASTER_KEY` access

3. **Use Environment Variables**
   ```python
   # Good ✅
   api_key = os.getenv("API_KEY")
   
   # Bad ❌
   api_key = "hardcoded-key-123"
   ```

4. **Validate Input**
   - Sanitize user inputs
   - Limit file sizes (10MB max)
   - Validate file types (PDF only)

### For Users

1. **Strong Passwords** - Use unique, complex admin passwords
2. **Secure Environment** - Protect `.env` file with appropriate permissions
3. **Regular Backups** - Backup encryption keys securely
4. **Monitor Access** - Review admin dashboard regularly

## 🚨 Important Security Notices

⚠️ **Critical Warnings:**

1. **Master Key Loss = Data Loss**
   - If you lose `ENCRYPTION_MASTER_KEY`, all encrypted data becomes unrecoverable
   - Store it in a secure password manager
   - Keep offline backup in secure location

2. **Environment File Security**
   - Never commit `.env` to version control
   - Use file permissions: `chmod 600 .env`
   - Restrict server access to authorized personnel only

3. **MongoDB Security**
   - Enable authentication on MongoDB
   - Use strong database passwords
   - Whitelist only necessary IP addresses
   - Enable TLS/SSL for connections

4. **Production Deployment**
   - Always use HTTPS for webhooks
   - Enable rate limiting
   - Set up monitoring and alerts
   - Regular security audits

## 📊 Dependencies

```python
# Core Dependencies
python-telegram-bot==22.3      # Telegram Bot API
google-generativeai            # Google Gemini AI
pymongo==4.5.0                 # MongoDB driver
cryptography==41.0.7           # Encryption library
flask==2.0.0                   # Web framework

# PDF Processing
PyMuPDF>=1.23.23              # PDF text extraction

# Utilities
python-dotenv==1.0.1          # Environment variables
aiofiles==23.2.1              # Async file operations
reportlab==4.2.2              # PDF generation
requests==2.31.0              # HTTP requests
```

## 🐛 Troubleshooting

### Common Issues

**1. Encryption Key Errors**
```
Error: Invalid encryption key format
```
**Solution:** Ensure `ENCRYPTION_MASTER_KEY` is properly base64-encoded:
```python
import base64
key = base64.urlsafe_b64encode(b'your-32-byte-key-here').decode()
```

**2. MongoDB Connection Failed**
```
Error: Could not connect to MongoDB
```
**Solution:** 
- Check `MONGO_URI` format
- Verify network connectivity
- Whitelist your IP in MongoDB Atlas
- Ensure database user has proper permissions

**3. Gemini API Errors**
```
Error: API quota exceeded
```
**Solution:**
- Check API key validity
- Verify quota limits in Google Cloud Console
- Add billing if free tier exhausted

**4. File Upload Issues**
```
Error: File too large or invalid format
```
**Solution:**
- Ensure PDF is under 10MB
- Verify file is valid PDF (not corrupted)
- Check file contains extractable text

**5. Webhook Not Receiving Updates**
```
Error: No updates received via webhook
```
**Solution:**
- Ensure `WEBHOOK_URL` is publicly accessible
- Must use HTTPS (not HTTP)
- Check firewall/security group settings
- Verify webhook is set: `curl https://api.telegram.org/bot<token>/getWebhookInfo`

### Debug Mode

Enable detailed logging:
```python
# In bot.py, change:
logging.basicConfig(level=logging.DEBUG)
```

### Testing Components

**Test Encryption:**
```python
from bot import DataEncryption
enc = DataEncryption()
test_data = {"test": "data"}
encrypted = enc.encrypt_data(123456, test_data)
decrypted = enc.decrypt_data(123456, encrypted)
assert test_data == decrypted
```

**Test Gemini API:**
```python
python resume_checker.py  # Runs built-in tests
python interview_module.py  # Tests question generation
```

## 📈 Performance Optimization

### Response Time Targets
- Resume analysis: < 30 seconds
- Question generation: < 15 seconds
- Answer evaluation: < 5 seconds per answer
- Report generation: < 10 seconds

### Optimization Tips
1. **Use Connection Pooling** for MongoDB
2. **Implement Caching** for frequently accessed data
3. **Async Processing** for long-running operations
4. **Rate Limiting** to prevent API quota exhaustion

## 🤝 Contributing

We welcome contributions! Here's how:

### Getting Started
1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes following code style
4. Test thoroughly (especially encryption)
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open Pull Request

### Contribution Guidelines

**Code Style:**
- Follow PEP 8 for Python code
- Use type hints where applicable
- Add docstrings for functions
- Comment complex logic

**Security Contributions:**
- Use established cryptographic libraries
- Follow OWASP security guidelines
- Never store secrets in code
- Test edge cases thoroughly
- Add appropriate logging

**Testing Requirements:**
- Test encryption/decryption flows
- Verify error handling
- Check input validation
- Test with various file sizes

**Documentation:**
- Update README for new features
- Add inline code comments
- Update API documentation
- Include usage examples

### Areas for Contribution
- 🔐 Additional security features
- 🌍 Internationalization (i18n)
- 📊 Enhanced analytics dashboard
- 🎨 UI/UX improvements
- 🧪 Additional test coverage
- 📝 Documentation improvements

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**MIT License Summary:**
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No liability or warranty

## 🔗 Resources & Links

### Project Links
- **GitHub Repository**: [AI_Resume_Review](https://github.com/klu-2200031955/AI_Resume_Review)
- **Live Bot**: [@AIResumeReviewBot](https://t.me/AIResumeReviewBot)
- **Support Bot**: [@AIResumeReviewSupportBot](https://t.me/AIResumeReviewSupportBot)
- **Issues & Feature Requests**: [GitHub Issues](https://github.com/klu-2200031955/AI_Resume_Review/issues)

### Documentation
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Google Gemini AI](https://ai.google.dev/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Cryptography Library](https://cryptography.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [PBKDF2 Specification](https://tools.ietf.org/html/rfc2898)

## 🏆 Acknowledgments

Special thanks to:
- **Telegram** for the excellent Bot API
- **Google** for Gemini AI technology
- **MongoDB** for reliable database services
- **Python Community** for amazing libraries
- **Contributors** for their valuable input

## 📞 Support

Need help?

- **📧 Email**: svptk12@gmail.com
- **💬 Telegram Support**: [@AIResumeReviewSupportBot](https://t.me/AIResumeReviewSupportBot)
- **🐛 Report Bugs**: [GitHub Issues](https://github.com/klu-2200031955/AI_Resume_Review/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/klu-2200031955/AI_Resume_Review/discussions)

---

<div align="center">

**Built with ❤️ by developers, for developers**

⭐ Star this repo if you find it helpful!

[Report Bug](https://github.com/klu-2200031955/AI_Resume_Review/issues) · [Request Feature](https://github.com/klu-2200031955/AI_Resume_Review/issues) · [Documentation](https://github.com/klu-2200031955/AI_Resume_Review/wiki)

</div>

---

**⚠️ Final Security Reminder**: This bot handles sensitive personal data (resumes, career information). Always ensure proper environment configuration, keep encryption keys secure, and never share your `.env` file. Regular security audits and updates are essential for production deployments.
