# Knowledge Building Platform

A full‑stack institutional knowledge‑sharing and learning platform built using **Flask + MySQL**, designed to help students, instructors, and administrators manage courses, upload resources, track progress, and collaborate efficiently.

---

## 🚀 Features

### 🎓 **Student Features**
- Browse and enroll in courses
- View lessons, documents, PPTs, videos, and PDFs
- Attempt quizzes and view results
- Track learning progress
- Receive notifications

### 🧑‍🏫 **Instructor Features**
- Create and manage courses
- Upload lessons, videos, study materials, and quizzes
- Manage topics and question banks
- View student performance

### 🛠️ **Admin Features**
- Add/edit/delete topics
- Manage courses and users
- Upload global resources
- Access analytics dashboard

### 📁 **Platform Features**
- Clean UI with multiple theme options
- Secure file uploads
- Role‑based access control (admin / instructor / student)
- Google OAuth login (configurable)

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript, Jinja Templates |
| Database | MySQL |
| Authentication | Google OAuth (configurable) |
| File Storage | Local static uploads |

---

## 📦 Folder Structure
```
knowledge_building_platform/
├── app.py
├── config.py
├── requirements.txt
├── static/
│   ├── css/
│   └── uploads/
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   └── ...
└── __pycache__/
```

---

## ⚙️ Installation Guide

### 1️⃣ Clone the Repository
```
git clone https://github.com/Manjunath9346/knowledge_building_platform.git
cd knowledge_building_platform
```

### 2️⃣ Create Virtual Environment
```
python -m venv venv
venv\Scripts\activate  # Windows
```

### 3️⃣ Install Dependencies
```
pip install -r requirements.txt
```

### 4️⃣ Setup `.env` (Recommended)
Create a file named `.env`:
```
SECRET_KEY=
MAIL_USERNAME=
MAIL_PASSWORD=
GOOGLE_OAUTH_CLIENT_ID=
GOOGLE_OAUTH_CLIENT_SECRET=
```

### 5️⃣ Run the App
```
python app.py
```
Visit: **http://localhost:5000**

---

## 🛡️ Security Notes
- Do **NOT** commit API keys, OAuth tokens, or email passwords.
- Use a `.env` file to store secrets securely.
- `.gitignore` now protects `__pycache__/` and compiled files.

---

## 📌 Future Enhancements
- API endpoints for mobile app
- Instructor analytics dashboard
- Real‑time chat/forum
- Cloud storage (S3 / Firebase)
- Deploy on Render/Heroku/AWS

---

## 👨‍💻 Author
**Manjunath Sankarapu**  
GitHub: [Manjunath9346](https://github.com/Manjunath9346)

---

If you want, I can:
✔ Add screenshots section  
✔ Add badges (Python, Flask, GitHub stars, etc.)  
✔ Add deployment tutorial  
✔ Improve formatting  

Just tell me! 😊

