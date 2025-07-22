# ProjectTrackingHub
Timeline: February – April 2024
Project Tracking Hub is a web-based platform for managing and organizing detailed project information, enabling team collaboration, and automatically generating professional PDF reports with progress visualizations.


## ⚙️ Features

- 🗂️ Create, edit, and delete projects and tasks
- 👥 Add and manage multiple collaborators or administrators per project
- 📅 Organize work using task blocks
- 📊 Visualize progress with charts (via Matplotlib)
- 🧾 Generate downloadable PDF reports of project status
- 🔐 User authentication and password reset (via email)

**Note:**  
This web app was primarily designed for desktop screens and does not currently feature a responsive UI for mobile or tablet devices.

## 🛠️ Built With

- **Python** + **Flask** (Backend)
- **HTML/CSS + Jinja2** (Frontend)
- **PostgreSQL + SQLAlchemy** (Database ORM)
- **matplotlib** – for generating progress charts
- **pdfkit / wkhtmltopdf** – for creating PDFs
- **Flask-Mail** – for email support

## 🚀 Getting Started

### ✅ Prerequisites

- Python 3.10+
- PostgreSQL
- wkhtmltopdf installed (for PDF generation)
- SMTP credentials (for password reset via email)

### 🔧 Setup Instructions

- git clone https://github.com/NoStory-py/ProjectTrackingHub.git
- cd ProjectTrackingHub
- pip install -r requirements.txt
- flask db init
- flask db migrate -m "Initial"
- flask db upgrade
- python app.py

### 🛠️ Set environment variables for app.py
- SECRET_KEY=your-secret-key
- MAIL_USERNAME=your-email@gmail.com
- MAIL_PASSWORD=your-app-password
- MAIL_DEFAULT_SENDER=your-email@gmail.com
