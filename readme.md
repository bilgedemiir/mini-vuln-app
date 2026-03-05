# Flask Security Lab

This project is a small Flask web application created to demonstrate common web security vulnerabilities and how to fix them.

The repository contains two main implementations:

- **vulnerable** → intentionally vulnerable version used for learning and demonstrating attacks
- **secure** → fixed and secure implementation

This project was built as part of my cybersecurity learning process.


# Project Overview

The application includes a simple web system with:

- User registration
- Login system
- Comment system
- Admin panel

The vulnerable version demonstrates common security issues, while the secure version shows how those vulnerabilities can be fixed.


# Repository Structure

flask-security-lab
│
├ master
│ └ project documentation (this README)
│
├ vulnerable
│ └ intentionally vulnerable implementation
│
└ secure
└ secure implementation with fixes

# Vulnerabilities Demonstrated

The **vulnerable branch** includes examples of common web security vulnerabilities:

- SQL Injection
- Stored Cross-Site Scripting (XSS)
- Broken Access Control
- Hardcoded admin privilege logic
- Missing CSRF protection
- Weak secret key configuration

These vulnerabilities are intentionally included for educational purposes.


# Security Improvements

The **secure branch** demonstrates how these vulnerabilities can be fixed:

- Parameterized SQL queries to prevent SQL Injection
- Escaped HTML output to prevent XSS
- Role-based access control for admin routes
- Password hashing using **bcrypt**
- CSRF protection in forms
- Secret key loaded from environment variables
- Improved session handling


# Technologies Used

- Python
- Flask
- SQLite
- bcrypt


# Running the Project Locally

Clone the repository:
git clone https://github.com/bilgedemiir/flask-security-lab.git

Create a virtual environment:
python -m venv .venv

Activate the environment:
Windows:
.venv\Scripts\activate

Install dependencies:
pip install -r requirements.txt

Initialize the database:
python -c "from db import init_db; init_db()"

Run the application:
python app.py


# Disclaimer

This project contains intentionally vulnerable code in the **vulnerable branch** for educational purposes only.

Do not deploy vulnerable code in production environments.
