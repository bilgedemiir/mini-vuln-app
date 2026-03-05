# Mini Web Security Demo (Flask)
## This project demonstrates common web vulnerabilities and their secure fixes.

Branches
vulnerable → intentionally vulnerable version
secure → fixed secure implementation
Features
Register / Login
Comment system
Admin panel
Technologies
Python
Flask
SQLite
bcrypt
Run Locally
python -m venv .venv .venv\Scripts\activate pip install -r requirements.txt

python -c "from db import init_db; init_db()" python app.py