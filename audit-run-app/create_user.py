"""Create an auditor account. Run manually: python create_user.py
"""
import getpass
import warnings
warnings.filterwarnings("ignore")
from werkzeug.security import generate_password_hash

import os
os.environ.setdefault("FLASK_DEBUG", "1")

from app import app  
from models import db, User  

if __name__ == "__main__":
    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty.")
        raise SystemExit(1)

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        raise SystemExit(1)
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        raise SystemExit(1)

    with app.app_context():
        if User.query.filter_by(username=username).first():
            print(f"User '{username}' already exists.")
            raise SystemExit(1)
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        print(f"Created auditor account '{username}'.")