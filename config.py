from dotenv import load_dotenv
import os
from app import app

load_dotenv()

class config:
    app.config['SECRET_KEY'] = '85732984091'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
