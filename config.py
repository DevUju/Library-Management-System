from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# Set up the configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["CACHE_TYPE"] = os.getenv("CACHE_TYPE") 
app.config["CACHE_REDIS_HOST"] = os.getenv("CACHE_REDIS_HOST")
app.config["CACHE_REDIS_PORT"] = os.getenv("CACHE_REDIS_PORT")
app.config['CACHE_REDIS_PASSWORD'] = os.getenv("CACHE_REDIS_PASSWORD")
app.config['CACHE_REDIS_URL'] = os.getenv("CACHE_REDIS_URL")
app.config["CACHE_DEFAULT_TIMEOUT"] = os.getenv("CACHE_DEFAULT_TIMEOUT")

# Initialize the database
db = SQLAlchemy(app)