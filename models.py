from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)

class Owner(db.Model):
    __tablename__ = "owner"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(), nullable= False)
    last_name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return f"iD: {self.id}. Name: {self.first_name} {self.last_name}"
    
class Book(db.Model):
    __tablename__ = "book"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False, unique=True)
    description = db.Column(db.String(), nullable=False)
    author_first_name = db.Column(db.String(), nullable=False)
    author_last_name = db.Column(db.String(), nullable=False)
    
    def __repr__(self):
        return f"Book's Details: {self.id}. {self.name}"
    

