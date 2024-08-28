from config import app, db
from models import Owner, Book
from flask import request, jsonify
from flask_caching import Cache
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
import redis
import json
from datetime import timedelta
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Initialize Flask extensions
jwt = JWTManager(app)
cache = Cache(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
expiration = timedelta(days=30)

# Initialize Redis client
redis_client = redis.Redis(
  host=os.getenv("CACHE_REDIS_HOST"),
  port=os.getenv("CACHE_REDIS_PORT"),
  password=os.getenv("CACHE_REDIS_PASSWORD"))
# redis_client = redis.Redis(host=os.getenv("CACHE_REDIS_HOST"), port=os.getenv("CACHE_REDIS_PORT"), db=os.getenv("DB"))

# Utility function to validate and commit a model to the database
def validate_model(model):
    try:
        db.session.add(model)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        errors = []
        for err in e.orig.args:
            errors.append({"field": err.split()[0], "message": " ".join(err.split()[1:])})
        return jsonify({"errors": errors}), 422
    return  jsonify({"message": "User created successfully!"}), 201


# User Registration Endpoint
@app.route("/user/register", methods=["POST"])
def user_register():
    try:
        data = request.get_json()
        f_name = data["first_name"]
        l_name = data["last_name"]
        user_email = data["email"]
        user_password = data["password"]

        existing_user = Owner.query.filter_by(email=user_email).first()
        if existing_user:
            return jsonify({"message": "Email already exists", "status": "Bad request", "statusCode": 401})

        hashed_password = bcrypt.generate_password_hash(user_password).decode("utf-8")
        new_user = Owner(
            first_name=f_name,
            last_name=l_name,
            email=user_email,
            password=hashed_password
        )

        validate_model(new_user)
        return jsonify({
                "Status": "Success",
                "Message": "Registration Successful",
                "data": {
                    "user_data": {
                        "id": new_user.id,
                        "first_name": new_user.first_name,
                        "last_name": new_user.last_name,
                        "email": new_user.email}}})
    except Exception as e:
        return jsonify({"status": "Bad request", 
                        "message": f"Registration failed: {str(e)}", 
                        "statusCode": 401}), 401


# User Login and Authentication Endpoint
@app.route("/user/login", methods=["POST"])
def user_login():
    try:
        data = request.get_json()
        email = data["email"]
        password = data["password"]

        user = Owner.query.filter_by(email=email).first()

        if user is None:
            return jsonify({"status": "Bad request", "message": "User not found", "statusCode": 404}), 404

        if bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=email, expires_delta=expiration)
            refresh_token = create_refresh_token(identity=email)

            redis_client.set(f"token:{email}", access_token)
            redis_client.expire(f"token:{email}", timedelta(hours=1))

            return jsonify({
                "Status": "Success",
                "Message": "Login Successful",
                "data": {
                    "Access_Token": access_token,
                    "Refresh_Token": refresh_token,
                    "librarian": {
                        "id": user.id,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "email": user.email
                    }
                }
            }), 200
        else:
            return jsonify({"status": "Bad request", 
                            "message": "Incorrect password", 
                            "statusCode": 401}), 401
    except Exception as e:
        return jsonify({"status": "Bad request", 
                        "message": f"Authentication failed: {str(e)}", 
                        "statusCode": 401}), 401

# Refresh Token Endpoint
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user, expires_delta=expiration)
        return jsonify({"Status": "Success", 
                        "Message": "Token Refreshed", 
                        "Access_Token": new_access_token}), 200
    except Exception:
        return jsonify({"Status": "Bad request", 
                        "Message": "Token refresh failed", 
                        "StatusCode": 401}), 401

# User Logout Endpoint
@app.route("/user/logout", methods=["POST"])
@jwt_required()
def user_logout():
    try:
        access_token = request.headers['Authorization'].split(" ")[1]
        cache.delete(access_token)
        return jsonify({"Status": "Success", 
                        "Message": "Logged out successfully"}), 200
    except Exception:
        return jsonify({"Status": "Bad request", 
                        "Message": "Logout failed", 
                        "StatusCode": 400}), 400

# Add Book Endpoint
@app.route("/add/book", methods=["POST"])
@jwt_required()
def add_book():
    try:
        data = request.get_json()
        book_name = data["name"]
        book_description = data["description"]
        first_name = data["author_first_name"]
        last_name = data["author_last_name"]

        new_book = Book(
            name=book_name,
            description=book_description,
            author_first_name=first_name,
            author_last_name=last_name
        )

        validate_model(new_book)
        return jsonify({
            "Status": "Success",
            "Message": "Book added successfully",
            "book_data": {
                "id": new_book.id,
                "name": new_book.name,
                "description": new_book.description,
                "author_first_name": new_book.author_first_name,
                "author_last_name": new_book.author_last_name
        }}), 201
    except Exception:
        return jsonify({"status": "Bad request", 
                        "message": "Book failed to be added", 
                        "statusCode": 401})

# Get All Books Endpoint
@app.route("/books", methods=["GET"])
def get_books():
    try:
        cache_key = "all_books"
        cached_books = redis_client.get(cache_key)

        if cached_books:
            books_data = json.loads(cached_books)
            return jsonify({"books": books_data}), 200

        books = Book.query.all()
        books_data = [{
            "id": book.id,
            "name": book.name,
            "description": book.description,
            "author_first_name": book.author_first_name,
            "author_last_name": book.author_last_name
        } for book in books]

        redis_client.setex(cache_key, timedelta(seconds=60), json.dumps(books_data))

        return jsonify({"books": books_data}), 200
    except Exception as e:
        return jsonify({"Message": f"Unable to retrieve books!!! {str(e)}"}), 500


# Get a Particular Book Endpoint
@app.route("/book/<int:book_id>", methods=["GET"])
def get_book(book_id):
    try:
        cache_key = f"book_{book_id}"
        cached_book = redis_client.get(cache_key)

        if cached_book:
            book_data = json.loads(cached_book)
            return jsonify({"Status": "Success", "Book": book_data}), 200

        book = Book.query.get(book_id)
        if book is None:
            return jsonify({"status": "Not Found", "message": "Book not found", "statusCode": 404}), 404

        book_data = {
            "id": book.id,
            "name": book.name,
            "description": book.description,
            "author_first_name": book.author_first_name,
            "author_last_name": book.author_last_name
        }

        redis_client.setex(cache_key, timedelta(seconds=60), str(book_data))

        return jsonify({"Status": "Success", "Book": book_data}), 200
    except Exception as e:
        return jsonify({"Status": "Error", "Message": f"An error occurred: {str(e)}"}), 500


# Update a Particular Book Endpoint
@app.route("/book/update/<int:book_id>", methods=["PATCH"])
@jwt_required()
def update_book(book_id):
    try:
        data = request.get_json()
        book = Book.query.get(book_id)

        if not book:
            return jsonify({"status": "Not Found", "message": "Book not found", "statusCode": 404}), 404

        book.name = data.get("name", book.name)
        book.description = data.get("description", book.description)
        book.author_first_name = data.get("author_first_name", book.author_first_name)
        book.author_last_name = data.get("author_last_name", book.author_last_name)
        db.session.commit()

        book_data = {
            "id": book.id,
            "name": book.name,
            "description": book.description,
            "author_first_name": book.author_first_name,
            "author_last_name": book.author_last_name
        }

        cache_key = f'book_{book_id}'
        redis_client.delete(cache_key)

        redis_client.setex(cache_key, timedelta(seconds=60), json.dumps(book_data))

        return jsonify({"Status": "Success", 
                        "Message": "Book updated successfully"}), 200
    except Exception as e:
        return jsonify({"Status": "Bad request", 
                        "Message": f"Update failed: {str(e)}", 
                        "StatusCode": 400}), 400


# Delete a Book Endpoint
@app.route("/book/delete/<int:book_id>", methods=["DELETE"])
@jwt_required()
def delete_book(book_id):
    try:
        book = Book.query.get(book_id)
        if not book:
            return jsonify({"status": "Not Found", "message": "Book not found", "statusCode": 404}), 404

        db.session.delete(book)
        db.session.commit()

        cache_key = f'book_{book_id}'
        redis_client.delete(cache_key)

        return jsonify({"Status": "Success", 
                        "Message": "Book deleted successfully"}), 200
    except Exception as e:
        return jsonify({"Status": "Bad request", 
                        "Message": f"Delete failed: {str(e)}", 
                        "StatusCode": 400}), 400


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)