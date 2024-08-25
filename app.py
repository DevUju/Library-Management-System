from config import app, db
from models import Owner, Book
from flask import request, jsonify
from flask_caching import Cache
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
import redis
from datetime import timedelta
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os

load_dotenv()


jwt = JWTManager(app)
cache = Cache(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
expiration = timedelta(days=30)


# Initialize Redis client directly
# redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

redis_client = redis.Redis(
  host=os.getenv("REDIS_HOST"),
  port=os.getenv("REDIS_PORT"),
  password=os.getenv("REDIS_PASSWORD"))


# Validate user model
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


#Implement User Registration
@app.route("/user/register", methods=["POST"])
def user_register():
    try:
        data = request.get_json()
        f_name = data["first_name"]
        l_name = data["last_name"]
        user_email = data["email"]
        user_password = data["password"]
        
        existing_user = Owner.query.filter((Owner.email == user_email)).first()
        if existing_user:
            return jsonify({
                "message": "Email already exists", 
                "status": "Bad request", 
                "statusCode": 401})


        hashed_password = bcrypt.generate_password_hash(user_password).decode("utf-8")

        new_user = Owner(
            first_name = f_name,
            last_name = l_name,
            email = user_email,
            password = hashed_password
        )

        validate_model(new_user)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "Status": "Success",
            "Message": "Registration Successful",
                "User": {
                    "id": new_user.id,
                    "first_name": new_user.first_name,
                    "last_name": new_user.last_name,
                    "email": new_user.email
                }
            }
        ), 200
    except:
        return jsonify({
                        "status": "Bad request", 
                        "message": "Registration failed", 
                        "statusCode": 401})


#Implement User Login and Authentication
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
    except:
        return jsonify({
                        "status": "Bad request", 
                        "message": f"Authentication failed", 
                        "statusCode": 401})
    

# Implement a refresh token endpoint
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()  
        new_access_token = create_access_token(identity=current_user, expires_delta=expiration)
        return jsonify({
            "Status": "Success",
            "Message": "Token Refreshed",
            "Access_Token": new_access_token
        }), 200
    except:
        return jsonify({"Status": "Bad request", 
                        "Message": "Token refresh failed", 
                        "StatusCode": 401}), 401


# Implement a logout endpoint
@app.route("/user/logout", methods=["POST"])
@jwt_required()
def user_logout():
    try:
        access_token = request.headers['Authorization'].split(" ")[1]
        
        cache.delete(access_token)
        return jsonify({
            "Status": "Success",
            "Message": "Logged out successfully"
        }), 200
    except:
        return jsonify({
            "Status": "Bad request",
            "Message": "Logout failed",
            "StatusCode": 400
        }), 400


# Endpoint for adding a book
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
            "Message": "Book Added Successfully",
            "book_data": {
                "id": new_book.id,
                "name": new_book.name,
                "description": new_book.description,
                "author_first_name": new_book.author_first_name,
                "author_last_name": new_book.author_last_name
            }
        }), 200
    except:
        return jsonify({
            "status": "Bad request", 
            "message": "Book failed to be added", 
            "statusCode": 401})


# Endpoint for getting all books
@app.route("/books", methods=["GET"])
@cache.cached(timeout=60, key_prefix='all_books')  
def get_books():
    try:
        books = Book.query.all()
        books_data = [{
            "id": book.id,
            "name": book.name,
            "description": book.description,
            "author_first_name": book.author_first_name,
            "author_last_name": book.author_last_name
        } for book in books]
        return jsonify({"books": books_data}), 200
    except:
        return jsonify({
            "Message": "Unable to retrieve books!!!"
        })


# Endpoint for getting a particular book
@app.route("/book/<int:book_id>", methods=["GET"])
@cache.cached(timeout=60, key_prefix="book_<book_id>")  
def get_book(book_id):
    try:
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

        return jsonify({"Status": "Success", 
                        "Book": book_data}), 200
    except:
        return jsonify({
            "Status": "Not Found",
            "Message": "Book does not exist"
        })


# Endpoint for updating a particular book
@app.route("/book/update/<int:book_id>", methods=["PATCH"])
@cache.cached(timeout=60, key_prefix="book_<book_id>")
@jwt_required()
def update_book(book_id):
    try:
        data = request.get_json()
        book = Book.query.get(book_id)
        print("Visible Data")
        if not book:
            return jsonify({"status": "Not Found", "message": "Book not found", "statusCode": 404}), 404

        book.name = data.get("name", book.name)
        book.description = data.get("description", book.description)
        book.author_first_name = data.get("author_first_name", book.author_first_name)
        book.author_last_name = data.get("author_last_name", book.author_last_name)
        db.session.commit()

        print(cache.get(book_id))
        cache.delete(f'book_{book_id}')

        return jsonify({"Status": "Success", 
                        "Message": "Book updated successfully"}), 200
    except:
        return jsonify({"Status": "Bad request", 
                        "Message": "Update failed", 
                        "StatusCode": 400}), 400


# Endpoint for deleting a book
@app.route("/book/delete/<int:book_id>", methods=["DELETE"])
@cache.cached(timeout=60, key_prefix="book_<book_id>")
@jwt_required()
def delete_book(book_id):
    try:
        book = Book.query.get(book_id)
        if not book:
            return jsonify({"status": "Not Found", "message": "Book not found", "statusCode": 404}), 404

        db.session.delete(book)
        db.session.commit()

        cache.delete(f'book_{book_id}')

        return jsonify({"Status": "Success", 
                        "Message": "Book deleted successfully"}), 200
    except:
        return jsonify({"Status": "Bad request", 
                        "Message": "Delete failed", 
                        "StatusCode": 400}), 400


with app.app_context():
    db.create_all()       

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)