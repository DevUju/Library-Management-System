from config import app, db
from flask import request, jsonify
from flask_caching import Cache
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
import redis
from datetime import timedelta
from flask_bcrypt import Bcrypt
import os


app.config['JWT_SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['CACHE_TYPE'] = 'RedisCache' 
app.config['CACHE_REDIS_HOST'] = 'localhost'
app.config['CACHE_REDIS_PORT'] = 6379
app.config['CACHE_DEFAULT_TIMEOUT'] = 300


jwt = JWTManager(app)
cache = Cache(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
expiration = timedelta(days=30)


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
        
        # Check if username or email already exists
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
                "librarian": {
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
        username = data["email"]
        password = data["password"]

        user = Owner.query.filter_by(username=username).first()

        if user is None:
            return jsonify({"status": "Bad request", "message": "User not found", "statusCode": 404}), 404
        if bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=username, expires_delta=expiration)
            refresh_token = create_refresh_token(identity=username)
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
                        "message": "Authentication failed", 
                        "statusCode": 401})
