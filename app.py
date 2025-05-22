from flask import Flask, request, jsonify
from flask_cors import CORS
from bson.objectid import ObjectId
from pymongo import MongoClient
import bcrypt
import jwt
from flask_jwt_extended import jwt_required, get_jwt_identity
import datetime

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'your_secret_key'

client = MongoClient("mongodb+srv://marrapumanasa11:Manasa12@cluster0.ajrkokv.mongodb.net/")

# User database
user_db = client["user_db"]
users_collection = user_db["users"]

# Admin database
admin_db = client["admin_db"]
admin_collection = admin_db["admins"]

# Material database
db = client["Materials_db"]
collection = db["Materials"]


# ====================== FETCH USERS ======================

def convert_user(user):
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "password": user["password"].decode() if isinstance(user["password"], bytes) else user["password"]
    }


@app.route('/users', methods=['GET'])
def get_users():
    users = user_db.users.find()
    users_list = [convert_user(user) for user in users]
    return jsonify(users_list)


@app.route("/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 1:
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404
    

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_email = get_jwt_identity() 
    user = users_collection.find_one({"email": user_email})
    if user:
        return jsonify({
            "username": user["username"],
            "email": user["email"]
        }), 200
    return jsonify({"msg": "User not found"}), 404


# ====================== FETCH MATERIALS ======================


def serialize(doc):
    doc['_id'] = str(doc['_id'])
    return doc


@app.route("/materials", methods=["GET"])
def get_materials():
    materials = list(collection.find())
    return jsonify([serialize(m) for m in materials])


@app.route("/materials", methods=["POST"])
def add_material():
    data = request.json
    collection.insert_one(data)
    return jsonify({"message": "Material added successfully"}), 201


@app.route('/materials/<id>', methods=['PUT'], endpoint="update_material")
def update_material(id):
    data = request.json

    if '_id' in data:
        del data['_id']

    result = collection.update_one({"_id": ObjectId(id)}, {"$set": data})
    
    if result.matched_count:
        return jsonify({"message": "Material updated successfully"}), 200
    else:
        return jsonify({"error": "Material not found"}), 404


@app.route("/materials/<string:id>", methods=["DELETE"])
def delete_material(id):
    collection.delete_one({"_id": ObjectId(id)})
    return jsonify({"message": "Material deleted successfully"})


# ====================== USER ROUTES ======================


# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password = data['password']

    # Check if user already exists
    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}), 400

    # Hash password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into database
    users_collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_pw
    })

    return jsonify({"message": "User registered successfully"}), 201


# User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        # Check if request data is present and contains required fields
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"message": "Missing email or password"}), 400

        email = data['email']
        password = data['password']

        # Find user in the database
        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"message": "Invalid email or password"}), 401

        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            token = jwt.encode(
                {
                    "email": email,
                    "username": user['username'],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                },
                app.config['SECRET_KEY'],
                algorithm="HS256"
            )
            return jsonify({"message": "Login successful", "token": token}), 200
        else:
            return jsonify({"message": "Invalid email or password"}), 401

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


# Forgot Password (Generate Token)
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data['email']

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "Email not found"}), 404

    reset_token = jwt.encode(
        {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    return jsonify({"message": "Reset token generated", "token": reset_token}), 200


# Reset Password
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data['token']
    new_password = data['new_password']

    try:
        decoded_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        email = decoded_data['email']
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users_collection.update_one({"email": email}, {"$set": {"password": hashed_pw}})
        return jsonify({"message": "Password reset successful"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 400


# ====================== ADMIN ROUTES ======================

@app.route('/api/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    admin = admin_collection.find_one({"username": username})

    if admin:
        if bcrypt.checkpw(password.encode('utf-8'), admin['password']):
            return jsonify({"message": "Login successful", "status": "success"}), 200
        else:
            return jsonify({"message": "Incorrect password", "status": "fail"}), 401
    else:
        return jsonify({"message": "Admin not found", "status": "fail"}), 404


# ====================== RECOMMEND ======================

@app.route("/recommend", methods=["POST"])
def recommend_material():
    """Recommend materials based on user preferences."""
    data = request.json
    budget = data.get("budget")
    min_durability = data.get("min_durability")
    environmental_pref = data.get("environmental_suitability")

    query = {
        "Cost_Per_Unit": {"$lte": budget},
        "Durability": {"$gte": min_durability}
    }
    if environmental_pref:
        query["Environmental_Suitability"] = environmental_pref

    recommended_materials = list(collection.find(query, {"_id": 0}))
    return jsonify(recommended_materials)


# ====================== MAIN ======================

if __name__ == '__main__':
    app.run(debug=True)