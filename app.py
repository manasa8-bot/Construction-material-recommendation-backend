from flask import Flask, request, jsonify
from flask_cors import CORS
from bson.objectid import ObjectId
from pymongo import MongoClient
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
