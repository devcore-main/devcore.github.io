from flask import Flask, request, jsonify
from validators import validate_email, validate_password, validate_contact

app = Flask(__name__)

@app.post("/signup")
def signup():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")

    # ---- VALIDATION ----
    if not validate_email(email):
        return jsonify({"error": "Invalid email"}), 400
    
    if not validate_password(password):
        return jsonify({"error": "Password too short"}), 400
    
    return jsonify({"message": "Account created successfully!"})
    

@app.post("/contact")
def contact():
    data = request.json

    if not validate_contact(data.get("name"), data.get("email"), data.get("message")):
        return jsonify({"error": "Missing fields"}), 400

    return jsonify({"message": "Message sent!"})


if __name__ == "__main__":
    app.run(debug=True)
