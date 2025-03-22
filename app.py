# Install required dependencies before running this script:
# pip install flask flask_sqlalchemy flask_jwt_extended pymysql python-dotenv werkzeug pyotp qrcode[pil]

import datetime
import pyotp
import qrcode
import io
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config  # Import our configuration

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ------------------- Database Models ------------------- #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    otp_secret = db.Column(db.String(255), nullable=True)  # 2FA Secret Key

# Create tables (Run once)
with app.app_context():
    db.create_all()

# ------------------- API Endpoints ------------------- #

# User Signup: Register a new user
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not all(k in data for k in ("name", "username", "password")):
        return jsonify({'error': 'Missing data'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        name=data['name'],
        username=data['username'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# User Login: Authenticate user and return a JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not all(k in data for k in ("username", "password")):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify({'token': token}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

# Generate 2FA QR Code and store secret in the database
@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a new secret key and save it to the database
    secret = pyotp.random_base32()
    user.otp_secret = secret
    db.session.commit()

    # Create provisioning URI for Google Authenticator
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name='Data_Integrity_Section_2FA')

    # Generate QR code
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img, format='PNG')
    img.seek(0)

    return send_file(img, mimetype='image/png')

# Verify 2FA Code using the stored OTP secret in the database
@app.route('/verify-2fa/<username>', methods=['POST'])
def verify_2fa(username):
    data = request.get_json()
    user_code = data.get('code')

    user = User.query.filter_by(username=username).first()
    if not user or not user.otp_secret:
        return jsonify({'message': 'User not found or 2FA not set up'}), 404

    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(user_code):
        return jsonify({'message': '2FA verified successfully'})
    else:
        return jsonify({'message': 'Invalid or expired code'}), 401

if __name__ == '__main__':
    app.run(debug=True)
