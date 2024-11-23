from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize the Flask app
trial_app = Flask(__name__)  # Renamed to trial_app to avoid conflicts
trial_app.secret_key = os.getenv('SECRET_KEY')  # Use the secret key from .env
Bootstrap(trial_app)

# Dummy storage
patients = {}
doctors = {}
nurses = {}
patient_records = {}

# RSA Key generation and management
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

private_key, public_key = generate_rsa_keys()

def encrypt_data(data):
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode('utf-8'))

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key), base64.b64encode(cipher_aes.nonce + tag + ciphertext)

def decrypt_data(encrypted_aes_key, encrypted_data):
    encrypted_aes_key = base64.b64decode(encrypted_aes_key)
    encrypted_data = base64.b64decode(encrypted_data)

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data.decode('utf-8')

# Templates dictionary (same as in your paste)
templates = {
    "index": """
    {% extends "bootstrap/base.html" %}
    {% block content %}
    <div class="container text-center mt-5">
        <h1>Welcome to Patient Record System</h1>
        <a href="{{ url_for('register') }}" class="btn btn-primary mt-3">Register</a>
        <a href="{{ url_for('login') }}" class="btn btn-success mt-3">Login</a>
    </div>
    {% endblock %}
    """,
    # ... (rest of your templates)
}

# Define your routes
def setup_routes(app):
    @app.route('/')
    def index():
        return render_template_string(templates["index"])

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            role = request.form['role']
            username = request.form['username']
            password = request.form['password']
            
            encrypted_password = encrypt_data(password)
            
            if role == 'patient':
                patients[username] = {'password': encrypted_password, 'records': {}}
            elif role == 'doctor':
                doctors[username] = {'password': encrypted_password, 'patients': {}}
            elif role == 'nurse':
                nurses[username] = {'password': encrypted_password}
            
            flash(f"{role.capitalize()} {username} registered successfully!")
            return redirect(url_for('login'))
        return render_template_string(templates["register"])

    # Add all other routes similarly...
    # (login, patient_dashboard, doctor_dashboard, nurse_dashboard)

# Function to initialize the trial app
def init_trial_app():
    setup_routes(trial_app)
    return trial_app

# This allows the main app.py to import and use this
def get_trial_app():
    return trial_app

if __name__ == "__main__":
    app = init_trial_app()
    app.run(debug=True)