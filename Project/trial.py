from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
app.secret_key = "your_secret_key"
Bootstrap(app)

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
    aes_key = get_random_bytes(16)  # 128-bit AES key
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

# Templates
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
    "register": """
    {% extends "bootstrap/base.html" %}
    {% block content %}
    <div class="container mt-5">
        <h2>Register</h2>
        <form method="POST">
            <div class="form-group">
                <label for="role">Role</label>
                <select class="form-control" id="role" name="role" required>
                    <option value="patient">Patient</option>
                    <option value="doctor">Doctor</option>
                    <option value="nurse">Nurse</option>
                </select>
            </div>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
    </div>
    {% endblock %}
    """,
    "login": """
    {% extends "bootstrap/base.html" %}
    {% block content %}
    <div class="container-fluid" style="
    background-image: url('{{ url_for('static', filename='login.webp') }}'); 
    background-size: cover; 
    background-position: center; 
    height: 100vh; 
    width: 100vw; 
    display: flex; 
    justify-content: center; 
    align-items: center;
">
    <div class="p-5 bg-light rounded" style="width: 300px;">
        <h2>Login</h2>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-success w-100">Login</button>
        </form>
    </div>
</div>


    {% endblock %}
    """,
    "patient_dashboard": """
    {% extends "bootstrap/base.html" %}
    {% block content %}
        <div class="container-fluid" style="
    background-image: url('{{ url_for('static', filename='patient.webp') }}'); 
    background-size: cover; 
    background-position: center; 
    height: 100vh; 
    width: 100vw; 
    display: flex; 
    justify-content: center; 
    align-items: center;
">
    <div class="p-5 bg-light rounded" style="width: 300px;">
        <h2 style="color: #000">Patient Dashboard - ID Card</h2>
        <form method="POST">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" class="form-control" id="name" name="name" required>
            </div>
            <div class="form-group">
                <label for="insurance">Insurance Number</label>
                <input type="text" class="form-control" id="insurance" name="insurance" required>
            </div>
            <div class="form-group">
                <label for="state_id">State ID</label>
                <input type="text" class="form-control" id="state_id" name="state_id" required>
            </div>
            <div class="form-group">
                <label for="phone">Phone Number</label>
                <input type="tel" class="form-control" id="phone" name="phone" required>
            </div>
            <div class="form-group">
                <label for="specialized">Specialized Doctor</label>
                <select class="form-control" id="specialized" name="specialized" required>
                    <option value="cardiac">Cardiac</option>
                    <option value="general">General</option>
                    <option value="ortho">Orthopedic</option>
                    <option value="neuro">Neurologist</option>
                </select>
            </div>
            <div class="form-group">
                <label for="emergency">Emergency Contact</label>
                <input type="text" class="form-control" id="emergency" name="emergency" required>
            </div>
            <button type="submit" class="btn btn-primary">Save ID Card</button>
        </form>
        <h3 class="mt-4">Your Current Status: {{ status }}</h3>
    </div>
    </div>
    {% endblock %}
    """,
    "doctor_dashboard": """
    {% extends "bootstrap/base.html" %}
    {% block content %}
    <div class="container-fluid" style="
    background-image: url('{{ url_for('static', filename='doctor.webp') }}'); 
    background-size: cover; 
    background-position: center; 
    height: 100vh; 
    width: 100vw; 
    display: flex; 
    justify-content: center; 
    align-items: center;
">
    <div class="p-5 bg-light rounded" style="width: 300px;">
        <h2 style="color: #fff">Doctor Dashboard</h2>
        <ul>
            {% for patient, record in patient_records.items() %}
            <li>
                <strong>{{ patient }}</strong> - 
                Status: 
                <span class="badge badge-success" style="background-color: {{ 'green' if record['status'] == 'Normal' else 'red' }}">{{ record['status'] }}</span>
                - {{ record['comments'] }}
            </li>
            {% endfor %}
        </ul>
        <form method="POST">
            <div class="form-group">
                <label for="patient">Select Patient</label>
                <input type="text" class="form-control" id="patient" name="patient" required>
            </div>
            <div class="form-group">
                <label for="status">Update Status</label>
                <select class="form-control" id="status" name="status" required>
                    <option value="Normal">Normal</option>
                    <option value="Critical">Critical</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">Update Status</button>
        </form>
    </div>
    </div>  
    {% endblock %}
    """,
    "nurse_dashboard": """
    {% extends "bootstrap/base.html" %}
    {% block content %}
            <div class="container-fluid" style="
    background-image: url('{{ url_for('static', filename='nurse.webp') }}'); 
    background-size: cover; 
    background-position: center; 
    height: 100vh; 
    width: 100vw; 
    display: flex; 
    justify-content: center; 
    align-items: center;
">
    <div class="p-5 bg-light rounded" style="width: 300px;">
        <h2 style="color:#000">Nurse Dashboard</h2>
        <h4>Contact Patients</h4>
        <ul>
            {% for patient, record in patient_records.items() %}
            <li>{{ patient }} - Phone: {{ record['phone'] }}</li>
            {% endfor %}
        </ul>
        <form method="POST">
            <div class="form-group">
                <label for="patient">Select Patient</label>
                <input type="text" class="form-control" id="patient" name="patient" required>
            </div>
            <div class="form-group">
                <label for="message">Message</label>
                <textarea class="form-control" id="message" name="message" required></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Send Message</button>
        </form>
    </div>
    </div>
    {% endblock %}
    """,
}

@app.route('/')
def index():
    return render_template_string(templates["index"])

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form['role']
        username = request.form['username']
        password = request.form['password']
        
        # Encrypt password
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

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verify login
        role = None
        for user_role, user_dict in {'patient': patients, 'doctor': doctors, 'nurse': nurses}.items():
            if username in user_dict:
                role = user_role
                encrypted_password = user_dict[username]['password']
                decrypted_password = decrypt_data(*encrypted_password)
                if decrypted_password == password:
                    flash(f"Welcome, {username}!")
                    if role == 'patient':
                        return redirect(url_for('patient_dashboard', username=username))
                    elif role == 'doctor':
                        return redirect(url_for('doctor_dashboard', username=username))
                    elif role == 'nurse':
                        return redirect(url_for('nurse_dashboard', username=username))
                else:
                    flash("Incorrect password!")
                    return redirect(url_for('login'))
        
        flash("User not found!")
        return redirect(url_for('login'))
    return render_template_string(templates["login"])

# Patient Dashboard Route
@app.route('/patient_dashboard/<username>', methods=['GET', 'POST'])
def patient_dashboard(username):
    if username not in patients:
        flash("Patient not found!")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Save patient ID card data
        name = request.form['name']
        insurance = request.form['insurance']
        state_id = request.form['state_id']
        phone = request.form['phone']
        specialized = request.form['specialized']
        emergency = request.form['emergency']
        
        patients[username]['records'] = {
            'name': name,
            'insurance': insurance,
            'state_id': state_id,
            'phone': phone,
            'specialized': specialized,
            'emergency': emergency,
            'status': 'Normal'
        }
        flash("Patient ID card updated successfully!")
    
    record = patients[username]['records']
    status = record.get('status', 'No status available')
    return render_template_string(templates["patient_dashboard"], status=status)

# Doctor Dashboard Route
@app.route('/doctor_dashboard/<username>', methods=['GET', 'POST'])
def doctor_dashboard(username):
    if username not in doctors:
        flash("Doctor not found!")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Update patient status
        patient_username = request.form['patient']
        status = request.form['status']
        
        if patient_username in patients:
            patients[patient_username]['records']['status'] = status
            flash(f"Updated status for {patient_username} to {status}!")
        else:
            flash("Patient not found!")
    
    return render_template_string(templates["doctor_dashboard"], patient_records=patients)

# Nurse Dashboard Route
@app.route('/nurse_dashboard/<username>', methods=['GET', 'POST'])
def nurse_dashboard(username):
    if username not in nurses:
        flash("Nurse not found!")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Send message to patient
        patient_username = request.form['patient']
        message = request.form['message']
        
        if patient_username in patients:
            flash(f"Message sent to {patient_username}: {message}")
        else:
            flash("Patient not found!")
    
    return render_template_string(templates["nurse_dashboard"], patient_records=patients)

# Run the Flask application
if __name__ == "__main__":
    app.run(debug=True)