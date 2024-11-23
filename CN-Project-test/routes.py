# routes.py
from app import app, db, bcrypt
from flask import render_template, redirect, url_for, flash, request, abort, send_from_directory
from forms import RegistrationForm, LoginForm, PatientProfileForm, HealthDataForm, CommentForm, PrescriptionForm, SearchForm
from models import User, Patient, HealthData, Comment, Prescription
from flask_login import login_user, logout_user, login_required, current_user
from decorators import role_required
from utils import encrypt_data, decrypt_data
from werkzeug.utils import secure_filename
import os

def allowed_file(filename):
    allowed_extensions = {'pdf', 'png', 'jpg', 'jpeg'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role_name=form.role_name.data
        )
        db.session.add(user)
        db.session.commit()
        # If the user is a patient, create a Patient record
        if user.role_name == 'patient':
            patient = Patient(user_id=user.id)
            db.session.add(patient)
            db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        # Allow login with either email or username
        user = User.query.filter(
            (User.email == form.email_or_username.data) | (User.username == form.email_or_username.data)
        ).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your credentials.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role_name == 'patient':
        return redirect(url_for('patient_dashboard'))
    elif current_user.role_name == 'nurse':
        return redirect(url_for('nurse_dashboard'))
    elif current_user.role_name == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    else:
        abort(403)

# Patient Routes
@app.route('/patient_dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    return render_template('patient_dashboard.html')

@app.route('/patient/profile', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def patient_profile():
    patient = Patient.query.get(current_user.id)
    form = PatientProfileForm()

    if form.validate_on_submit():
        # Encrypt the address before saving (ensure it's binary)
        encrypted_address = encrypt_data(form.address.data)  # Encrypt as bytes
        patient.address = encrypted_address  # Save encrypted binary data
        patient.age = form.age.data
        patient.height = form.height.data
        patient.weight = form.weight.data
        patient.sex = form.sex.data
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('patient_profile'))
    elif request.method == 'GET':
        # Decrypt the address for display if it exists
        if patient.address:
            decrypted_address = decrypt_data(patient.address)  # Decrypt binary to string
            form.address.data = decrypted_address
        form.age.data = patient.age
        form.height.data = patient.height
        form.weight.data = patient.weight
        form.sex.data = patient.sex

    return render_template('patient_profile.html', patient=patient, form=form)

@app.route('/patient/submit_health_data', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def submit_health_data():
    form = HealthDataForm()
    if form.validate_on_submit():
        file = form.file.data
        symptoms = form.symptoms.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{current_user.id}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            # Save to database
            health_data = HealthData(
                patient_id=current_user.id,
                file_path=unique_filename,
                symptoms=symptoms
            )
            db.session.add(health_data)
            db.session.commit()
            flash('Health data submitted successfully.', 'success')
            return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid file type.', 'danger')
    return render_template('submit_health_data.html', form=form)

@app.route('/patient/prescriptions')
@login_required
@role_required('patient')
def view_prescriptions():
    prescriptions = Prescription.query.filter_by(patient_id=current_user.id).all()
    return render_template('patient_prescriptions.html', prescriptions=prescriptions)

@app.route('/patient/nurse_comments')
@login_required
@role_required('patient')
def view_nurse_comments():
    comments = Comment.query.filter_by(patient_id=current_user.id, role='nurse').all()
    return render_template('patient_nurse_comments.html', comments=comments)

@app.route('/uploads/<filename>')
@login_required
@role_required('patient')
def uploaded_file(filename):
    # Ensure the file belongs to the current user
    health_data = HealthData.query.filter_by(patient_id=current_user.id, file_path=filename).first()
    if health_data:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        abort(403)

# Doctor Routes
@app.route('/doctor_dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    return render_template('doctor_dashboard.html')

@app.route('/doctor/search_patients', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def search_patients():
    form = SearchForm()
    patients = []
    if form.validate_on_submit():
        search_query = form.search_query.data
        patients = User.query.filter(
            (User.role_name == 'patient') &
            ((User.username.contains(search_query)) | (User.email.contains(search_query)))
        ).all()
    return render_template('doctor_search_patients.html', patients=patients, form=form)

@app.route('/doctor/view_patient/<int:patient_id>')
@login_required
@role_required('doctor')
def doctor_view_patient(patient_id):
    patient = Patient.query.get(patient_id)
    if not patient:
        abort(404)
    user = User.query.get(patient.user_id)
    health_data = HealthData.query.filter_by(patient_id=patient_id).all()
    # Exclude address from patient data
    patient_data = {
        'age': patient.age,
        'height': patient.height,
        'weight': patient.weight,
        'sex': patient.sex
    }
    comments = Comment.query.filter_by(patient_id=patient_id, role='doctor').all()
    prescriptions = Prescription.query.filter_by(patient_id=patient_id).all()
    return render_template('doctor_view_patient.html', user=user, patient_data=patient_data, health_data=health_data, comments=comments, prescriptions=prescriptions)

@app.route('/doctor/add_comment/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def doctor_add_comment(patient_id):
    form = CommentForm()
    if form.validate_on_submit():
        comment_text = form.comment.data
        comment = Comment(
            patient_id=patient_id,
            author_id=current_user.id,
            comment=comment_text,
            role='doctor'
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
        return redirect(url_for('doctor_view_patient', patient_id=patient_id))
    return render_template('doctor_add_comment.html', patient_id=patient_id, form=form)

@app.route('/doctor/add_prescription/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def doctor_add_prescription(patient_id):
    form = PrescriptionForm()
    if form.validate_on_submit():
        prescription_text = form.prescription.data
        prescription = Prescription(
            patient_id=patient_id,
            doctor_id=current_user.id,
            prescription=prescription_text
        )
        db.session.add(prescription)
        db.session.commit()
        flash('Prescription added successfully.', 'success')
        return redirect(url_for('doctor_view_patient', patient_id=patient_id))
    return render_template('doctor_add_prescription.html', patient_id=patient_id, form=form)

# Nurse Routes
@app.route('/nurse_dashboard')
@login_required
@role_required('nurse')
def nurse_dashboard():
    return render_template('nurse_dashboard.html')

@app.route('/nurse/search_patients', methods=['GET', 'POST'])
@login_required
@role_required('nurse')
def nurse_search_patients():
    form = SearchForm()
    patients = []
    if form.validate_on_submit():
        search_query = form.search_query.data
        patients = User.query.filter(
            (User.role_name == 'patient') &
            ((User.username.contains(search_query)) | (User.email.contains(search_query)))
        ).all()
    return render_template('nurse_search_patients.html', patients=patients, form=form)

@app.route('/nurse/view_patient/<int:patient_id>')
@login_required
@role_required('nurse')
def nurse_view_patient(patient_id):
    patient = db.session.query(Patient).autoflush(False).get(patient_id)
    if not patient:
        abort(404)
    user = db.session.query(User).autoflush(False).get(patient.user_id)

    # Decrypt the address for display if it exists
    decrypted_address = decrypt_data(patient.address) if patient.address else None

    comments = db.session.query(Comment).autoflush(False).filter_by(patient_id=patient_id).all()
    prescriptions = db.session.query(Prescription).autoflush(False).filter_by(patient_id=patient_id).all()

    return render_template(
        'nurse_view_patient.html',
        user=user,
        patient=patient,
        comments=comments,
        prescriptions=prescriptions,
        decrypted_address=decrypted_address
    )

@app.route('/nurse/add_comment/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('nurse')
def nurse_add_comment(patient_id):
    form = CommentForm()
    if form.validate_on_submit():
        comment_text = form.comment.data
        comment = Comment(
            patient_id=patient_id,
            author_id=current_user.id,
            comment=comment_text,
            role='nurse'
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
        return redirect(url_for('nurse_view_patient', patient_id=patient_id))
    return render_template('nurse_add_comment.html', patient_id=patient_id, form=form)

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404
