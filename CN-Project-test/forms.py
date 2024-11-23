# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DecimalField, IntegerField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, NumberRange
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role_name = SelectField('Role', choices=[('patient', 'Patient'), ('nurse', 'Nurse'), ('doctor', 'Doctor')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    # Custom validation to check if username or email already exists
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already registered.')

class LoginForm(FlaskForm):
    email_or_username = StringField('Email or Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PatientProfileForm(FlaskForm):
    address = StringField('Address', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=0)])
    height = DecimalField('Height (cm)', validators=[DataRequired(), NumberRange(min=0)])
    weight = DecimalField('Weight (kg)', validators=[DataRequired(), NumberRange(min=0)])
    sex = SelectField('Sex', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    submit = SubmitField('Update Profile')

class HealthDataForm(FlaskForm):
    file = FileField('Upload Health File', validators=[DataRequired()])
    symptoms = TextAreaField('Symptoms/Sickness', validators=[DataRequired()])
    submit = SubmitField('Submit Health Data')

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')

class PrescriptionForm(FlaskForm):
    prescription = TextAreaField('Prescription', validators=[DataRequired()])
    submit = SubmitField('Add Prescription')

class SearchForm(FlaskForm):
    search_query = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')
