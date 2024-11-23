# decorators.py
from flask import abort
from flask_login import current_user
from functools import wraps

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role_name != role:
                abort(403)  # Forbidden access
            return f(*args, **kwargs)
        return decorated_function
    return decorator
