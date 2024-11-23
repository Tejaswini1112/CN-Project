# run.py
from app import app

if __name__ == '__main__':
    # For local development with HTTPS (optional)
    # app.run(ssl_context=('cert.pem', 'key.pem'))
    app.run(debug=True)
