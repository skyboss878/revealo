from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import requests
import base64
import os
import re

app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///revelo.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # PayPal Configuration
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "AQgoEsXMSG92HCurAfIz9VB6FklPn_EzCkXn0S04kzzinjRZiGrLctBv7PXGL3Gxt2DKmdp1h6a_1lDZ")
    PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
    PAYPAL_PLAN_ID = os.getenv("PAYPAL_PLAN_ID", "P-8DP70117TD556851YNA33XXA")
    PAYPAL_ENVIRONMENT = os.getenv("PAYPAL_ENVIRONMENT", "sandbox")
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Database Models
# Database Models
class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paypal_subscription_id = db.Column(db.String(50), unique=True, nullable=False)
    plan_id = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='PENDING')  # PENDING, ACTIVE, CANCELLED, SUSPENDED
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_billing_time = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "paypal_subscription_id": self.paypal_subscription_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "next_billing_time": self.next_billing_time.isoformat() if self.next_billing_time else None
        }
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "paypal_subscription_id": self.paypal_subscription_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "next_billing_time": self.next_billing_time.isoformat() if self.next_billing_time else None
        }
    
    # Relationship with subscriptions
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat(),
            'has_active_subscription': self.has_active_subscription()
        }
    
    def has_active_subscription(self):
        active_sub = Subscription.query.filter_by(
            user_id=self.id, 
            status='ACTIVE'
        ).first()
        return active_sub is not None

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paypal_subscription_id = db.Column(db.String(50), unique=True, nullable=False)
    plan_id = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='PENDING')  # PENDING, ACTIVE, CANCELLED, SUSPENDED
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_billing_time = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'paypal_subscription_id': self.paypal_subscription_id,
            'plan_id': self.plan_id,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'next_billing_time': self.next_billing_time.isoformat() if self.next_billing_time else None
        }

# PayPal API Helper Functions
class PayPalAPI:
    @staticmethod
    def get_access_token():
        """Get PayPal access token"""
        url = f"https://api-m.{'sandbox.' if app.config['PAYPAL_ENVIRONMENT'] == 'sandbox' else ''}paypal.com/v1/oauth2/token"
        
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'en_US',
            'Authorization': f'Basic {base64.b64encode(f"{app.config["PAYPAL_CLIENT_ID"]}:{app.config["PAYPAL_CLIENT_SECRET"]}".encode()).decode()}'
        }
        
        data = 'grant_type=client_credentials'
        
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            return response.json().get('access_token')
        except requests.exceptions.RequestException as e:
            print(f"PayPal API Error: {e}")
            return None
    
    @staticmethod
    def get_subscription_details(subscription_id):
        """Get subscription details from PayPal"""
        access_token = PayPalAPI.get_access_token()
        if not access_token:
            return None
p        
        url = f"https://api-m.{'sandbox.' if app.config['PAYPAL_ENVIRONMENT'] == 'sandbox' else ''}paypal.com/v1/billing/subscriptions/{subscription_id}"
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"PayPal API Error: {e}")
            return None

# Utility Functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    return len(password) >= 6

# API Routes
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user
        user = User(email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Create access token
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'Account created successfully',
            'user': user.to_dict(),
            'access_token': access_token
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Signup error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import requests
import base64
import os
import re

app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///revelo.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # PayPal Configuration
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "AQgoEsXMSG92HCurAfIz9VB6FklPn_EzCkXn0S04kzzinjRZiGrLctBv7PXGL3Gxt2DKmdp1h6a_1lDZ")
    PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
    PAYPAL_PLAN_ID = os.getenv("PAYPAL_PLAN_ID", "P-8DP70117TD556851YNA33XXA")
    PAYPAL_ENVIRONMENT = os.getenv("PAYPAL_ENVIRONMENT", "sandbox")

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Database Models

    # class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
Relationship with subscriptions
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paypal_subscription_id = db.Column(db.String(255), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.DateTime, nullable=True)
    end_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'paypal_subscription_id': self.paypal_subscription_id,
            'status': self.status,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None
        }

# Routes and logic here...

def get_paypal_access_token():
    auth = base64.b64encode(
        f"{app.config['PAYPAL_CLIENT_ID']}:{app.config['PAYPAL_CLIENT_SECRET']}".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    url = "https://api-m.paypal.com/v1/oauth2/token" if app.config['PAYPAL_ENVIRONMENT'] == "live" else "https://api-m.sandbox.paypal.com/v1/oauth2/token"

    response = requests.post(url, headers=headers, data={"grant_type": "client_credentials"})

    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        print("Failed to get PayPal access token:", response.text)
        return None

# Your existing routes and error handlers below (I assume you already have them)...

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Revelo API</title>
    </head>
    <body>
        <h1>Revelo API is running!</h1>
        <h2>Available Endpoints:</h2>
        <ul>
            <li>POST /api/signup - Create new user account</li>
            <li>POST /api/login - User login</li>
            <li>GET /api/user/profile - Get user profile (requires auth)</li>
            <li>POST /api/subscription/create - Create subscription record (requires auth)</li>
            <li>GET /api/subscription/status - Get subscription status (requires auth)</li>
            <li>POST /api/subscription/webhook - PayPal webhook handler</li>
        </ul>
        <p>Add your frontend files to connect to these endpoints.</p>
    </body>
    </html>
    """)

if __name__ == '__main__':
    app.run(debug=True)
