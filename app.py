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
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Create access token
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/subscription/webhook', methods=['POST'])
def paypal_webhook():
    """Handle PayPal webhook notifications"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        event_type = data.get('event_type')
        resource = data.get('resource', {})
        
        if event_type == 'BILLING.SUBSCRIPTION.ACTIVATED':
            subscription_id = resource.get('id')
            plan_id = resource.get('plan_id')
            
            # Find subscription in our database
            subscription = Subscription.query.filter_by(
                paypal_subscription_id=subscription_id
            ).first()
            
            if subscription:
                subscription.status = 'ACTIVE'
                subscription.updated_at = datetime.utcnow()
                
                # Update next billing time if provided
                if 'billing_info' in resource and 'next_billing_time' in resource['billing_info']:
                    subscription.next_billing_time = datetime.fromisoformat(
                        resource['billing_info']['next_billing_time'].replace('Z', '+00:00')
                    )
                
                db.session.commit()
        
        elif event_type == 'BILLING.SUBSCRIPTION.CANCELLED':
            subscription_id = resource.get('id')
            
            subscription = Subscription.query.filter_by(
                paypal_subscription_id=subscription_id
            ).first()
            
            if subscription:
                subscription.status = 'CANCELLED'
                subscription.updated_at = datetime.utcnow()
                db.session.commit()
        
        return jsonify({'message': 'Webhook processed'}), 200
        
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500

@app.route('/api/subscription/create', methods=['POST'])
@jwt_required()
def create_subscription():
    """Create a subscription record after PayPal approval"""
    try:
        data = request.get_json()
        user_id = get_jwt_identity()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        subscription_id = data.get('subscription_id')
        
        if not subscription_id:
            return jsonify({'error': 'Subscription ID is required'}), 400
        
        # Verify subscription with PayPal
        paypal_data = PayPalAPI.get_subscription_details(subscription_id)
        
        if not paypal_data:
            return jsonify({'error': 'Failed to verify subscription with PayPal'}), 400
        
        # Check if subscription already exists
        existing_sub = Subscription.query.filter_by(
            paypal_subscription_id=subscription_id
        ).first()
        
        if existing_sub:
            return jsonify({'error': 'Subscription already exists'}), 409
        
        # Create subscription record
        subscription = Subscription(
            user_id=user_id,
            paypal_subscription_id=subscription_id,
            plan_id=paypal_data.get('plan_id', app.config['PAYPAL_PLAN_ID']),
            status=paypal_data.get('status', 'PENDING')
        )
        
        db.session.add(subscription)
        db.session.commit()
        
        return jsonify({
            'message': 'Subscription created successfully',
            'subscription': subscription.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Create subscription error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get user profile information"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': user.to_dict(),
            'subscriptions': [sub.to_dict() for sub in user.subscriptions]
        }), 200
        
    except Exception as e:
        print(f"Get profile error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/subscription/status', methods=['GET'])
@jwt_required()
def get_subscription_status():
    """Get user's subscription status"""
    try:
        user_id = get_jwt_identity()
        
        active_subscription = Subscription.query.filter_by(
            user_id=user_id,
            status='ACTIVE'
        ).first()
        
        if active_subscription:
            return jsonify({
                'has_subscription': True,
                'subscription': active_subscription.to_dict()
            }), 200
        else:
            return jsonify({
                'has_subscription': False,
                'subscription': None
            }), 200
            
    except Exception as e:
        print(f"Get subscription status error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authentication token required'}), 401

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()

# Development route to serve the frontend (remove in production)
@app.route('/')
def index():
    # In production, serve this from a proper web server
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
