from dot.env import load_dotenv import os
# load enviorment variables from .env file load_dotenv()
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


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_active": self.is_active
        }


# PayPal API Helper Functions
def get_paypal_access_token():
    """Get PayPal access token for API calls"""
    url = f"https://api-m.{app.config['PAYPAL_ENVIRONMENT']}.paypal.com/v1/oauth2/token"
    
    headers = {
        "Accept": "application/json",
        "Accept-Language": "en_US",
    }
    
    # Create basic auth header
    client_id = app.config['PAYPAL_CLIENT_ID']
    client_secret = app.config['PAYPAL_CLIENT_SECRET']
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers["Authorization"] = f"Basic {credentials}"
    
    data = "grant_type=client_credentials"
    
    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        raise Exception(f"Failed to get PayPal access token: {response.text}")


def create_paypal_subscription(plan_id, return_url, cancel_url):
    """Create a PayPal subscription"""
    access_token = get_paypal_access_token()
    
    url = f"https://api-m.{app.config['PAYPAL_ENVIRONMENT']}.paypal.com/v1/billing/subscriptions"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "PayPal-Request-Id": f"SUBSCRIPTION-{datetime.utcnow().timestamp()}",
        "Prefer": "return=representation"
    }
    
    payload = {
        "plan_id": plan_id,
        "start_time": (datetime.utcnow() + timedelta(minutes=1)).isoformat() + "Z",
        "quantity": "1",
        "shipping_amount": {
            "currency_code": "USD",
            "value": "0.00"
        },
        "subscriber": {
            "name": {
                "given_name": "John",
                "surname": "Doe"
            },
            "email_address": "customer@example.com"
        },
        "application_context": {
            "brand_name": "Revelo Premium",
            "locale": "en-US",
            "shipping_preference": "NO_SHIPPING",
            "user_action": "SUBSCRIBE_NOW",
            "payment_method": {
                "payer_selected": "PAYPAL",
                "payee_preferred": "IMMEDIATE_PAYMENT_REQUIRED"
            },
            "return_url": return_url,
            "cancel_url": cancel_url
        }
    }
    
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code in [200, 201]:
        return response.json()
    else:
        raise Exception(f"Failed to create PayPal subscription: {response.text}")


# Routes
@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Revelo Premium Subscription</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .btn { background: #0070ba; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 16px; }
            .btn:hover { background: #005ea6; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            .alert { padding: 15px; margin-bottom: 20px; border-radius: 5px; }
            .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Revelo Premium Subscription</h1>
            <p>Subscribe to Revelo Premium for advanced features and unlimited access.</p>
            
            <div id="auth-section">
                <h2>Login or Register</h2>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" required>
                </div>
                <button class="btn" onclick="login()">Login</button>
                <button class="btn" onclick="register()">Register</button>
            </div>
            
            <div id="subscription-section" style="display: none;">
                <h2>Subscribe to Premium</h2>
                <p>Monthly Premium Plan - $9.99/month</p>
                <button class="btn" onclick="createSubscription()">Subscribe with PayPal</button>
            </div>
            
            <div id="status-section" style="display: none;">
                <h2>Subscription Status</h2>
                <div id="subscription-info"></div>
            </div>
        </div>

        <script>
            let currentUser = null;
            let authToken = null;

            async function login() {
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    
                    const data = await response.json();
                    if (response.ok) {
                        authToken = data.access_token;
                        currentUser = data.user;
                        showSubscriptionSection();
                        checkSubscriptionStatus();
                    } else {
                        alert('Login failed: ' + data.message);
                    }
                } catch (error) {
                    alert('Login error: ' + error.message);
                }
            }

            async function register() {
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    
                    const data = await response.json();
                    if (response.ok) {
                        alert('Registration successful! Please login.');
                    } else {
                        alert('Registration failed: ' + data.message);
                    }
                } catch (error) {
                    alert('Registration error: ' + error.message);
                }
            }

            async function createSubscription() {
                try {
                    const response = await fetch('/api/create-subscription', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        }
                    });
                    
                    const data = await response.json();
                    if (response.ok) {
                        // Redirect to PayPal for approval
                        const approvalUrl = data.approval_url;
                        window.location.href = approvalUrl;
                    } else {
                        alert('Subscription creation failed: ' + data.message);
                    }
                } catch (error) {
                    alert('Subscription error: ' + error.message);
                }
            }

            async function checkSubscriptionStatus() {
                try {
                    const response = await fetch('/api/subscription-status', {
                        headers: { 'Authorization': 'Bearer ' + authToken }
                    });
                    
                    const data = await response.json();
                    if (response.ok && data.subscription) {
                        document.getElementById('subscription-info').innerHTML = `
                            <p><strong>Status:</strong> ${data.subscription.status}</p>
                            <p><strong>Plan:</strong> ${data.subscription.plan_id}</p>
                            <p><strong>Next Billing:</strong> ${data.subscription.next_billing_time || 'N/A'}</p>
                        `;
                        document.getElementById('status-section').style.display = 'block';
                    }
                } catch (error) {
                    console.error('Status check error:', error);
                }
            }

            function showSubscriptionSection() {
                document.getElementById('auth-section').style.display = 'none';
                document.getElementById('subscription-section').style.display = 'block';
            }
        </script>
    </body>
    </html>
    """)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 400
    
    # Create new user
    user = User(email=email)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/create-subscription', methods=['POST'])
@jwt_required()
def create_subscription():
    user_id = get_jwt_identity()
    
    try:
        # Create PayPal subscription
        return_url = request.host_url + 'api/subscription-success'
        cancel_url = request.host_url + 'api/subscription-cancel'
        
        paypal_subscription = create_paypal_subscription(
            app.config['PAYPAL_PLAN_ID'],
            return_url,
            cancel_url
        )
        
        # Save subscription to database
        subscription = Subscription(
            user_id=user_id,
            paypal_subscription_id=paypal_subscription['id'],
            plan_id=app.config['PAYPAL_PLAN_ID'],
            status='PENDING'
        )
        
        db.session.add(subscription)
        db.session.commit()
        
        # Find approval URL
        approval_url = None
        for link in paypal_subscription['links']:
            if link['rel'] == 'approve':
                approval_url = link['href']
                break
        
        return jsonify({
            'subscription_id': paypal_subscription['id'],
            'approval_url': approval_url
        }), 201
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/api/subscription-success')
def subscription_success():
    subscription_id = request.args.get('subscription_id')
    
    if subscription_id:
        # Update subscription status
        subscription = Subscription.query.filter_by(paypal_subscription_id=subscription_id).first()
        if subscription:
            subscription.status = 'ACTIVE'
            db.session.commit()
    
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Subscription Successful</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; text-align: center; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success">✓ Subscription Successful!</div>
            <p>Your subscription has been activated successfully.</p>
            <a href="/">Return to Dashboard</a>
        </div>
    </body>
    </html>
    """)


@app.route('/api/subscription-cancel')
def subscription_cancel():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Subscription Cancelled</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; text-align: center; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .cancel { color: #dc3545; font-size: 24px; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="cancel">✗ Subscription Cancelled</div>
            <p>You cancelled the subscription process.</p>
            <a href="/">Return to Dashboard</a>
        </div>
    </body>
    </html>
    """)


@app.route('/api/subscription-status')
@jwt_required()
def subscription_status():
    user_id = get_jwt_identity()
    subscription = Subscription.query.filter_by(user_id=user_id).first()
    
    if subscription:
        return jsonify({'subscription': subscription.to_dict()}), 200
    else:
        return jsonify({'subscription': None}), 200


# Webhook endpoint for PayPal notifications
@app.route('/api/paypal-webhook', methods=['POST'])
def paypal_webhook():
    try:
        # This is a simplified webhook handler
        # In production, you should verify the webhook signature
        data = request.get_json()
        
        event_type = data.get('event_type')
        resource = data.get('resource', {})
        
        if event_type == 'BILLING.SUBSCRIPTION.ACTIVATED':
            subscription_id = resource.get('id')
            subscription = Subscription.query.filter_by(paypal_subscription_id=subscription_id).first()
            if subscription:
                subscription.status = 'ACTIVE'
                subscription.next_billing_time = datetime.fromisoformat(resource.get('billing_info', {}).get('next_billing_time', '').replace('Z', '+00:00'))
                db.session.commit()
        
        elif event_type == 'BILLING.SUBSCRIPTION.CANCELLED':
            subscription_id = resource.get('id')
            subscription = Subscription.query.filter_by(paypal_subscription_id=subscription_id).first()
            if subscription:
                subscription.status = 'CANCELLED'
                db.session.commit()
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
