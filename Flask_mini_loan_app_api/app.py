from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///testingdb.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

db = SQLAlchemy(app)
CORS(app)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    loans = db.relationship('Loan', backref='user', lazy=True)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))


class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    term = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    repayments = db.relationship('Repayment', backref='loan', lazy=True)


class Repayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')


# Create the database tables within an application context
with app.app_context():
    db.create_all()


# Helper function to schedule repayments for a loan
def schedule_repayments(loan):
    today = datetime.utcnow().date()
    for i in range(1, loan.term + 1):
        
        due_date = today + timedelta(weeks=i)
        repayment = Repayment(amount=loan.amount / loan.term, due_date=due_date, loan_id=loan.id)
        db.session.add(repayment)
    db.session.commit()


# Routes

# User Registration
@app.route('/register', methods=['POST'])
def register():
    """
    User registration endpoint.
    """
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Check if the email already exists
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"message": "Email already registered"}), 400

    # Create a new user
    new_user = User(name=name, email=email, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Registration successful"})


# Admin Registration
@app.route('/admin_register', methods=['POST'])
def admin_register():
    """
    Admin registration endpoint.
    """
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Check if the email already exists
    admin = Admin.query.filter_by(email=email).first()
    if admin:
        return jsonify({"message": "Email already registered"}), 400

    # Create a new admin user
    new_admin = Admin(name=name, email=email, password=generate_password_hash(password))
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({"message": "Admin registration successful"})


# User Login
@app.route('/login', methods=['POST'])
def login():
    """
    User login endpoint.
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # Generate a JWT token with the user's email and an expiration time
        expiration_time = datetime.utcnow() + timedelta(minutes=60)  # You can adjust the expiration time as needed
        token_payload = {'email': email, 'exp': expiration_time}
        jwt_token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

        # Include the JWT token in the login response
        response_data = {
            "message": "Login successful",
            "token": jwt_token  # Include the token in the response
        }
        return jsonify(response_data)

    return jsonify({"message": "Invalid credentials"}), 401


# Admin Login
@app.route('/admin_login', methods=['POST'])
def admin_login():
    """
    Admin login endpoint.
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Find the admin by email
    admin = Admin.query.filter_by(email=email).first()
    if not admin or not check_password_hash(admin.password, password):
        return jsonify({"message": "Invalid email or password"}), 401

    # Generate a JWT token for admin
    expiration_time = datetime.utcnow() + timedelta(days=1)  # You can adjust the expiration time
    token_payload = {'email': email, 'is_admin': True, 'exp': expiration_time}
    jwt_token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

    # Include the JWT token in the login response
    response_data = {
        "message": "Admin login successful",
        "token": jwt_token
    }

    return jsonify(response_data)


# Loan Request
@app.route('/loan_request', methods=['POST'])
def loan_request():
    """
    Loan Request endpoint.
    """
    # Check for the authorization token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401 

    try:
        # Verify and decode the JWT token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print("payload", payload)
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Check if the user email in the JWT payload matches the requested user's email
    authenticated_user_email = payload.get('email')  # Update the key based on your payload
    print("authenticated_user_email", authenticated_user_email)

    # Try to get the user by email
    user = User.query.filter_by(email=authenticated_user_email).first()

    if not user:
        return jsonify({"message": "User does not exist"}), 404

    # Access the user's ID
    user_id = user.id
    print("User ID:", user_id)

    # Validate loan request data
    data = request.get_json()
    if not all(key in data for key in ['amount', 'term']):
        return jsonify({"message": "Invalid loan request data"}), 400

    amount = data['amount']
    term = data['term']

    # Additional validation: Ensure that the term is not more than 3
    if not 1 <= term <= 3:
        return jsonify({"message": "Invalid term. Term should be between 1 and 3"}), 400

    # Create a new loan request
    new_loan = Loan(amount=amount, term=term, user_id=user_id)
    db.session.add(new_loan)
    db.session.commit()

    # Schedule repayments
    schedule_repayments(new_loan)

    return jsonify({"message": "Loan request submitted successfully"})


# Customer and Admin View Loans
@app.route('/view_loans', methods=['GET'])
def view_loans():
    """
    Customer and Admin View Loans endpoint.
    """
    # Check for the authorization token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401 

    try:
        # Verify and decode the JWT token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print("payload" , payload)
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Check if the user is an admin
    is_admin = payload.get('is_admin', False)

    if is_admin:
        # Admin view: Retrieve all loans
        loans = Loan.query.all()
    else:
        # User view: Retrieve loans belonging to the user
        authenticated_user_email = payload['email']
        user = User.query.filter_by(email=authenticated_user_email).first()

        if not user:
            return jsonify({"message": "User does not exist"}), 404

        loans = Loan.query.filter_by(user_id=user.id).all()

    # Format the response data
    loan_data = [
        {
            "id": loan.id,
            "amount": loan.amount,
            "term": loan.term,
            "status": loan.status,
            "repayments": [
                {
                    "id": repayment.id,
                    "amount": repayment.amount,
                    "due_date": repayment.due_date.strftime('%Y-%m-%d'),
                    "status": repayment.status
                }
                for repayment in loan.repayments
            ]
        }
        for loan in loans
    ]

    return jsonify({"loans": loan_data})


# Admin Approve Loan
@app.route('/approve_loan/<int:loan_id>', methods=['PUT'])
def approve_loan(loan_id):
    """
    Admin Approve Loan endpoint.
    """
    # Check if the loan exists and is in 'pending' status
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401 

    try:
        # Verify and decode the JWT token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print("payload" , payload)
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

    # Check if the user email in the JWT payload matches the requested user's email
    authenticated_user_email = payload['email']
    print("authenticated_user_email" , authenticated_user_email)


    # Try to get the user by email
    admin_qry = Admin.query.filter_by(email=authenticated_user_email).first()

    if not admin_qry:
        return jsonify({"message": "admin does not exist"}), 404

    # # Access the user's ID
    # user_id = user.id
    # print("User ID:", user_id)   

    else:
        loan = Loan.query.get(loan_id)
        if not loan or loan.status != 'pending':
            return jsonify({"message": "Invalid loan or loan is not in pending status"}), 400

        # Approve the loan
        loan.status = 'approved'
        db.session.commit()

        return jsonify({"message": "Loan approved successfully"})    


# Customer Add Repayment
@app.route('/add_repayment/<int:loan_id>', methods=['POST'])
def add_repayment(loan_id):
    data = request.get_json()
    amount_paid = data.get('amount_paid')

    # Check if the loan exists and is in 'approved' status
    loan = Loan.query.get(loan_id)
    if not loan or loan.status != 'approved':
        return jsonify({"message": "Invalid loan or loan is not in approved status"}), 400

    # Check if the repayment amount is greater than or equal to the scheduled repayment
    next_repayment = Repayment.query.filter_by(loan_id=loan.id, status='pending').order_by(Repayment.due_date).first()
    if not next_repayment or amount_paid < next_repayment.amount:
        return jsonify({"message": "Invalid repayment amount"}), 400

    # Mark the scheduled repayment as paid
    next_repayment.status = 'paid'

    # Check if all repayments are completed, mark the loan as paid
    if all(repayment.status == 'paid' for repayment in loan.repayments):
        loan.status = 'paid'

    db.session.commit()

    return jsonify({"message": "Repayment added successfully"})


# Run the application
if __name__ == '__main__':
    app.run(debug=True)

