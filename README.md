## Loan Management System
## Overview
This is a simple Flask application for managing loans. The system allows users to register, request loans, view their loans, and make repayments. Admins can register, log in, view all loans, and approve loan requests.

## Features
## User Registration:
Endpoint: /register
Allows users to register with a unique email.

## Admin Registration:
Endpoint: /admin_register
Allows admins to register with a unique email.

## User Login:
Endpoint: /login
Generates a JWT token upon successful login for authentication.

## Admin Login:
Endpoint: /admin_login
Generates a JWT token upon successful admin login for authentication.

## Loan Request:
Endpoint: /loan_request
Registered users can request a loan.

## View Loans:
Endpoint: /view_loans
Allows both users and admins to view loans.

## Approve Loan (Admin Only):
Endpoint: /approve_loan/<int:loan_id>
Allows admins to approve a pending loan.

## Add Repayment (User Only):
Endpoint: /add_repayment/<int:loan_id>
Allows users to add a repayment for an approved loan.

## Dependencies
Flask
Flask-SQLAlchemy
Flask-CORS
Flask-JWT-Extended

## Database
SQLite is used for the database.
Tables are created on application startup in instance directory.

## Authentication
JSON Web Tokens (JWT) are used for authentication and authorization.
Tokens are generated upon successful login and are required for accessing protected endpoints.

## Notes
This is a basic implementation and may require additional security measures for production use.
Ensure the secure storage and handling of secret keys.
Adjust expiration times in token generation based on your requirements.

## Getting Started

1. **Set up a Virtual Environment:-**
    - Create a virtual environment named `venv` using the command:- `python -m venv venv`.
    - Activate the virtual environment by running:- `venv\Scripts\activate`.
    - On macOS/Linux:- source `venv/bin/activate`

2. **Install Required Python Packages:-**
    - Install the necessary Python packages using pip. You can install all the required 
    - packages from the provided requirements.txt file:
    - `pip install -r requirements.txt`

3. **Configure File:-**
    Database URI: sqlite:///testingdb.db
    Secret Key: your_secret_key (Replace with a secure, randomly generated key in production).

  # Configure your database connection URL

    ## Sqlite Configuration
      app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///testingdb.db'
      app.config['SECRET_KEY'] = 'your_secret_key'

    ## MYSQL Configuration
    <!-- - app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/dbname'
      first create database on mysql and put the dbname on app.config -->

4. **Run the FlaskAPI Server**
 Start the FlaskAPI server using Uvicorn. You can use one of the following commands:
  1. For development with automatic reload:   
     flask run --reload

5. **API Documentation**
   For detailed information about each endpoint, request parameters, and responses, please refer to the Postman API documentation. You can find the complete API documentation in the provided Postman doc file.
    

 These instructions should help you set up and run your FlaskAPI project with the required dependencies. 
 Make sure to follow each step carefully, 
 and ensure that your virtual environment is activated while working on the project.




