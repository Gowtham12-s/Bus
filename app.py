import os
import base64
import csv
import numpy as np
import face_recognition
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Ensure required directories exist
if not os.path.exists("data/images/users"):
    os.makedirs("data/images/users")
if not os.path.exists("data/images/attendance"):
    os.makedirs("data/images/attendance")

# Database model for Users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('You need to log in first!', 'danger')
        return redirect('/login')
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', email=user.email)

@app.route('/login')
def login_page():
    if 'user_id' in session:  # If already logged in, redirect to Attendance
        flash('You are already logged in!', 'info')
        return redirect('/Attendance')
    
    return render_template('login.html')


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['txt']
    email = request.form['email']
    password = request.form['pswd']
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already registered!', 'danger')
        return redirect('/login')
    
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    flash('Account created successfully! Please login.', 'success')
    return redirect('/login')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['pswd']
    
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        flash('Login successful!', 'success')
        return redirect('/')
    else:
        flash('Invalid email or password', 'danger')
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully!', 'info')
    return redirect('/')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
