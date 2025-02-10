import os
import base64
import csv
import numpy as np
import face_recognition
import cv2
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, flash, jsonify, Response, url_for
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

# Load face recognition data
path = 'images'
images = []
classNames = []
if os.path.exists(path):
    myList = os.listdir(path)
    for cl in myList:
        curImg = cv2.imread(f'{path}/{cl}')
        images.append(curImg)
        classNames.append(os.path.splitext(cl)[0])
print("Students:", classNames)

def findEncodings(images):
    encodeList = []
    for img in images:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        encode = face_recognition.face_encodings(img)[0]
        encodeList.append(encode)
    return encodeList

def markAttendance(name):
    with open('Attendance.csv', 'a+') as f:
        f.seek(0)
        myDataList = f.readlines()
        nameList = [line.split(',')[0] for line in myDataList]
        if name not in nameList:
            now = datetime.now()
            dateString = now.strftime('%Y-%m-%d')
            timeString = now.strftime('%H:%M:%S')
            f.writelines(f'\n{name},{dateString},{timeString}')

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/hi')
def hi():
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
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

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully!', 'info')
    return redirect('/')

# Face recognition camera
stop_stream = False  # Global flag to control streaming

def generate_frames():
    global stop_stream
    cap = cv2.VideoCapture(0)
    encodeListKnown = findEncodings(images)
    print('Training Complete..')
    while True:
        success, img = cap.read()
        if not success or stop_stream:
            break
        imgS = cv2.resize(img, (0, 0), None, 0.25, 0.25)
        imgS = cv2.cvtColor(imgS, cv2.COLOR_BGR2RGB)
        facesCurFrame = face_recognition.face_locations(imgS)
        encodesCurFrame = face_recognition.face_encodings(imgS, facesCurFrame)
        for encodeFace, faceLoc in zip(encodesCurFrame, facesCurFrame):
            matches = face_recognition.compare_faces(encodeListKnown, encodeFace)
            faceDis = face_recognition.face_distance(encodeListKnown, encodeFace)
            matchIndex = np.argmin(faceDis)
            if matches[matchIndex]:
                name = classNames[matchIndex].upper()
                markAttendance(name)
                stop_stream = True
                cap.release()
                return
        ret, buffer = cv2.imencode('.jpg', img)
        frame = buffer.tobytes()
        yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    cap.release()

@app.route('/start_camera')
def start_camera():
    return render_template('camera.html')

@app.route('/video')
def video():
    global stop_stream
    stop_stream = False
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/check_status')
def check_status():
    global stop_stream
    return jsonify({"stop": stop_stream})

@app.route('/emp')
def emp():
    return render_template('emp.html')

@app.route('/businfo')
def businfo():
    return render_template('bus_info.html')

@app.route('/track')
def track():
    bus_name = request.args.get('bus')
    print('bus name :', bus_name)
    source = request.args.get('source')
    stop1 = request.args.get('stop1')
    stop2 = request.args.get('stop2')
    stop3 = request.args.get('stop3')
    destination = request.args.get('destination')
    return render_template('track.html', bus_name=bus_name, source=source, stop1=stop1, stop2=stop2, stop3=stop3, destination=destination)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
