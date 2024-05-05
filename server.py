from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
import re
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Подключение к базе данных SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Модель для хранения пользователей и их файлов
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    files = db.relationship('File', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Создание таблиц в базе данных
with app.app_context():
    db.create_all()

def create_user_directory(username):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

def is_valid_username(username):
    return re.match("^[a-zA-Z0-9_-]{3,20}$", username)

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if is_valid_username(username):
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            create_user_directory(username)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username. Usernames must be between 3 and 20 characters long and can only contain letters, numbers, underscores, and hyphens."
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password."
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            files = File.query.filter_by(user_id=user.id).all()
            return render_template('dashboard.html', username=username, files=files)
        else:
            return "User not found."
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
            if 'file' in request.files:
                file = request.files['file']
                if file.filename != '':
                    filename = file.filename
                    new_file = File(filename=filename, user_id=user.id)
                    db.session.add(new_file)
                    db.session.commit()
                    file_path = os.path.join(user_folder, filename)
                    file.save(file_path)
                    return redirect(url_for('dashboard'))
                else:
                    return "No file selected."
            else:
                return "No file part in request."
        else:
            return "User not found."
    return redirect(url_for('index'))

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    if 'username' in session:
        username = session['username']
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        return send_from_directory(directory=user_folder, filename=filename)
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
