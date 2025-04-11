from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests
import json  
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'AdminDragon'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

USER_PASTEBIN_RAW_URL = 'https://pastebin.com/raw/4Ld94DJZ'
FAMILY_PASTEBIN_RAW_URL = 'https://pastebin.com/raw/9a6Yriej'

# Data fetching functions
def get_users_data():
    try:
        response = requests.get(USER_PASTEBIN_RAW_URL)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
    return {'users': []}

def get_family_data():
    try:
        response = requests.get(FAMILY_PASTEBIN_RAW_URL)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
    return {'families': []}

def verify_password(stored, provided):
    if stored.startswith("pbkdf2:"):
        return check_password_hash(stored, provided)
    return stored == provided

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        data = get_users_data()
        users = data.get('users', [])
        for user in users:
            if user.get('email') == email and verify_password(user.get('password'), password):
                session['user_email'] = email
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        flash('Invalid email or password!', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        age = request.form.get('age')
        family_id = request.form.get('family_id')
        data = get_users_data()
        users = data.get('users', [])
        if any(u.get('email') == email for u in users):
            flash('Email already exists!', 'danger')
            return render_template('signup.html')
        hashed_password = generate_password_hash(password)
        users.append({
            'email': email,
            'password': hashed_password,
            'age': age,
            'family_id': family_id
        })
        try:
            api_dev_key = 'ROiTWbDu8aMQSRvAyGP5MvrDpi1N1KFV'
            api_paste_code = json.dumps({'users': users}, indent=2)
            response = requests.post(
                'https://pastebin.com/api/api_post.php',
                data={
                    'api_dev_key': api_dev_key,
                    'api_option': 'paste',
                    'api_paste_code': api_paste_code,
                    'api_paste_name': 'Medication Users',
                    'api_paste_private': 1
                }
            )
            if response.status_code == 200 and "pastebin.com" in response.text:
                flash('Account created successfully!', 'success')
                return redirect(url_for('login'))
            flash('Failed to update data in Pastebin.', 'danger')
        except Exception as e:
            print(f"Error updating Pastebin: {e}")
            flash('An error occurred while saving your data.', 'danger')
        return render_template('signup.html')
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    email = session.get('user_email')
    data = get_users_data()
    users = data.get('users', [])
    current = next((u for u in users if u.get('email') == email), None)
    if current:
        family_id = current.get('family_id')
        family_members = [u.get('email') for u in users if u.get('family_id') == family_id]
        if email in family_members:
            family_members.remove(email)
        return render_template('dashboard.html', user=current, family_members_emails=family_members)
    return redirect(url_for('login'))

@app.route('/family')
def family():
    if request.args:
        return redirect(url_for('family'))
    if 'user_email' not in session:
        return redirect(url_for('login'))
    email = session.get('user_email')
    data = get_users_data()
    current = next((u for u in data.get('users', []) if u.get('email') == email), None)
    if not current:
        flash('User not found', 'danger')
        return redirect(url_for('login'))
    family_id = current.get('family_id')
    family_data = get_family_data()
    family_obj = next((f for f in family_data.get('families', []) if f.get('family_id') == family_id), None)
    if not family_obj:
        flash('Family not found', 'danger')
        return redirect(url_for('dashboard'))
    members = [m for m in family_obj.get('members', []) if m.get('email') != email]
    return render_template('family.html', family_members=members)

@app.route('/add_reminder', methods=['GET', 'POST'])
def add_reminder():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        med_name = request.form.get('medName')
        dose = request.form.get('dose')
        time_val = request.form.get('time')
        flash('Reminder added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_reminder.html')

if __name__ == "__main__":
    app.run(debug=True)
