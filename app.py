from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import logging

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'your-secret-key'

users = []
activity_log = []
organizations = []

@app.route('/')
def index():
    return "Welcome to the GOLIATH - Secure Courier Digital Vault Drive"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = next((user for user in users if user['username'] == username), None)
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            logging.info(f'User {user["id"]} logged in')
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password"

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session.pop('user_id', None)
        logging.info(f'User {user_id} logged out')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = next((user for user in users if user['id'] == user_id), None)
    if not user:
        return redirect(url_for('login'))

    if user['role'] == 'admin':
        return render_template('dashboard.html', users=users, organizations=organizations)
    else:
        return render_template('dashboard.html')

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = next((user for user in users if user['id'] == user_id), None)
    if not user or user['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        organization = request.form['organization']
        users.append({'id': len(users)+1, 'username': username, 'password': password, 'role': role, 'organization': organization})
        logging.info(f'Admin {user_id} added user {username}')
        return redirect(url_for('dashboard'))
    
    return render_template('add_user.html', organizations=organizations)

@app.route('/activity_log')
def view_activity_log():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = next((user for user in users if user['id'] == user_id), None)
    if not user or user['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('activity_log.html', activity_log=activity_log)

@app.route('/sync_with_host')
def sync_with_host():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = next((user for user in users if user['id'] == user_id), None)
    if not user or user['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    # Syncing logic with the host
    # ...
    
    logging.info(f'Admin {user_id} initiated sync with host')
    return redirect(url_for('dashboard'))

@app.route('/add_organization', methods=['GET', 'POST'])
def add_organization():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = next((user for user in users if user['id'] == user_id), None)
    if not user or user['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        organization = request.form['organization']
        organizations.append(organization)
        logging.info(f'Admin {user_id} added organization {organization}')
        return redirect(url_for('dashboard'))
    
    return render_template('add_organization.html')

if __name__ == '__main__':
    logging.basicConfig(filename='activity.log', level=logging.INFO)
    app.run()
