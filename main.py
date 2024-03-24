from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import generate_password_hash, check_password_hash
import sqlite3
import re

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Function to establish connection to SQLite database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS doctors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 email TEXT,
                 password TEXT,
                 bod DATE,
                 phone TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 email TEXT,
                 phone TEXT,
                 password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS patients (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 email TEXT,
                 password TEXT,
                 bod DATE,
                 phone TEXT)''')
    conn.commit()
    conn.close()

create_tables()

# Fetch all doctors from the database
def get_doctors():
    conn = get_db_connection()
    doctors = conn.execute('SELECT * FROM doctors').fetchall()
    conn.close()
    return doctors

# Fetch all patients from the database
def get_patients():
    conn = get_db_connection()
    patients = conn.execute('SELECT * FROM patients').fetchall()
    conn.close()
    return patients

# Define roles for users
class Role:
    DOCTOR = 'doctor'
    ADMIN = 'admin'
    PATIENT = 'patient'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, role):
        self.id = user_id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    # Split the user_id into role and id
    role, id = user_id.split('-', 1)
    
    user = None
    if role == 'doctor':
        user = connection.execute('SELECT * FROM doctors WHERE id = ?', (id,)).fetchone()
    elif role == 'admin':
        user = connection.execute('SELECT * FROM admins WHERE id = ?', (id,)).fetchone()
    elif role == 'patient':
        user = connection.execute('SELECT * FROM patients WHERE id = ?', (id,)).fetchone()
    connection.close()

    if user:
        return User(user_id, role)
    else:
        return None

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        connection = get_db_connection()

        user = None
        # Check the admins, doctors, and patients tables for a user with the provided email
        for role in ['admins', 'doctors', 'patients']:
            user = connection.execute(f"SELECT * FROM {role} WHERE email = ?", (email,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_role'] = role[:-1]  # Remove the plural 's'
                break

        connection.close()

        if user:
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            error = "Incorrect username or password"
            return render_template("login.html", error=error)

    return render_template("login.html")


def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def index():
    patients_count = len(get_patients())
    doctors_count = len(get_doctors())
    admin_name = None

    # Only attempt to access admin name if the user role is 'admin'
    if 'user_role' in session and session['user_role'] == 'admin':
        conn = get_db_connection()
        admin = conn.execute('SELECT name FROM admins WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if admin:
            admin_name = admin['name']
        else:
            admin_name = 'Admin'  # Fallback name if the admin is not found

    return render_template('dashboard.html', 
                           doctors_count=doctors_count, 
                           patients_count=patients_count,
                           admin_name=admin_name, 
                           logged_in=session.get('logged_in'))

@app.route('/doctors')
@login_required
def doctors():
    doctors = get_doctors()
    return render_template('doctors.html', doctors=doctors)

@app.route('/create_doctor',  methods=['GET', 'POST'])
@login_required
def create_doctor():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        bod = request.form['bod']
        phone = request.form['phone']
        password = request.form['password']

        hashed_password = generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()

        # Check if email exists
        if conn.execute("SELECT * FROM doctors WHERE email = ?", (email,)).fetchone():
            conn.close()
            flash('Email is already registered. Please use a different email.', 'error')
            return redirect(url_for('create_doctor'))

        # Check if phone exists
        if conn.execute("SELECT * FROM doctors WHERE phone = ?", (phone,)).fetchone():
            conn.close()
            flash('Phone number is already registered. Please use a different phone number.', 'error')
            return redirect(url_for('create_doctor'))

        # Insert form data into the database
        conn.execute("INSERT INTO doctors (name, email, bod, phone, password) VALUES (?, ?, ?, ?, ?)", (name, email, bod, phone, hashed_password))

        # Commit the transaction
        conn.commit()
        conn.close()

        flash('Doctor has been created successfully!', 'success')

        return redirect(url_for('doctors'))
    else:
        return render_template('create_doctor.html')

@app.route('/edit_doctor/<int:doctor_id>',  methods=['GET', 'POST'])
@login_required
def edit_doctor(doctor_id):
    conn = get_db_connection()
    doctor = conn.execute("SELECT * FROM doctors WHERE id = ?", (doctor_id,)).fetchone()
    conn.close()

    if doctor is None:
        flash('Doctor not found!', 'error')
        return redirect(url_for('doctors'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        bod = request.form['bod']
        phone = request.form['phone']
        new_password = request.form['password']

        conn = get_db_connection()

        # Check if email exists
        if conn.execute("SELECT * FROM doctors WHERE email = ? AND id != ?", (email, doctor_id)).fetchone():
            conn.close()
            flash('Email is already registered. Please use a different email.', 'error')
            return redirect(url_for('edit_doctor', doctor_id=doctor_id))

        # Check if phone exists
        if conn.execute("SELECT * FROM doctors WHERE phone = ? AND id != ?", (phone, doctor_id)).fetchone():
            conn.close()
            flash('Phone number is already registered. Please use a different phone number.', 'error')
            return redirect(url_for('edit_doctor', doctor_id=doctor_id))

        # Check if the password has changed
        if new_password:
            hashed_password = generate_password_hash(new_password).decode('utf-8')
        else:
            # Keep the existing password if it has not changed
            hashed_password = doctor['password']

        # Update form data in the database
        conn.execute("UPDATE doctors SET name = ?, email = ?, bod = ?, phone = ?, password = ? WHERE id = ?",
                     (name, email, bod, phone,hashed_password, doctor_id))

        # Commit the transaction
        conn.commit()
        conn.close()

        flash('Doctor has been updated successfully!', 'success')

        return redirect(url_for('doctors'))
    else:
        return render_template('edit_doctor.html',  doctor=doctor)
    
@app.route('/patients')
@login_required
def patients():
    patients = get_patients()
    return render_template('patients.html', patients=patients)

@app.route('/create_patient',  methods=['GET', 'POST'])
@login_required
def create_patient():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        bod = request.form['bod']
        phone = request.form['phone']
        password = request.form['password']

        hashed_password = generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        
        # Check if email exists
        if conn.execute("SELECT * FROM patients WHERE email = ?", (email,)).fetchone():
            conn.close()
            flash('Email is already registered. Please use a different email.', 'error')
            return redirect(url_for('create_patient'))

        # Check if phone exists
        if conn.execute("SELECT * FROM patients WHERE phone = ?", (phone,)).fetchone():
            conn.close()
            flash('Phone number is already registered. Please use a different phone number.', 'error')
            return redirect(url_for('create_patient'))

        # Insert form data into the database
        conn.execute("INSERT INTO patients (name, email, bod, phone, password) VALUES (?, ?, ?, ?, ?)", (name, email, bod, phone, hashed_password))

        # Commit the transaction
        conn.commit()
        conn.close()

        flash('patient has been created successfully!', 'success')

        return redirect(url_for('patients'))
    else:
        return render_template('create_patient.html')
    
    
@app.route('/edit_patient/<int:patient_id>',  methods=['GET', 'POST'])
@login_required
def edit_patient(patient_id):
    conn = get_db_connection()
    patient = conn.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    conn.close()

    if patient is None:
        flash('Patient not found!', 'error')
        return redirect(url_for('patients'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        bod = request.form['bod']
        phone = request.form['phone']
        new_password = request.form['password']

        conn = get_db_connection()

        # Check if email exists
        if conn.execute("SELECT * FROM patients WHERE email = ? AND id != ?", (email, patient_id)).fetchone():
            conn.close()
            flash('Email is already registered. Please use a different email.', 'error')
            return redirect(url_for('edit_patient', patient_id=patient_id))

        # Check if phone exists
        if conn.execute("SELECT * FROM patients WHERE phone = ? AND id != ?", (phone, patient_id)).fetchone():
            conn.close()
            flash('Phone number is already registered. Please use a different phone number.', 'error')
            return redirect(url_for('edit_patient', patient_id=patient_id))

        # Check if the password has changed
        if new_password:
            hashed_password = generate_password_hash(new_password).decode('utf-8')
        else:
            # Keep the existing password if it has not changed
            hashed_password = patient['password']

        # Update form data in the database
        conn.execute("UPDATE patients SET name = ?, email = ?, bod = ?, phone = ?, password = ? WHERE id = ?",
                     (name, email, bod, phone,hashed_password, patient_id))

        # Commit the transaction
        conn.commit()
        conn.close()

        flash('Patient has been updated successfully!', 'success')

        return redirect(url_for('patients'))
    else:
        return render_template('edit_patient.html', patient=patient)
    


def add_admin(name, email, phone, password):
    conn = get_db_connection()
    c = conn.cursor()

    # Regular expression for validating an Email
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    # Regular expression for validating a Saudi phone number (starts with 05 followed by 8 digits)
    phone_regex = r'05\d{8}'
    # Regular expression for validating a Password
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'

    # Check if email is valid
    if not re.fullmatch(email_regex, email):
        print("Invalid email format.")
        conn.close()
        return

    # Check if phone is valid
    if not re.fullmatch(phone_regex, phone):
        print("Invalid phone format. Phone should start with 05 followed by 8 digits.")
        conn.close()
        return

    # Check if password is valid
    if not re.fullmatch(password_regex, password):
        print("Invalid password format. Password must contain at least one letter, one number, one special character, and be at least 8 characters long.")
        conn.close()
        return

    # Check if email already exists in the database
    c.execute("SELECT * FROM admins WHERE email = ?", (email,))
    if c.fetchone():
        print("An admin with this email already exists.")
        conn.close()
        return

    # Check if phone already exists in the database
    c.execute("SELECT * FROM admins WHERE phone = ?", (phone,))
    if c.fetchone():
        print("An admin with this phone number already exists.")
        conn.close()
        return

    # If email and phone are unique and valid, proceed to add the new admin
    hashed_password = generate_password_hash(password).decode('utf-8')
    c.execute("INSERT INTO admins (name, email, phone, password) VALUES (?, ?, ?, ?)", 
              (name, email, phone, hashed_password))
    conn.commit()
    conn.close()
    print(f"Admin {name} added successfully!")


def remove_admin(id):
    conn = get_db_connection()
    c = conn.cursor()

    # Check if the admin exists before trying to delete
    c.execute("SELECT * FROM admins WHERE id = ?", (id,))
    if not c.fetchone():
        print("No admin found with this ID.")
        conn.close()
        return

    # If the admin exists, delete them
    c.execute("DELETE FROM admins WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    print(f"Admin with ID {id} has been deleted successfully.")

def edit_admin(admin_id, name, email, phone, new_password=None):
    conn = get_db_connection()
    c = conn.cursor()

    # Validate email format
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not re.fullmatch(email_regex, email):
        print("Invalid email format.")
        conn.close()
        return False, "Invalid email format."

    # Validate phone format
    phone_regex = r'05\d{8}'
    if not re.fullmatch(phone_regex, phone):
        print("Invalid phone format.")
        conn.close()
        return False, "Invalid phone format."

    # Validate password format if a new password is provided
    if new_password:
        password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
        if not re.fullmatch(password_regex, new_password):
            print("Invalid password format.")
            conn.close()
            return False, "Invalid password format."
        hashed_password = generate_password_hash(new_password).decode('utf-8')
    else:
        # Retrieve the existing hashed password if no new password is provided
        existing_admin = c.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
        if not existing_admin:
            print("Admin not found.")
            conn.close()
            return False, "Admin not found."
        hashed_password = existing_admin['password']

    # Update the admin's information in the database
    c.execute("UPDATE admins SET name = ?, email = ?, phone = ?, password = ? WHERE id = ?",
              (name, email, phone, hashed_password, admin_id))
    conn.commit()
    conn.close()
    print(f"Admin with ID {admin_id} has been updated successfully!")
    return True, "Admin updated successfully."


    
@app.route('/remove_doctor', methods=['POST'])
@login_required
def remove_doctor():
    doctor_id = request.form['doctor_id']
    
    # Connect to the SQLite database
    conn = get_db_connection()

    # Execute SQL DELETE statement to remove the record
    conn.execute("DELETE FROM doctors WHERE id = ?", (doctor_id,))

    # Commit the transaction
    conn.commit()
    conn.close()

    flash('Doctor has been removed successfully!', 'success')

    return redirect(url_for('doctors'))  # Redirect to the doctors page after removal

@app.route('/remove_patient', methods=['POST'])
@login_required
def remove_patient():
    patient_id = request.form['patient_id']
    
    # Connect to the SQLite database
    conn = get_db_connection()

    # Execute SQL DELETE statement to remove the record
    conn.execute("DELETE FROM patients WHERE id = ?", (patient_id,))

    # Commit the transaction
    conn.commit()
    conn.close()

    flash('Patient has been removed successfully!', 'success')

    return redirect(url_for('patients'))  # Redirect to the doctors page after removal


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
