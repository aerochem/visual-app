from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Load branding config
with open('pda_app_spec.json') as f:
    CONFIG = json.load(f)

# --- Role-based access decorator ---
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('Access denied.')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Auth routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Placeholder login logic
    return render_template('login.html', branding=CONFIG['branding'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- MR Features ---
@app.route('/gallery')
@role_required('mr', 'admin')
def gallery():
    # Visual gallery for MRs
    return render_template('gallery.html', branding=CONFIG['branding'])

@app.route('/doctors')
@role_required('mr', 'admin')
def doctor_list():
    # List doctors
    return render_template('doctor_list.html', branding=CONFIG['branding'])

@app.route('/doctors/add', methods=['GET', 'POST'])
@role_required('mr', 'admin')
def add_doctor():
    # Add doctor form
    return render_template('doctor_form.html', branding=CONFIG['branding'])

@app.route('/doctors/bulk_upload', methods=['GET', 'POST'])
@role_required('mr', 'admin')
def bulk_upload_doctors():
    # Bulk upload via CSV
    return render_template('doctor_bulk_upload.html', branding=CONFIG['branding'])

@app.route('/doctors/<int:doctor_id>/reminder', methods=['GET', 'POST'])
@role_required('mr', 'admin')
def set_reminder(doctor_id):
    # Set visit reminder
    return render_template('reminder_form.html', branding=CONFIG['branding'])

@app.route('/doctors/<int:doctor_id>/notes', methods=['GET', 'POST'])
@role_required('mr', 'admin')
def notes_per_doctor(doctor_id):
    # Notes per doctor
    return render_template('notes.html', branding=CONFIG['branding'])

@app.route('/change_password', methods=['GET', 'POST'])
@role_required('mr', 'admin')
def change_password():
    # Change password
    return render_template('change_password.html', branding=CONFIG['branding'])

@app.route('/whatsapp_share/<int:product_id>')
@role_required('mr', 'admin')
def whatsapp_share(product_id):
    # WhatsApp share modal
    return render_template('whatsapp_share.html', branding=CONFIG['branding'])

# --- Admin Features ---
@app.route('/admin/products', methods=['GET', 'POST'])
@role_required('admin')
def product_upload():
    # Product upload (JPG/PDF)
    return render_template('product_upload.html', branding=CONFIG['branding'])

@app.route('/admin/users', methods=['GET', 'POST'])
@role_required('admin')
def user_creation():
    # User creation (email invite)
    return render_template('user_creation.html', branding=CONFIG['branding'])

@app.route('/admin/settings', methods=['GET', 'POST'])
@role_required('admin')
def settings():
    # Settings page (logo, company info, color control)
    return render_template('settings.html', branding=CONFIG['branding'])

@app.route('/admin/analytics')
@role_required('admin')
def analytics():
    # Analytics dashboard
    return render_template('analytics.html', branding=CONFIG['branding'])

# --- Static/Branding Assets ---
@app.route('/logo.png')
def logo():
    # Serve logo from static or config
    return send_from_directory('static', 'logo.png')

# --- Splash Screen ---
@app.route('/')
def splash():
    return render_template('splash.html', branding=CONFIG['branding'])

if __name__ == '__main__':
    app.run(debug=True) 