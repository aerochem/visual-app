from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import bcrypt
import os
from werkzeug.utils import secure_filename
import csv
from io import StringIO
import re

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'
DB_PATH = 'pda_app.db'

def get_db():
    return sqlite3.connect(DB_PATH)

def authenticate_user(username, password):
    with get_db() as conn:
        cur = conn.execute('SELECT id, password_hash, role FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        if not row:
            return None
        user_id, password_hash, role = row
        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            return {'id': user_id, 'username': username, 'role': role}
        return None

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('gallery'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    username = session.get('username')
    with get_db() as conn:
        product_count = conn.execute('SELECT COUNT(*) FROM products').fetchone()[0]
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] if role == 'admin' else None
        doctor_count = conn.execute('SELECT COUNT(*) FROM doctors').fetchone()[0]
        # Product category distribution
        product_category_counts = conn.execute('SELECT category, COUNT(*) FROM products WHERE category IS NOT NULL GROUP BY category').fetchall()
        # Doctor specialty distribution
        doctor_specialty_counts = conn.execute('SELECT specialty, COUNT(*) FROM doctors WHERE specialty IS NOT NULL GROUP BY specialty').fetchall()
        recent_products = conn.execute('SELECT id, name, image_path FROM products ORDER BY id DESC LIMIT 3').fetchall()
        settings = conn.execute('SELECT company_name, logo_path FROM company_settings LIMIT 1').fetchone()
        if settings:
            company_name, logo_path = settings
        else:
            company_name, logo_path = 'PDA App', None
    return render_template(
        'dashboard.html',
        username=username,
        role=role,
        product_count=product_count,
        user_count=user_count,
        doctor_count=doctor_count,
        product_category_counts=product_category_counts,
        doctor_specialty_counts=doctor_specialty_counts,
        recent_products=recent_products,
        company_name=company_name,
        logo_path=logo_path
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/gallery')
@login_required
def gallery():
    category = request.args.get('category')
    with get_db() as conn:
        if category:
            products = conn.execute('SELECT id, name, image_path, category FROM products WHERE category = ? ORDER BY id', (category,)).fetchall()
        else:
            products = conn.execute('SELECT id, name, image_path, category FROM products ORDER BY id').fetchall()
        categories = conn.execute('SELECT DISTINCT category FROM products WHERE category IS NOT NULL').fetchall()
    return render_template('gallery.html', products=products, categories=categories, selected_category=category, role=session.get('role'))

@app.route('/products/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if session.get('role') != 'admin':
        flash('Only admins can add products.', 'danger')
        return redirect(url_for('gallery'))
    if request.method == 'POST':
        name = request.form['name']
        image_path = request.form['image_path']
        with get_db() as conn:
            conn.execute('INSERT INTO products (name, image_path, uploaded_by) VALUES (?, ?, ?)',
                         (name, image_path, session['user_id']))
        flash('Product added.', 'success')
        return redirect(url_for('gallery'))
    return render_template('add_product.html', role=session.get('role'))

@app.route('/products/viewer/<int:product_id>')
@login_required
def product_viewer(product_id):
    role = session.get('role')
    if role not in ['admin', 'mr']:
        flash('Only MRs and admins can view products in full screen.', 'danger')
        return redirect(url_for('gallery'))
    with get_db() as conn:
        products = conn.execute('SELECT id, name, image_path FROM products ORDER BY id').fetchall()
        current = None
        for idx, prod in enumerate(products):
            if prod[0] == product_id:
                current = idx
                break
    if current is None:
        return 'Product not found.', 404
    return render_template('product_viewer.html', products=products, current=current, role=role)

@app.route('/products/upload', methods=['GET', 'POST'], endpoint='upload_products')
@login_required
def upload_products():
    if session.get('role') != 'admin':
        flash('Only admins can upload products.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        files = request.files.getlist('images')
        category = request.form.get('category')
        saved = 0
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                save_path = os.path.join('static', 'products', filename)
                file.save(save_path)
                with get_db() as conn:
                    conn.execute('INSERT INTO products (name, image_path, category, uploaded_by) VALUES (?, ?, ?, ?)',
                                 (filename, save_path.replace('\\', '/'), category, session['user_id']))
                saved += 1
        flash(f'{saved} product images uploaded.', 'success')
        return redirect(url_for('gallery'))
    # Fetch distinct categories for the upload form (optional, for UI)
    with get_db() as conn:
        categories = conn.execute('SELECT DISTINCT category FROM products WHERE category IS NOT NULL').fetchall()
    return render_template('upload_products.html', role=session.get('role'), categories=categories)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if session.get('role') != 'admin':
        flash('Access denied. Only admins can manage settings.', 'danger')
        return redirect(url_for('dashboard'))
    with get_db() as conn:
        settings = conn.execute('SELECT id, company_name, logo_path FROM company_settings LIMIT 1').fetchone()
        company_name = settings[1] if settings else ''
        logo_path = settings[2] if settings else ''
        settings_id = settings[0] if settings else None
    if request.method == 'POST':
        new_name = request.form.get('company_name', '').strip()
        logo_file = request.files.get('logo_file')
        logo_path_new = logo_path
        # Validate company name
        if not new_name:
            flash('Company name is required.', 'danger')
            return render_template('settings.html', company_name=company_name, logo_path=logo_path, role=session.get('role'))
        # Handle logo upload
        if logo_file and logo_file.filename:
            if not logo_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
                flash('Logo must be an image file (png, jpg, jpeg, gif, webp).', 'danger')
                return render_template('settings.html', company_name=company_name, logo_path=logo_path, role=session.get('role'))
            file_bytes = logo_file.read()
            if len(file_bytes) > 2 * 1024 * 1024:  # 2MB limit
                flash('Logo file is too large (max 2MB).', 'danger')
                return render_template('settings.html', company_name=company_name, logo_path=logo_path, role=session.get('role'))
            logo_file.seek(0)
            filename = secure_filename(logo_file.filename)
            save_dir = os.path.join('static', 'logo')
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, filename)
            logo_file.save(save_path)
            logo_path_new = f'logo/{filename}'
        # Update DB
        with get_db() as conn:
            if settings_id:
                conn.execute('UPDATE company_settings SET company_name=?, logo_path=? WHERE id=?', (new_name, logo_path_new, settings_id))
            else:
                conn.execute('INSERT INTO company_settings (company_name, logo_path) VALUES (?, ?)', (new_name, logo_path_new))
            conn.commit()
        flash('Settings updated.', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', company_name=company_name, logo_path=logo_path, role=session.get('role'))

@app.route('/doctors/<int:doctor_id>/products', methods=['POST'])
@login_required
def update_doctor_products(doctor_id):
    product_ids = request.form.getlist('product_ids')
    with get_db() as conn:
        # Remove old mappings
        conn.execute('DELETE FROM doctor_product_map WHERE doctor_id = ?', (doctor_id,))
        # Insert new mappings
        for pid in product_ids:
            conn.execute('INSERT INTO doctor_product_map (doctor_id, product_id) VALUES (?, ?)', (doctor_id, pid))
        conn.commit()
    return redirect(url_for('doctor_list'))

@app.route('/doctors')
@login_required
def doctor_list():
    with get_db() as conn:
        doctors = conn.execute('SELECT id, name FROM doctors ORDER BY name').fetchall()
        all_products = conn.execute('SELECT id, name FROM products ORDER BY name').fetchall()
        # Build a mapping: doctor_id -> set of mapped product ids
        doctor_mapped_ids = {}
        for doc in doctors:
            mapped = set(row[0] for row in conn.execute('SELECT product_id FROM doctor_product_map WHERE doctor_id=?', (doc[0],)).fetchall())
            doctor_mapped_ids[doc[0]] = mapped
    return render_template('doctor_list.html', doctors=doctors, all_products=all_products, doctor_mapped_ids=doctor_mapped_ids, role=session.get('role'))

@app.route('/doctors/add', methods=['GET', 'POST'])
@login_required
def add_doctor():
    if session.get('role') not in ['admin', 'mr']:
        flash('Access denied.', 'danger')
        return redirect(url_for('doctor_list'))
    with get_db() as conn:
        products = conn.execute('SELECT id, name, image_path FROM products ORDER BY name').fetchall()
    if request.method == 'POST':
        name = request.form['name']
        specialty = request.form['specialty']
        area = request.form['area']
        contact = request.form['contact']
        email = request.form['email']
        product_ids = request.form.getlist('product_ids')
        with get_db() as conn:
            cur = conn.execute('INSERT INTO doctors (name, specialty, area, contact, email) VALUES (?, ?, ?, ?, ?)', (name, specialty, area, contact, email))
            doctor_id = cur.lastrowid
            for pid in product_ids:
                conn.execute('INSERT INTO doctor_product_map (doctor_id, product_id) VALUES (?, ?)', (doctor_id, pid))
            conn.commit()
        flash('Doctor added.', 'success')
        return redirect(url_for('doctor_list'))
    return render_template('doctor_form.html', doctor=None, products=products, mapped=[], role=session.get('role'))

@app.route('/doctors/edit/<int:doctor_id>', methods=['GET', 'POST'])
@login_required
def edit_doctor(doctor_id):
    if session.get('role') not in ['admin', 'mr']:
        flash('Access denied.', 'danger')
        return redirect(url_for('doctor_list'))
    with get_db() as conn:
        doctor = conn.execute('SELECT id, name, specialty, area, contact, email FROM doctors WHERE id=?', (doctor_id,)).fetchone()
        products = conn.execute('SELECT id, name, image_path FROM products ORDER BY name').fetchall()
        mapped = set(row[0] for row in conn.execute('SELECT product_id FROM doctor_product_map WHERE doctor_id=?', (doctor_id,)).fetchall())
        if not doctor:
            flash('Doctor not found.', 'danger')
            return redirect(url_for('doctor_list'))
        if request.method == 'POST':
            name = request.form['name']
            specialty = request.form['specialty']
            area = request.form['area']
            contact = request.form['contact']
            email = request.form['email']
            product_ids = request.form.getlist('product_ids')
            conn.execute('UPDATE doctors SET name=?, specialty=?, area=?, contact=?, email=? WHERE id=?', (name, specialty, area, contact, email, doctor_id))
            conn.execute('DELETE FROM doctor_product_map WHERE doctor_id=?', (doctor_id,))
            for pid in product_ids:
                conn.execute('INSERT INTO doctor_product_map (doctor_id, product_id) VALUES (?, ?)', (doctor_id, pid))
            conn.commit()
            flash('Doctor updated.', 'success')
            return redirect(url_for('doctor_list'))
    return render_template('doctor_form.html', doctor=doctor, products=products, mapped=mapped, role=session.get('role'))

@app.route('/doctors/delete/<int:doctor_id>', methods=['POST'])
@login_required
def delete_doctor(doctor_id):
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('doctor_list'))
    with get_db() as conn:
        conn.execute('DELETE FROM doctors WHERE id=?', (doctor_id,))
        conn.commit()
    flash('Doctor deleted.', 'success')
    return redirect(url_for('doctor_list'))

@app.route('/doctors/bulk-upload', methods=['GET', 'POST'])
@login_required
def bulk_upload_doctors():
    if session.get('role') not in ['admin', 'mr']:
        flash('Access denied.', 'danger')
        return redirect(url_for('doctor_list'))
    if request.method == 'POST':
        file = request.files.get('csv_file')
        if not file or not file.filename.endswith('.csv'):
            flash('Please upload a valid CSV file.', 'danger')
            return redirect(url_for('bulk_upload_doctors'))
        reader = csv.DictReader(StringIO(file.read().decode('utf-8')))
        added = 0
        for row in reader:
            name = row.get('name')
            specialty = row.get('specialty')
            area = row.get('area')
            contact = row.get('contact')
            email = row.get('email')
            if name:
                try:
                    with get_db() as conn:
                        conn.execute('INSERT INTO doctors (name, specialty, area, contact, email) VALUES (?, ?, ?, ?, ?)', (name, specialty, area, contact, email))
                        conn.commit()
                    added += 1
                except Exception:
                    continue
        flash(f'{added} doctors uploaded.', 'success')
        return redirect(url_for('doctor_list'))
    return render_template('doctor_bulk_upload.html', role=session.get('role'))

@app.route('/doctors/sample-csv')
@login_required
def download_doctor_sample_csv():
    sample = 'name,specialty,area,contact,email\nDr. John Doe,Cardiology,New York,1234567890,john@example.com\n'
    return sample, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=doctor_sample.csv'}

@app.route('/mapping-dashboard')
@login_required
def mapping_dashboard():
    if session.get('role') not in ['admin', 'mr']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    with get_db() as conn:
        doctors = conn.execute('SELECT id, name, specialty, area, contact, email FROM doctors ORDER BY name').fetchall()
    return render_template('mapping_dashboard.html', doctors=doctors, role=session.get('role'))

@app.route('/api/doctor/<int:doctor_id>/products', methods=['GET'])
def api_doctor_products(doctor_id):
    with get_db() as conn:
        doctor = conn.execute('SELECT name, specialty, area FROM doctors WHERE id=?', (doctor_id,)).fetchone()
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404
        mapped = conn.execute('SELECT product_id FROM doctor_product_map WHERE doctor_id=?', (doctor_id,)).fetchall()
        mapped_ids = [row[0] for row in mapped]
        all_products = conn.execute('SELECT id, name, image_path FROM products').fetchall()
        all_products_json = [{'id': p[0], 'name': p[1], 'thumbnail': p[2]} for p in all_products]
    return jsonify({
        'doctor_name': doctor[0],
        'doctor_specialty': doctor[1],
        'doctor_area': doctor[2],
        'mapped_ids': mapped_ids,
        'all_products': all_products_json
    })

@app.route('/api/map-products', methods=['POST'])
def api_map_products():
    data = request.get_json()
    doctor_id = data.get('doctor_id')
    product_ids = data.get('product_ids', [])
    if not doctor_id or not isinstance(product_ids, list):
        return jsonify({'success': False, 'error': 'Invalid input'}), 400
    with get_db() as conn:
        conn.execute('DELETE FROM doctor_product_map WHERE doctor_id=?', (doctor_id,))
        for pid in product_ids:
            conn.execute('INSERT INTO doctor_product_map (doctor_id, product_id) VALUES (?, ?)', (doctor_id, pid))
        conn.commit()
    return jsonify({'success': True})

@app.route('/doctor/<int:doctor_id>/slideshow')
def doctor_slideshow(doctor_id):
    with get_db() as conn:
        doctor = conn.execute('SELECT id, name, specialty, area FROM doctors WHERE id=?', (doctor_id,)).fetchone()
        if not doctor:
            return "Doctor not found", 404
        products = conn.execute('''
            SELECT p.id, p.name, p.image_path, p.category
            FROM products p
            JOIN doctor_product_map dpm ON dpm.product_id = p.id
            WHERE dpm.doctor_id = ?
            ORDER BY p.id
        ''', (doctor_id,)).fetchall()
    return render_template('slideshow.html', doctor=doctor, products=products)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def user_creation():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip()
        role = request.form['role']
        # Basic validation
        if not username or not password or not email or not role:
            flash('All fields are required.', 'danger')
            return render_template('user_creation.html', role=session.get('role'))
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address.', 'danger')
            return render_template('user_creation.html', role=session.get('role'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('user_creation.html', role=session.get('role'))
        with get_db() as conn:
            # Check for unique username/email
            if conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
                flash('Username already exists.', 'danger')
                return render_template('user_creation.html', role=session.get('role'))
            if conn.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone():
                flash('Email already exists.', 'danger')
                return render_template('user_creation.html', role=session.get('role'))
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            conn.execute('INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
                         (username, password_hash, email, role))
            conn.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('user_creation.html', role=session.get('role'))

if __name__ == '__main__':
    app.run(debug=True) 