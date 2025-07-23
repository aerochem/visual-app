import sqlite3

conn = sqlite3.connect('pda_app.db')
c = conn.cursor()

# Users table
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('admin', 'mr')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Products table
c.execute('''
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    image_path TEXT NOT NULL,
    category TEXT,
    uploaded_by INTEGER,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
)
''')

# Company Settings table
c.execute('''
CREATE TABLE IF NOT EXISTS company_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT,
    logo_path TEXT
)
''')

# Doctor-Product Mapping table
c.execute('''
CREATE TABLE IF NOT EXISTS doctor_product_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    FOREIGN KEY (doctor_id) REFERENCES doctors(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
)
''')

# Doctors table (add more fields if not present)
c.execute('''
CREATE TABLE IF NOT EXISTS doctors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    specialty TEXT,
    area TEXT,
    contact TEXT,
    email TEXT UNIQUE
)
''')

conn.commit()
conn.close()
print('Minimal PDA App database and tables created successfully.')

# Debug: Print all products in the products table
with sqlite3.connect('pda_app.db') as conn:
    c = conn.cursor()
    print('\nCurrent products in the database:')
    for row in c.execute('SELECT id, name, image_path, category FROM products'):
        print(row) 