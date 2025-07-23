import sqlite3
import bcrypt
import getpass

DB_PATH = 'pda_app.db'

def register_user(username, password, email, role):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, role))
        print(f"User '{username}' registered successfully as {role}.")
    except sqlite3.IntegrityError as e:
        print(f"Error: {e}")

def main():
    print('Minimal PDA App User Registration')
    username = input('Username: ')
    password = getpass.getpass('Password: ')
    email = input('Email: ')
    role = input('Role (admin/mr): ').strip().lower()
    if role not in ('admin', 'mr'):
        print('Invalid role.')
        return
    register_user(username, password, email, role)

if __name__ == '__main__':
    main()
