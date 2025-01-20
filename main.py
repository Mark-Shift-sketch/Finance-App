from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'alkxctcegjjdvfbvgxzc'  # Use a strong secret key in production!

def get_db():
    conn = sqlite3.connect('users.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('PRAGMA journal_mode=WAL;')  # Enable Write-Ahead Logging for better concurrency
        
        # Create users table if it does not exist
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                        )''')

        # Create transactions table if it does not exist
        conn.execute('''CREATE TABLE IF NOT EXISTS transactions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            biller TEXT NOT NULL,
                            account_number TEXT NOT NULL,
                            amount REAL NOT NULL,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')

        # Create notifications table if it does not exist
        conn.execute('''CREATE TABLE IF NOT EXISTS notifications (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            message TEXT NOT NULL,
                            read INTEGER DEFAULT 0,  -- Add default value for read column
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')

        # Check if 'read' column exists, and add it if not
        try:
            conn.execute("SELECT read FROM notifications LIMIT 1")
        except sqlite3.OperationalError:
            # The 'read' column does not exist, so we need to add it
            conn.execute("ALTER TABLE notifications ADD COLUMN read INTEGER DEFAULT 0")

        conn.commit()


# Call init_db() to create the tables when the application starts
init_db()

@app.route('/')
def home():
    return render_template('signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('signup.html', message="Passwords do not match. Try again!")

        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password) or not any(char.islower() for char in password):
            return render_template('signup.html', message="Password must be at least 8 characters long, contain a digit, an uppercase letter, and a lowercase letter.")

        hashed_password = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (uname, hashed_password))
                conn.commit()
        except sqlite3.IntegrityError:
            return render_template('signup.html', message="Username already exists. Try a different one.")

        return render_template('signup.html', message="Signup successful! You can now log in.")

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['username']
        password = request.form['password']

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()

        if user:
            if check_password_hash(user['password'], password):
                session['username'] = name  # Store username in session
                return redirect(url_for('web_interface', username=name))
            else:
                return render_template('login.html', message="Incorrect password. Try again!")
        else:
            return render_template('login.html', message="Username not found. Please sign up first.")

    return render_template('login.html')

@app.route('/web/<username>', methods=['GET', 'POST'])
def web_interface(username):
    action = request.args.get('action', None)
    message = None
    biller = None
    amount = None
    account_number = None
    balance = None

    # Initialize unread_count to be used later
    unread_count = 0

    if request.method == 'POST':
        if action == 'messages':
            message = request.form.get('message', '').strip()
            if message:
                message = ("Message sent successfully!", 'success')
            else:
                message = ("Message can't be empty.", 'error')

        elif action == 'pay bills':
            # Get the form inputs
            biller = request.form.get('biller', '').strip()
            amount = request.form.get('amount', '').strip()
            account_number = request.form.get('account_number', '').strip()

            # Validation of inputs
            if not biller:
                message = ("Biller can't be empty.", 'error')
            elif not amount:
                message = ("Amount can't be empty.", 'error')
            elif not account_number:
                message = ("Account number can't be empty.", 'error')
            elif not account_number.isdigit():
                message = ("Account number must be numeric.", 'error')
            elif not amount.replace('.', '', 1).isdigit() or float(amount) <= 0:
                message = ("Amount must be a positive number.", 'error')
            else:
                try:
                    # Insert transaction into the database
                    with get_db() as conn:
                        conn.execute("INSERT INTO transactions (username, biller, amount, account_number) VALUES (?, ?, ?, ?)",
                                     (username, biller, float(amount), account_number))
                        conn.commit()

                    # After successful insertion, show success message
                    message = ("Payment successfully completed.", 'success')

                except Exception as e:
                    # Log the error if there's an issue with the database
                    print(f"Error inserting transaction: {str(e)}")  # You can also use a logger
                    message = ("An error occurred while processing the payment.", 'error')

            # Fetch the updated transactions to reflect changes immediately
            with get_db() as conn:
                transactions = conn.execute("SELECT biller, amount, account_number, timestamp FROM transactions WHERE username = ?", (username,)).fetchall()

            # After insertion and transaction update, re-render the template
            return render_template('dashboard.html', username=username, action=action, message=message, biller=biller, amount=amount, account_number=account_number, transactions=transactions, unread_count=unread_count)
    
    # For GET requests, fetch transactions and render the page
    with get_db() as conn:
        transactions = conn.execute("SELECT biller, amount, account_number, timestamp FROM transactions WHERE username = ?", (username,)).fetchall()
        notifications = conn.execute("SELECT title, message, timestamp FROM notifications ORDER BY timestamp DESC").fetchall()

        # Mark notifications as read if visiting the notifications page
        if action == 'notification':
            conn.execute("UPDATE notifications SET read = 1 WHERE read = 0")
            conn.commit()

        # Get unread notifications count
        unread_count = conn.execute("SELECT COUNT(*) FROM notifications WHERE read = 0").fetchone()[0]

    return render_template('dashboard.html', username=username, action=action, message=message, biller=biller, amount=amount, account_number=account_number, transactions=transactions, notifications=notifications, unread_count=unread_count)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin' not in session:  # Simple check to see if admin is logged in
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']
        
        with get_db() as conn:
            conn.execute("INSERT INTO notifications (title, message) VALUES (?, ?)", (title, message))
            conn.commit()
        
        return redirect(url_for('admin'))
    
    return render_template('admin.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_username = request.form['username']
        admin_password = request.form['password']

        # Simple hardcoded admin credentials check
        if admin_username == 'admin' and admin_password == 'password':
            session['admin'] = True
            return redirect(url_for('admin'))
        else:
            return render_template('admin_login.html', message="Invalid credentials")

    return render_template('admin_login.html')

if __name__ == "__main__":
    app.run(debug=True)
