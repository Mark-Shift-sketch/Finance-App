from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

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
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
    if not user:
        message = 'User not found.'
        return redirect(url_for('home'))

    user = dict(user)  # Make sure the result is converted to a dictionary
    action = request.args.get('action', None)
    message = None
    unread_count = 0
    recipient = None
    biller = None
    amount = None
    account_number = None

    if request.method == 'POST':
        amount = request.form.get('amount', 0)
        amount = float(amount) if amount else 0.0
        bank_account_number = request.form.get('bank_account_number', None)
        bank_pin = request.form.get('bank_pin', None)
        recipient_username = request.form.get('recipient_username', None)
        bank_name = request.form.get('bank_name', None)
        #old_pin = request.form.get('old_pin', '').strip()
        #new_pin = request.form.get('new_pin', '').strip()
        #confirm_pin = request.form.get('confirm_pin', '').strip()


        
        if action == 'balance':
         # Handle Cash-In to Account
            if amount <= 0:
                message = 'Amount must be greater than 0.'
            elif not bank_account_number or not bank_pin:
                message = 'Bank account number and PIN are required.'
            else:
                # Process cash-in to account
                user['balance'] += amount
                with get_db() as conn:
                    conn.execute("UPDATE users SET balance = ? WHERE username = ?", (user['balance'], username))
                    conn.commit()
                message = f"Successfully cashed in ${amount} to your account."

        #elif action == 'cashout_account':
            ## Handle Cash-Out from Account
            #if amount <= 0:
                #message = ('Amount must be greater than 0.')
            #elif user['balance'] < amount:
                #message = ('Insufficient balance for cash-out.')
            #elif not recipient_username:
               # message = 'Recipient username is required.'
            #else:
                #with get_db() as conn:
                    #recipient_user = conn.execute("SELECT * FROM users WHERE username = ?", (recipient_username,)).fetchone()
                   # if recipient_user:
                        ## Transfer money to recipient
                       # user['balance'] -= amount
                        #recipient_user['balance'] += amount
                       # conn.execute("UPDATE users SET balance = ? WHERE username = ?", (user['balance'], username))
                        #conn.execute("UPDATE users SET balance = ? WHERE username = ?", (recipient_user['balance'], recipient_username))
                        #conn.commit()
                        #message = f"Successfully transferred ${amount} to {recipient_username}."
                    #else:
                        #message = f"Recipient username '{recipient_username}' not found."

        #elif action == 'cashin_bank':
            # Handle Cash-In to Bank
            #if not bank_pin:
              #  message = ('Bank PIN is required.', 'error')
               # return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)
            #elif not check_password_hash(user['pin'], bank_pin):
              #  message = ('Incorrect PIN.', 'error')
                #return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

            #elif action == 'change-pin':
                #if 'pin' in user and user['pin'] and old_pin:
                  #  if not check_password_hash(user['pin'], old_pin):
                  #      message = ("Old PIN is incorrect.", 'error')
                  #      return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

                #if len(new_pin) != 4 or not new_pin.isdigit():
                   # message = ("New PIN must be 4 digits.", 'error')
               # elif new_pin != confirm_pin:
                  #  message = ("New PIN and confirmation do not match.", 'error')
                #else:
                   # hashed_pin = generate_password_hash(new_pin)
                   # with get_db() as conn:
                   #     conn.execute("UPDATE users SET pin = ? WHERE username = ?", (hashed_pin, username))
                   #     conn.commit()
                    #message = ("PIN has been successfully created/updated.", 'success')
                    #return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

                #return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

            #if amount <= 0:
                #message = ('Amount must be greater than 0.')
            #elif not bank_account_number or not bank_pin or not bank_name:
                #message = ('Bank details are required.')
            #else:
                ## Process cash-in to bank
                #user['bank_balance'] += amount
                #with get_db() as conn:
                    #conn.execute("UPDATE users SET bank_balance = ? WHERE username = ?", (user['bank_balance'], username))
                   # conn.commit()
                #message = f"Successfully cashed in ${amount} to your bank account ({bank_name})."

        #elif action == 'cashout_bank':
            # Handle Cash-Out from Bank (remove #(comment to use and modify it))
            
            # if not bank_pin:
                #message = ('Bank PIN is required.', 'error')
                #return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)
            #elif not check_password_hash(user['pin'], bank_pin):
               # message = ('Incorrect PIN.', 'error')
               # return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

            #elif action == 'change-pin':
                #if 'pin' in user and user['pin'] and old_pin:
                    #if not check_password_hash(user['pin'], old_pin):
                        #message = ("Old PIN is incorrect.", 'error')
                        #return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

                #if len(new_pin) != 4 or not new_pin.isdigit():
                    #message = ("New PIN must be 4 digits.", 'error')
                #elif new_pin != confirm_pin:
                   # message = ("New PIN and confirmation do not match.", 'error')
                #else:
                   # hashed_pin = generate_password_hash(new_pin)
                   # with get_db() as conn:
                    #    conn.execute("UPDATE users SET pin = ? WHERE username = ?", (hashed_pin, username))
                    #    conn.commit()
                    #message = ("PIN has been successfully created/updated.", 'success')
                   # return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)

                #return render_template('dashboard.html', username=username, message=message, unread_count=unread_count)
            #if amount <= 0:
               # message = 'Amount must be greater than 0.'
            #elif user['bank_balance'] < amount:
               # message = 'Insufficient balance for cash-out from bank.'
            #elif not bank_account_number or not bank_pin or not bank_name:
                #message = 'Bank details are required.'
            #else:
                # Process cash-out from bank
                #user['bank_balance'] -= amount
              #  with get_db() as conn:
                    #conn.execute("UPDATE users SET bank_balance = ? WHERE username = ?", (user['bank_balance'], username))
                  #  conn.commit()
               # message = f"Successfully cashed out ${amount} from your bank account ({bank_name})."

        elif action == 'messages':
            message_content = request.form.get('message', '').strip()
            if message_content:
                message = ("Message sent successfully!", 'success')
            else:
                message = ("Message can't be empty.", 'error')
        elif action == 'transfer-money':
            amount = request.form.get('amount', '').strip()
            bank_account = request.form.get('bank_account', '').strip()

            if not amount:
                message = ("Amount can't be empty.", 'error')
            elif not bank_account:
                message = ("Bank Account number can't be empty", 'error')
            else:
                try:
                    amount = float(amount)
                    if user['balance'] < amount:
                        message = ("Insufficient balance for transfer.", 'error')
                    else:
                        with get_db() as conn:
                            recipient_user = conn.execute("SELECT * FROM users WHERE username = ?", (recipient_username,)).fetchone()
                            if recipient_user:
                                user['balance'] -= amount
                                recipient_user = dict(recipient_user)
                                recipient_user['balance'] += amount
                                conn.execute("UPDATE users SET balance = ? WHERE username = ?", (user['balance'], username))
                                conn.execute("UPDATE users SET balance = ? WHERE username = ?", (recipient_user['balance'], recipient_username))
                                conn.commit()
                                message = (f"Successfully transferred ${amount} to {recipient_username}.", 'success')
                            else:
                                message = (f"Recipient username '{recipient_username}' not found.", 'error')
                except ValueError:
                    message = ("Invalid amount.", 'error')

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
            elif user['balance'] < float(amount):
                message = ("Insufficient balance to pay bills.", 'error')
            else:
                try:
                    # Insert transaction into the database
                    with get_db() as conn:
                        conn.execute("INSERT INTO transactions (username, biller, amount, account_number) VALUES (?, ?, ?, ?)",
                                     (username, biller, float(amount), account_number))
                        user['balance'] -= float(amount)  # Deduct the amount from user's balance
                        conn.execute("UPDATE users SET balance = ? WHERE username = ?", (user['balance'], username))
                        conn.commit()

                        # After successful insertion, show success message
                    message = ("Payment successfully completed.", 'success')

                except Exception as e:
                    # Log the error if there's an issue with the database
                    print(f"Error inserting transaction: {str(e)}")  # You can also use a logger
                    message = ("An error occurred while processing the payment.", 'error')

            # Update balance in database after transaction
            with get_db() as conn:
                transactions = conn.execute("SELECT biller, amount, account_number, timestamp FROM transactions WHERE username = ?", (username,)).fetchall()
                conn.execute("UPDATE users SET balance = ? WHERE username = ?", (user['balance'], username))
                conn.commit()

            return render_template('dashboard.html', username=username, action=action, message=message, biller=biller, amount=amount, account_number=account_number, transactions=transactions, unread_count=unread_count)



        elif action == 'sendmoney':
            recipient_username = request.form.get('recipient_username', '').strip()
            amount = request.form.get('amount', '').strip()

            if not recipient_username:
                message = ("Recipient username can't be empty.", 'error')
            elif not amount:
                message = ("Amount can't be empty.", 'error')
            else:
                try:
                    amount = float(amount)
                    if user['balance'] < amount:
                        message = ("Insufficient balance for Send money.", 'error')
                    else:
                        with get_db() as conn:
                            recipient_user = conn.execute("SELECT * FROM users WHERE username = ?", (recipient_username,)).fetchone()
                            if recipient_user:
                                user['balance'] -= amount
                                recipient_user = dict(recipient_user)
                                recipient_user['balance'] += amount
                                conn.execute("UPDATE users SET balance = ? WHERE username = ?", (user['balance'], username))
                                conn.execute("UPDATE users SET balance = ? WHERE username = ?", (recipient_user['balance'], recipient_username))
                                conn.commit()
                                message = (f"Successfully Send Money ${amount} to {recipient_username}.", 'success')
                            else:
                                message = (f"Recipient username '{recipient_username}' not found.", 'error')

                except ValueError:
                    message = ("Invalid amount.", 'error')

    # Fetch notifications and unread count
    with get_db() as conn:
        transactions = conn.execute("SELECT biller, amount, account_number, timestamp FROM transactions WHERE username = ?", (username,)).fetchall()
        notifications = conn.execute("SELECT title, message, timestamp FROM notifications ORDER BY timestamp DESC").fetchall()
        unread_count = conn.execute("SELECT COUNT(*) FROM notifications WHERE read = 0").fetchone()[0]

    return render_template('dashboard.html', username=username, user=user, message=message, biller=biller, amount=amount, account_number=account_number, recipient=recipient, unread_count=unread_count, notifications=notifications, action=action)


# Add Transaction Helper Function
def add_transaction(user, transaction_type, amount):
    user['transactions'].append({
        'transaction_type': transaction_type,
        'amount': amount,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

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
