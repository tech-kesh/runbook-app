from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'wiki_runbooks.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, username, password, is_admin):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'], user_data['is_admin'])
    return None

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    conn = get_db_connection()
    pages = conn.execute('SELECT * FROM pages').fetchall()
    conn.close()
    return render_template('index.html', pages=pages)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_page():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = get_db_connection()
        conn.execute('INSERT INTO pages (title, content) VALUES (?, ?)', (title, content))
        conn.commit()
        conn.close()
        flash('Page created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('create_page.html')


@app.route('/page/<int:page_id>', methods=['GET', 'POST'])
def view_page(page_id):
    conn = get_db_connection()
    page = conn.execute('SELECT * FROM pages WHERE id = ?', (page_id,)).fetchone()
    conn.close()

    if page is None:
        flash('Page not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'delete' in request.form:
            if current_user.is_authenticated and current_user.is_admin:
                conn = get_db_connection()
                conn.execute('DELETE FROM pages WHERE id = ?', (page_id,))
                conn.commit()
                conn.close()
                flash('Page deleted successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('You do not have permission to delete this page.', 'error')
        elif 'edit' in request.form:
            return redirect(url_for('edit_page', page_id=page_id))

    return render_template('view_page.html', page=page)


@app.route('/edit/<int:page_id>', methods=['GET', 'POST'])
@login_required
def edit_page(page_id):
    conn = get_db_connection()
    page = conn.execute('SELECT * FROM pages WHERE id = ?', (page_id,)).fetchone()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn.execute('UPDATE pages SET title = ?, content = ? WHERE id = ?', (title, content, page_id))
        conn.commit()
        conn.close()
        flash('Page updated successfully!', 'success')
        return redirect(url_for('view_page', page_id=page_id))

    conn.close()
    return render_template('edit_page.html', page=page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'], user['password'], user['is_admin'])
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form

        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Username already exists.', 'error')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                         (username, hashed_password, is_admin))
            conn.commit()
            conn.close()
            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            conn.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            conn.close()
            flash('Password reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')
    
    return render_template('password_reset.html')

@app.route('/view_users')
@login_required
def view_users():
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('view_users.html', users=users)

if __name__ == '__main__':
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL
        )
    ''')
    conn.close()
    app.run(debug=True)
