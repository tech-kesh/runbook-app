from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

DATABASE = 'wiki_runbooks.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    pages = conn.execute('SELECT * FROM pages').fetchall()
    conn.close()
    return render_template('index.html', pages=pages)

@app.route('/create', methods=['GET', 'POST'])
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

    if request.method == 'POST':
        if 'delete' in request.form:
            conn = get_db_connection()
            conn.execute('DELETE FROM pages WHERE id = ?', (page_id,))
            conn.commit()
            conn.close()
            flash('Page deleted successfully!', 'success')
            return redirect(url_for('index'))
        elif 'edit' in request.form:
            return redirect(url_for('edit_page', page_id=page_id))

    return render_template('view_page.html', page={'title': page['title'], 'content': page['content']})

@app.route('/edit/<int:page_id>', methods=['GET', 'POST'])
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    ''')
    conn.close()
    app.run(debug=True)

    
    
