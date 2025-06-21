from flask import Flask, request, escape, session
import sqlite3
import hashlib
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'medium_secret_key_123'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def init_db():
    conn = sqlite3.connect('/app/users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)')
    
    # Hash with MD5 (weak)
    admin_hash = hashlib.md5('admin123'.encode()).hexdigest()
    user_hash = hashlib.md5('user123'.encode()).hexdigest()
    
    cursor.execute(f"INSERT OR IGNORE INTO users VALUES (1, 'admin', '{admin_hash}')")
    cursor.execute(f"INSERT OR IGNORE INTO users VALUES (2, 'user', '{user_hash}')")
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return '''
    <html>
    <head><title>⚠️ Medium Security Website</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>⚠️ MEDIUM SECURITY WEBSITE (Port 5002)</h1>
        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <strong>⚠️ TINGKAT KEAMANAN: MEDIUM</strong><br>
            Beberapa proteksi dasar, tapi masih ada kerentanan
        </div>
        
        <h3>Features:</h3>
        <ul>
            <li><a href="/login">🔐 Login (Weak MD5 Hash)</a></li>
            <li><a href="/search?q=test">🔍 Search (Basic XSS Protection)</a></li>
            <li><a href="/upload">📁 File Upload (Some Validation)</a></li>
        </ul>
        
        <h4>🛡️ Protections Applied:</h4>
        <ul>
            <li>✅ Parameterized SQL queries</li>
            <li>✅ Basic HTML escaping</li>
            <li>✅ File type validation</li>
            <li>❌ Weak password hashing (MD5)</li>
            <li>❌ No CSRF protection</li>
        </ul>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Basic validation
        if len(username) > 50 or len(password) > 50:
            return "Input too long!"
        
        # BETTER: Parameterized query but weak hashing
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = sqlite3.connect('/app/users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", 
                      (username, password_hash))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            session['user'] = result[1]
            return f"<h2>✅ Welcome {result[1]}!</h2><a href='/'>Home</a>"
        else:
            return "<h2>❌ Invalid credentials!</h2><a href='/login'>Try again</a>"
    
    return '''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>🔐 Login Form (Medium Security)</h2>
        <form method="post">
            Username: <input type="text" name="username" maxlength="50" required><br><br>
            Password: <input type="password" name="password" maxlength="50" required><br><br>
            <input type="submit" value="Login">
        </form>
        <div style="background: #e7f3ff; padding: 10px; margin: 15px 0;">
            <strong>🔑 Test Account:</strong> admin / admin123
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # BETTER: Basic HTML escaping
    escaped_query = escape(query)
    
    return f'''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>🔍 Search Results (Basic Protection)</h2>
        <form method="get">
            <input type="text" name="q" value="{escaped_query}" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
        <div style="margin: 20px 0;">
            <h3>You searched for: {escaped_query}</h3>
            <p>No results found for "{escaped_query}"</p>
        </div>
        <div style="background: #e7f3ff; padding: 10px;">
            <strong>🛡️ Protection:</strong> HTML escaping applied
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file selected'
        
        file = request.files['file']
        if file.filename == '':
            return 'No file selected'
        
        # BETTER: File validation
        if not allowed_file(file.filename):
            return 'File type not allowed!'
        
        # BETTER: Secure filename
        filename = secure_filename(file.filename)
        upload_path = f"/app/uploads/{filename}"
        os.makedirs('/app/uploads', exist_ok=True)
        file.save(upload_path)
        
        return f'<h2>✅ File {filename} uploaded safely!</h2><a href="/upload">Upload more</a>'
    
    return '''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>📁 File Upload (With Validation)</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".txt,.pdf,.png,.jpg,.jpeg,.gif">
            <input type="submit" value="Upload">
        </form>
        <div style="background: #e7f3ff; padding: 10px; margin: 15px 0;">
            <strong>🛡️ Allowed:</strong> txt, pdf, png, jpg, jpeg, gif
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/health')
def health():
    return {"status": "healthy", "security": "medium"}

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)