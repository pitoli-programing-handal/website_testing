from flask import Flask, request
import sqlite3
import subprocess
import os

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('/app/users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', '12345')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return '''
    <html>
    <head><title>🚨 Vulnerable Website</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🚨 VULNERABLE WEBSITE (Port 5001)</h1>
        <div style="background: #ffe6e6; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <strong>⚠️ TINGKAT KEAMANAN: SANGAT RENTAN</strong>
        </div>
        
        <h3>Test Vulnerabilities:</h3>
        <ul>
            <li><a href="/login">🔓 SQL Injection</a></li>
            <li><a href="/search?q=test">🔍 XSS Attack</a></li>
            <li><a href="/ping">💻 Command Injection</a></li>
            <li><a href="/upload">📁 File Upload</a></li>
        </ul>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: SQL Injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        conn = sqlite3.connect('/app/users.db')
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return f"<h2>✅ Welcome {result[1]}!</h2><a href='/'>Home</a>"
            else:
                return "<h2>❌ Login failed!</h2><a href='/login'>Try again</a>"
        except Exception as e:
            return f"<h2>💥 Database error: {str(e)}</h2><a href='/login'>Back</a>"
    
    return '''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>🔓 Login Form (SQL Injection)</h2>
        <form method="post">
            Username: <input type="text" name="username"><br><br>
            Password: <input type="text" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
        <div style="background: #fff3cd; padding: 10px; margin: 15px 0;">
            <strong>💡 Try:</strong> admin' OR '1'='1' --
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: XSS
    return f'''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>🔍 Search Results (XSS Vulnerable)</h2>
        <form method="get">
            <input type="text" name="q" value="{query}" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
        <div style="margin: 20px 0;">
            <h3>You searched for: {query}</h3>
            <p>No results found for "{query}"</p>
        </div>
        <div style="background: #fff3cd; padding: 10px;">
            <strong>💡 Try:</strong> &lt;script&gt;alert('XSS')&lt;/script&gt;
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form['host']
        try:
            # VULNERABLE: Command Injection
            result = subprocess.check_output(f"ping -c 2 {host}", shell=True, text=True)
            return f'''
            <html>
            <body style="font-family: Arial; margin: 40px;">
                <h2>💻 Ping Results</h2>
                <pre>{result}</pre>
                <a href="/ping">← Back</a>
            </body>
            </html>
            '''
        except Exception as e:
            return f"Error: {str(e)}"
    
    return '''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>💻 Ping Tool (Command Injection)</h2>
        <form method="post">
            Host: <input type="text" name="host" placeholder="google.com">
            <input type="submit" value="Ping">
        </form>
        <div style="background: #fff3cd; padding: 10px; margin: 15px 0;">
            <strong>💡 Try:</strong> google.com; ls -la
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
        
        # VULNERABLE: No validation
        upload_path = f"/app/uploads/{file.filename}"
        os.makedirs('/app/uploads', exist_ok=True)
        file.save(upload_path)
        
        return f'<h2>✅ File {file.filename} uploaded!</h2><a href="/upload">Upload more</a>'
    
    return '''
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h2>📁 File Upload (No Validation)</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
        <div style="background: #fff3cd; padding: 10px; margin: 15px 0;">
            <strong>💡 Try:</strong> Upload .php, .jsp files
        </div>
        <a href="/">← Back</a>
    </body>
    </html>
    '''

@app.route('/health')
def health():
    return {"status": "healthy", "vulnerabilities": "many"}

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)