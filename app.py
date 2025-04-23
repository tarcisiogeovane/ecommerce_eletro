from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
import sqlite3
import os
import bcrypt
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_123'  # Mude para algo único
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
Session(app)

# Criar pasta para uploads
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Função para obter caminho do banco de dados
def get_db_path():
    return os.path.join(os.path.dirname(__file__), 'database.db')

# Verificar extensão do arquivo
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Configurar banco de dados SQLite
def init_db():
    db_path = get_db_path()
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            photo_path TEXT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        # Criar usuário admin inicial
        hashed_pwd = bcrypt.hashpw('h3kq45jj'.encode('utf-8'), bcrypt.gensalt())
        c.execute('INSERT OR REPLACE INTO users (username, password, is_admin) VALUES (?, ?, 1)', 
                  ('tarcisio', hashed_pwd))
        conn.commit()
        conn.close()
    else:
        # Adicionar colunas category e photo_path se não existirem
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        try:
            c.execute('ALTER TABLE products ADD COLUMN category TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE products ADD COLUMN photo_path TEXT')
        except sqlite3.OperationalError:
            pass
        # Garantir que tarcisio é admin
        hashed_pwd = bcrypt.hashpw('h3kq45jj'.encode('utf-8'), bcrypt.gensalt())
        c.execute('UPDATE users SET is_admin = 1, password = ? WHERE username = ?', 
                  (hashed_pwd, 'tarcisio'))
        conn.commit()
        conn.close()

# Inicializar o banco
init_db()

# Página inicial (catálogo com busca e filtros)
@app.route('/', methods=['GET', 'POST'])
def home():
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Parâmetros de busca e filtros
    search_query = request.args.get('search', '')
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    
    query = 'SELECT id, title, description, price, category, photo_path FROM products WHERE 1=1'
    params = []
    
    if search_query:
        query += ' AND (title LIKE ? OR description LIKE ?)'
        params.extend([f'%{search_query}%', f'%{search_query}%'])
    
    if category:
        query += ' AND category = ?'
        params.append(category)
    
    if min_price:
        query += ' AND price >= ?'
        params.append(float(min_price))
    
    if max_price:
        query += ' AND price <= ?'
        params.append(float(max_price))
    
    c.execute(query, params)
    products = c.fetchall()
    
    # Obter categorias para o filtro
    c.execute('SELECT DISTINCT category FROM products WHERE category IS NOT NULL')
    categories = [row[0] for row in c.fetchall()]
    
    conn.close()
    return render_template('home.html', products=products, categories=categories, 
                         search_query=search_query, category=category, 
                         min_price=min_price, max_price=max_price)

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('SELECT id, password, is_admin FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
            session['user_id'] = user[0]
            session['username'] = username
            session['is_admin'] = user[2]
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha inválidos!', 'error')
    return render_template('login.html')

# Página de logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da conta.', 'success')
    return redirect(url_for('home'))

# Página de cadastro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)', 
                      (username, hashed_pwd))
            conn.commit()
            conn.close()
            flash('Cadastro realizado! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário já existe!', 'error')
    return render_template('register.html')

# Página de criar anúncio (apenas admin)
@app.route('/create_ad', methods=['GET', 'POST'])
def create_ad():
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Apenas administradores podem criar anúncios!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        user_id = session['user_id']
        photo_path = None
        
        # Processar upload de foto
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(photo_path)
                photo_path = f'uploads/{filename}'
        
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('INSERT INTO products (title, description, price, category, photo_path, user_id) VALUES (?, ?, ?, ?, ?, ?)',
                  (title, description, price, category, photo_path, user_id))
        conn.commit()
        conn.close()
        flash('Anúncio criado com sucesso!', 'success')
        return redirect(url_for('home'))
    return render_template('create_ad.html')

# Apagar anúncio (apenas admin)
@app.route('/delete_ad/<int:id>')
def delete_ad(id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Apenas administradores podem apagar anúncios!', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT photo_path FROM products WHERE id = ?', (id,))
    product = c.fetchone()
    
    # Apagar foto do sistema de arquivos, se existir
    if product and product[0]:
        photo_path = os.path.join('static', product[0])
        if os.path.exists(photo_path):
            os.remove(photo_path)
    
    c.execute('DELETE FROM products WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Anúncio apagado com sucesso!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)