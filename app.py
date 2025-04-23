from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
import sqlite3
import os
import bcrypt
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import cloudinary.api
import mercadopago

# Importar dotenv condicionalmente
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # No Render, dotenv não é necessário

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_123'  # Mude para algo único
app.config['SESSION_TYPE'] = 'filesystem'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
Session(app)

# Configurar Cloudinary
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME', 'seu_cloud_name'),
    api_key=os.environ.get('CLOUDINARY_API_KEY', 'sua_api_key'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET', 'sua_api_secret'),
    secure=True
)

# Configurar Mercado Pago
mercado_pago_sdk = mercadopago.SDK(os.environ.get('MERCADO_PAGO_ACCESS_TOKEN', 'seu_access_token'))

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
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        c.execute('''CREATE TABLE product_photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            photo_url TEXT,
            photo_public_id TEXT,
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')
        c.execute('''CREATE TABLE cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')
        # Criar usuário admin inicial
        hashed_pwd = bcrypt.hashpw('h3kq45jj'.encode('utf-8'), bcrypt.gensalt())
        c.execute('INSERT OR REPLACE INTO users (username, password, is_admin) VALUES (?, ?, 1)', 
                  ('tarcisio', hashed_pwd))
        conn.commit()
        conn.close()
    else:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        # Adicionar tabela product_photos se não existir
        try:
            c.execute('''CREATE TABLE product_photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                photo_url TEXT,
                photo_public_id TEXT,
                FOREIGN KEY (product_id) REFERENCES products (id)
            )''')
        except sqlite3.OperationalError:
            pass
        # Adicionar tabela cart se não existir
        try:
            c.execute('''CREATE TABLE cart (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                product_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (product_id) REFERENCES products (id)
            )''')
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

# Página inicial (produtos em destaque)
@app.route('/', methods=['GET'])
def home():
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Selecionar até 8 produtos com a primeira foto
    c.execute('''SELECT p.id, p.title, p.description, p.price, p.category, 
                        (SELECT photo_url FROM product_photos WHERE product_id = p.id LIMIT 1) as photo_url
                 FROM products p LIMIT 8''')
    products = c.fetchall()
    
    conn.close()
    return render_template('home.html', products=products)

# Página de busca
@app.route('/search', methods=['GET'])
def search():
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Parâmetros de busca e filtros
    search_query = request.args.get('search', '')
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    
    query = '''SELECT p.id, p.title, p.description, p.price, p.category, 
                      (SELECT photo_url FROM product_photos WHERE product_id = p.id LIMIT 1) as photo_url
               FROM products p WHERE 1=1'''
    params = []
    
    if search_query:
        query += ' AND (p.title LIKE ? OR p.description LIKE ?)'
        params.extend([f'%{search_query}%', f'%{search_query}%'])
    
    if category:
        query += ' AND p.category = ?'
        params.append(category)
    
    if min_price:
        query += ' AND p.price >= ?'
        params.append(float(min_price))
    
    if max_price:
        query += ' AND p.price <= ?'
        params.append(float(max_price))
    
    c.execute(query, params)
    products = c.fetchall()
    
    # Obter categorias para o filtro
    c.execute('SELECT DISTINCT category FROM products WHERE category IS NOT NULL')
    categories = [row[0] for row in c.fetchall()]
    
    conn.close()
    return render_template('search.html', products=products, categories=categories, 
                         search_query=search_query, category=category, 
                         min_price=min_price, max_price=max_price)

# Página de detalhes do produto
@app.route('/product/<int:id>')
def product(id):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Obter detalhes do produto
    c.execute('SELECT id, title, description, price, category FROM products WHERE id = ?', (id,))
    product = c.fetchone()
    
    if not product:
        conn.close()
        flash('Produto não encontrado!', 'error')
        return redirect(url_for('home'))
    
    # Obter todas as fotos do produto
    c.execute('SELECT photo_url, photo_public_id FROM product_photos WHERE product_id = ?', (id,))
    photos = c.fetchall()
    
    conn.close()
    return render_template('product.html', product=product, photos=photos)

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
        
        # Inserir produto
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('INSERT INTO products (title, description, price, category, user_id) VALUES (?, ?, ?, ?, ?)',
                  (title, description, price, category, user_id))
        product_id = c.lastrowid
        
        # Processar upload de até 5 fotos
        files = request.files.getlist('photos')
        for file in files[:5]:  # Limitar a 5 fotos
            if file and allowed_file(file.filename):
                upload_result = cloudinary.uploader.upload(file, folder='ecommerce_eletro')
                photo_url = upload_result['secure_url']
                photo_public_id = upload_result['public_id']
                c.execute('INSERT INTO product_photos (product_id, photo_url, photo_public_id) VALUES (?, ?, ?)',
                          (product_id, photo_url, photo_public_id))
        
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
    
    # Apagar fotos do Cloudinary
    c.execute('SELECT photo_public_id FROM product_photos WHERE product_id = ?', (id,))
    photos = c.fetchall()
    for photo in photos:
        if photo[0]:
            try:
                cloudinary.uploader.destroy(photo[0])
            except:
                pass
    
    # Apagar fotos e produto
    c.execute('DELETE FROM product_photos WHERE product_id = ?', (id,))
    c.execute('DELETE FROM products WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Anúncio apagado com sucesso!', 'success')
    return redirect(url_for('home'))

# Adicionar ao carrinho
@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if not session.get('user_id'):
        flash('Faça login para adicionar ao carrinho!', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('INSERT INTO cart (user_id, product_id) VALUES (?, ?)', 
              (session['user_id'], product_id))
    conn.commit()
    conn.close()
    flash('Produto adicionado ao carrinho!', 'success')
    return redirect(request.referrer or url_for('home'))

# Visualizar carrinho
@app.route('/cart')
def cart():
    if not session.get('user_id'):
        flash('Faça login para ver o carrinho!', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''SELECT c.id, p.title, p.description, p.price, p.category, 
                        (SELECT photo_url FROM product_photos WHERE product_id = p.id LIMIT 1) as photo_url
                 FROM cart c
                 JOIN products p ON c.product_id = p.id
                 WHERE c.user_id = ?''', (session['user_id'],))
    cart_items = c.fetchall()
    
    total = sum(item[3] for item in cart_items)
    
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total=total)

# Remover do carrinho
@app.route('/remove_from_cart/<int:cart_id>')
def remove_from_cart(cart_id):
    if not session.get('user_id'):
        flash('Faça login para gerenciar o carrinho!', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', (cart_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Produto removido do carrinho!', 'success')
    return redirect(url_for('cart'))

# Criar checkout com Mercado Pago
@app.route('/create_checkout', methods=['POST'])
def create_checkout():
    if not session.get('user_id'):
        flash('Faça login para finalizar a compra!', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''SELECT p.title, p.description, p.price
                 FROM cart c
                 JOIN products p ON c.product_id = p.id
                 WHERE c.user_id = ?''', (session['user_id'],))
    cart_items = c.fetchall()
    
    if not cart_items:
        flash('Seu carrinho está vazio!', 'error')
        return redirect(url_for('cart'))
    
    # Criar preferência de pagamento
    preference_data = {
        "items": [
            {
                "title": item[0],
                "quantity": 1,
                "unit_price": float(item[2]),
                "description": item[1]
            } for item in cart_items
        ],
        "back_urls": {
            "success": url_for('home', _external=True),
            "failure": url_for('cart', _external=True),
            "pending": url_for('cart', _external=True)
        },
        "auto_return": "approved"
    }
    
    preference_response = mercado_pago_sdk.preference().create(preference_data)
    preference = preference_response["response"]
    
    conn.close()
    return redirect(preference["init_point"])

# Página de pedidos (placeholder)
@app.route('/orders')
def orders():
    if not session.get('user_id'):
        flash('Faça login para ver seus pedidos!', 'error')
        return redirect(url_for('login'))
    return render_template('orders.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)