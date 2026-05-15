from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, bcrypt, jwt, os, uuid
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='public')
CORS(app)

SECRET = os.environ.get('JWT_SECRET', 'lumere_secret_2025')
DB = os.environ.get('DB_PATH', 'database/lumere.db')

# ── BANCO DE DADOS ──────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('database', exist_ok=True)
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        brand TEXT DEFAULT 'lumére',
        category TEXT NOT NULL,
        price REAL NOT NULL,
        original_price REAL,
        description TEXT,
        badge TEXT,
        stock INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS cart_items (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        quantity INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        total REAL NOT NULL,
        status TEXT DEFAULT 'pendente',
        address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS order_items (
        id TEXT PRIMARY KEY,
        order_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        product_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS appointments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        service TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        notes TEXT,
        status TEXT DEFAULT 'confirmado',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Admin padrão
    admin_id = str(uuid.uuid4())
    hashed = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
    c.execute("INSERT OR IGNORE INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)",
              (admin_id, 'Admin', 'admin@lumere.com', hashed, 'admin'))

    # Produtos de exemplo
    produtos = [
        (str(uuid.uuid4()), 'Sérum Vitamina C Iluminador', 'lumére', 'skincare', 189.0, 220.0, 'Sérum com vitamina C pura para iluminar e uniformizar o tom da pele.', 'novo', 15),
        (str(uuid.uuid4()), 'Hidratante Facial Rosa Mosqueta', 'lumére', 'skincare', 145.0, None, 'Hidratante com óleo de rosa mosqueta para regeneração celular intensa.', None, 20),
        (str(uuid.uuid4()), 'Máscara Noturna Regeneradora', 'lumére', 'skincare', 212.0, 265.0, 'Máscara de dormir com retinol e peptídeos para renovação da pele.', '-20%', 8),
        (str(uuid.uuid4()), 'Kit Ritual Skincare Completo', 'lumére', 'kits', 390.0, 480.0, 'Kit completo com sérum, hidratante, máscara e protetor solar.', 'kit', 5),
        (str(uuid.uuid4()), 'Base Matte Cobertura Total', 'lumére', 'maquiagem', 98.0, None, 'Base de longa duração com cobertura total e acabamento matte.', None, 25),
        (str(uuid.uuid4()), 'Perfume Floral Lumière', 'lumére', 'perfumes', 320.0, None, 'Fragrância floral com notas de rosa, jasmim e baunilha.', 'exclusivo', 10),
    ]
    c.executemany("INSERT OR IGNORE INTO products (id, name, brand, category, price, original_price, description, badge, stock) VALUES (?,?,?,?,?,?,?,?,?)", produtos)

    conn.commit()
    conn.close()
    print("✅ Banco de dados inicializado")

# ── AUTENTICAÇÃO ────────────────────────────────────────────

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token necessário'}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=['HS256'])
            request.user = data
        except Exception as e:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token necessário'}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=['HS256'])
            if data.get('role') != 'admin':
                return jsonify({'error': 'Acesso negado'}), 403
            request.user = data
        except:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

# ── ROTAS AUTH ──────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    d = request.json
    if not d or not d.get('name') or not d.get('email') or not d.get('password'):
        return jsonify({'error': 'Preencha todos os campos'}), 400
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE email=?', (d['email'],)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'E-mail já cadastrado'}), 409
    hashed = bcrypt.hashpw(d['password'].encode(), bcrypt.gensalt()).decode()
    uid = str(uuid.uuid4())
    conn.execute('INSERT INTO users (id,name,email,password) VALUES (?,?,?,?)',
                 (uid, d['name'], d['email'], hashed))
    conn.commit()
    conn.close()
    token = jwt.encode({'id': uid, 'name': d['name'], 'email': d['email'], 'role': 'user',
                        'exp': datetime.utcnow() + timedelta(days=7)}, SECRET, algorithm='HS256')
    return jsonify({'token': token, 'user': {'id': uid, 'name': d['name'], 'email': d['email'], 'role': 'user'}}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.json
    if not d or not d.get('email') or not d.get('password'):
        return jsonify({'error': 'Preencha todos os campos'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email=?', (d['email'],)).fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(d['password'].encode(), user['password'].encode()):
        return jsonify({'error': 'E-mail ou senha incorretos'}), 401
    token = jwt.encode({'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role'],
                        'exp': datetime.utcnow() + timedelta(days=7)}, SECRET, algorithm='HS256')
    return jsonify({'token': token, 'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']}})

@app.route('/api/auth/me', methods=['GET'])
@token_required
def me():
    conn = get_db()
    user = conn.execute('SELECT id,name,email,role,created_at FROM users WHERE id=?', (request.user['id'],)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    return jsonify(dict(user))

# ── ROTAS PRODUTOS ──────────────────────────────────────────

@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category')
    conn = get_db()
    if category:
        rows = conn.execute('SELECT * FROM products WHERE active=1 AND category=? ORDER BY created_at DESC', (category,)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM products WHERE active=1 ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/products/<pid>', methods=['GET'])
def get_product(pid):
    conn = get_db()
    row = conn.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Produto não encontrado'}), 404
    return jsonify(dict(row))

@app.route('/api/products', methods=['POST'])
@admin_required
def create_product():
    d = request.json
    if not d or not d.get('name') or not d.get('category') or not d.get('price'):
        return jsonify({'error': 'Campos obrigatórios: name, category, price'}), 400
    pid = str(uuid.uuid4())
    conn = get_db()
    conn.execute('INSERT INTO products (id,name,brand,category,price,original_price,description,badge,stock) VALUES (?,?,?,?,?,?,?,?,?)',
                 (pid, d['name'], d.get('brand','lumére'), d['category'], float(d['price']),
                  float(d['original_price']) if d.get('original_price') else None,
                  d.get('description'), d.get('badge'), int(d.get('stock', 0))))
    conn.commit()
    row = conn.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201

@app.route('/api/products/<pid>', methods=['PUT'])
@admin_required
def update_product(pid):
    d = request.json
    conn = get_db()
    conn.execute('''UPDATE products SET name=?,brand=?,category=?,price=?,original_price=?,
                    description=?,badge=?,stock=?,active=? WHERE id=?''',
                 (d['name'], d.get('brand','lumére'), d['category'], float(d['price']),
                  float(d['original_price']) if d.get('original_price') else None,
                  d.get('description'), d.get('badge'), int(d.get('stock',0)),
                  int(d.get('active',1)), pid))
    conn.commit()
    row = conn.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
    conn.close()
    return jsonify(dict(row))

@app.route('/api/products/<pid>', methods=['DELETE'])
@admin_required
def delete_product(pid):
    conn = get_db()
    conn.execute('UPDATE products SET active=0 WHERE id=?', (pid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── ROTAS CARRINHO ──────────────────────────────────────────

@app.route('/api/cart', methods=['GET'])
@token_required
def get_cart():
    conn = get_db()
    rows = conn.execute('''
        SELECT ci.id, ci.quantity, p.id as product_id, p.name, p.price, p.brand, p.badge
        FROM cart_items ci JOIN products p ON ci.product_id=p.id
        WHERE ci.user_id=?
    ''', (request.user['id'],)).fetchall()
    conn.close()
    items = [dict(r) for r in rows]
    total = sum(i['price'] * i['quantity'] for i in items)
    return jsonify({'items': items, 'total': round(total, 2)})

@app.route('/api/cart', methods=['POST'])
@token_required
def add_to_cart():
    d = request.json
    pid = d.get('product_id')
    qty = int(d.get('quantity', 1))
    conn = get_db()
    existing = conn.execute('SELECT id, quantity FROM cart_items WHERE user_id=? AND product_id=?',
                            (request.user['id'], pid)).fetchone()
    if existing:
        conn.execute('UPDATE cart_items SET quantity=? WHERE id=?', (existing['quantity'] + qty, existing['id']))
    else:
        conn.execute('INSERT INTO cart_items (id,user_id,product_id,quantity) VALUES (?,?,?,?)',
                     (str(uuid.uuid4()), request.user['id'], pid, qty))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/cart/<item_id>', methods=['PUT'])
@token_required
def update_cart(item_id):
    d = request.json
    qty = int(d.get('quantity', 1))
    conn = get_db()
    if qty <= 0:
        conn.execute('DELETE FROM cart_items WHERE id=? AND user_id=?', (item_id, request.user['id']))
    else:
        conn.execute('UPDATE cart_items SET quantity=? WHERE id=? AND user_id=?', (qty, item_id, request.user['id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/cart/<item_id>', methods=['DELETE'])
@token_required
def remove_from_cart(item_id):
    conn = get_db()
    conn.execute('DELETE FROM cart_items WHERE id=? AND user_id=?', (item_id, request.user['id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/cart/checkout', methods=['POST'])
@token_required
def checkout():
    d = request.json
    conn = get_db()
    items = conn.execute('''
        SELECT ci.quantity, p.id as product_id, p.name, p.price
        FROM cart_items ci JOIN products p ON ci.product_id=p.id
        WHERE ci.user_id=?
    ''', (request.user['id'],)).fetchall()
    if not items:
        conn.close()
        return jsonify({'error': 'Carrinho vazio'}), 400
    total = sum(i['price'] * i['quantity'] for i in items)
    oid = str(uuid.uuid4())
    conn.execute('INSERT INTO orders (id,user_id,total,address) VALUES (?,?,?,?)',
                 (oid, request.user['id'], round(total,2), d.get('address','')))
    for i in items:
        conn.execute('INSERT INTO order_items (id,order_id,product_id,product_name,quantity,price) VALUES (?,?,?,?,?,?)',
                     (str(uuid.uuid4()), oid, i['product_id'], i['name'], i['quantity'], i['price']))
    conn.execute('DELETE FROM cart_items WHERE user_id=?', (request.user['id'],))
    conn.commit()
    conn.close()
    return jsonify({'order_id': oid, 'total': round(total,2)}), 201

# ── ROTAS PEDIDOS ───────────────────────────────────────────

@app.route('/api/orders', methods=['GET'])
@token_required
def get_orders():
    conn = get_db()
    if request.user['role'] == 'admin':
        orders = conn.execute('''SELECT o.*, u.name as user_name, u.email as user_email
                                 FROM orders o JOIN users u ON o.user_id=u.id
                                 ORDER BY o.created_at DESC''').fetchall()
    else:
        orders = conn.execute('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC',
                              (request.user['id'],)).fetchall()
    result = []
    for o in orders:
        od = dict(o)
        items = conn.execute('SELECT * FROM order_items WHERE order_id=?', (o['id'],)).fetchall()
        od['items'] = [dict(i) for i in items]
        result.append(od)
    conn.close()
    return jsonify(result)

@app.route('/api/orders/<oid>/status', methods=['PUT'])
@admin_required
def update_order_status(oid):
    d = request.json
    conn = get_db()
    conn.execute('UPDATE orders SET status=? WHERE id=?', (d['status'], oid))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── ROTAS AGENDAMENTOS ──────────────────────────────────────

@app.route('/api/appointments', methods=['GET'])
@token_required
def get_appointments():
    conn = get_db()
    if request.user['role'] == 'admin':
        rows = conn.execute('''SELECT a.*, u.name as user_name, u.email as user_email
                               FROM appointments a JOIN users u ON a.user_id=u.id
                               ORDER BY a.date DESC, a.time DESC''').fetchall()
    else:
        rows = conn.execute('SELECT * FROM appointments WHERE user_id=? ORDER BY date DESC, time DESC',
                            (request.user['id'],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/appointments', methods=['POST'])
@token_required
def create_appointment():
    d = request.json
    if not d or not d.get('service') or not d.get('date') or not d.get('time'):
        return jsonify({'error': 'Preencha serviço, data e horário'}), 400
    aid = str(uuid.uuid4())
    conn = get_db()
    conn.execute('INSERT INTO appointments (id,user_id,service,date,time,notes) VALUES (?,?,?,?,?,?)',
                 (aid, request.user['id'], d['service'], d['date'], d['time'], d.get('notes','')))
    conn.commit()
    row = conn.execute('SELECT * FROM appointments WHERE id=?', (aid,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201

@app.route('/api/appointments/<aid>', methods=['DELETE'])
@token_required
def cancel_appointment(aid):
    conn = get_db()
    conn.execute('UPDATE appointments SET status=? WHERE id=? AND user_id=?',
                 ('cancelado', aid, request.user['id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/appointments/<aid>/status', methods=['PUT'])
@admin_required
def update_appointment_status(aid):
    d = request.json
    conn = get_db()
    conn.execute('UPDATE appointments SET status=? WHERE id=?', (d['status'], aid))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── ROTAS ADMIN ─────────────────────────────────────────────

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    conn = get_db()
    users = conn.execute('SELECT COUNT(*) as n FROM users WHERE role=?', ('user',)).fetchone()['n']
    products = conn.execute('SELECT COUNT(*) as n FROM products WHERE active=1').fetchone()['n']
    orders = conn.execute('SELECT COUNT(*) as n FROM orders').fetchone()['n']
    revenue = conn.execute("SELECT COALESCE(SUM(total),0) as s FROM orders WHERE status!='cancelado'").fetchone()['s']
    appointments = conn.execute('SELECT COUNT(*) as n FROM appointments').fetchone()['n']
    conn.close()
    return jsonify({'users': users, 'products': products, 'orders': orders,
                    'revenue': round(revenue, 2), 'appointments': appointments})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_users():
    conn = get_db()
    rows = conn.execute('SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── SERVIR FRONTEND ─────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('public', path)

# ── INICIAR ─────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print(f"🌸 lumére rodando na porta {port}")
    print("👤 Admin: admin@lumere.com / admin123")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(debug=debug, host="0.0.0.0", port=port)
