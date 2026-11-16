import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras

app = Flask(__name__)
CORS(app)

# Konfigurasi JWT
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "kunci-rahasia-warungku-ganti-ini-ya")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
jwt = JWTManager(app)

# Neon PostgreSQL Connection URL
DEFAULT_DATABASE_URL = "postgresql://neondb_owner:npg_DgcoiLG4jk3p@ep-super-heart-azcpq2rt-pooler.c-3.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def get_db_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# ==========================================================
# 0. DATABASE SCHEMA INITIALIZATION (POSTGRESQL)
# ==========================================================
def init_all_tables():
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(150) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS categories (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS products (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(150) NOT NULL,
                    barcode VARCHAR(100),
                    category VARCHAR(100) DEFAULT 'Umum',
                    buy_price NUMERIC(12, 2) DEFAULT 0,
                    sell_price NUMERIC(12, 2) NOT NULL,
                    stock INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_deleted BOOLEAN DEFAULT FALSE
                );

                CREATE TABLE IF NOT EXISTS transactions (
                    id SERIAL PRIMARY KEY,
                    invoice_number VARCHAR(50) NOT NULL UNIQUE,
                    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    total_amount NUMERIC(12, 2) NOT NULL,
                    pay_amount NUMERIC(12, 2) NOT NULL,
                    change_amount NUMERIC(12, 2) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS transaction_items (
                    id SERIAL PRIMARY KEY,
                    transaction_id INT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
                    product_id INT REFERENCES products(id) ON DELETE SET NULL,
                    product_name VARCHAR(150) NOT NULL,
                    price NUMERIC(12, 2) NOT NULL,
                    quantity INT NOT NULL,
                    subtotal NUMERIC(12, 2) NOT NULL
                );

                CREATE TABLE IF NOT EXISTS store_info (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    description TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
    except Exception as e:
        conn.rollback()
        print("Error initializing PostgreSQL schema:", e)
    finally:
        conn.close()

# ==========================================================
# 1. AUTHENTICATION (REGISTER & LOGIN)
# ==========================================================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "Nama, email, dan password wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Email sudah terdaftar!"}), 409

            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (%s, %s, %s) RETURNING id",
                (name, email, hashed_password)
            )
            conn.commit()

        return jsonify({"success": True, "message": "Registrasi berhasil! Silakan login."}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email dan password wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user["password"], password):
                return jsonify({"success": False, "message": "Email atau password salah!"}), 401

            access_token = create_access_token(identity=str(user["id"]))

        return jsonify({
            "success": True,
            "message": "Login berhasil!",
            "token": access_token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"]
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = int(get_jwt_identity())
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id, name, email, created_at FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "message": "User tidak ditemukan!"}), 404

        return jsonify({"success": True, "user": user}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Ubah Kata Sandi
@app.route("/api/change-password", methods=["POST"])
@jwt_required()
def change_password():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"success": False, "message": "Kata sandi lama dan kata sandi baru wajib diisi!"}), 400

    if len(new_password) < 6:
        return jsonify({"success": False, "message": "Kata sandi baru minimal 6 karakter!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id, password FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "message": "Pengguna tidak ditemukan!"}), 404

            if not check_password_hash(user["password"], old_password):
                return jsonify({"success": False, "message": "Kata sandi saat ini tidak sesuai!"}), 400

            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
            conn.commit()

        return jsonify({"success": True, "message": "Kata sandi berhasil diperbarui!"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Ambil Informasi Toko (Hanya Deskripsi)
@app.route("/api/store-info", methods=["GET"])
@jwt_required()
def get_store_info():
    user_id = int(get_jwt_identity())
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT description FROM store_info WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
            row = cursor.fetchone()
            description = row["description"] if row and row.get("description") else ""

        return jsonify({"success": True, "data": {"description": description}}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Simpan / Perbarui Informasi Toko (Hanya Deskripsi)
@app.route("/api/store-info", methods=["POST", "PUT"])
@jwt_required()
def save_store_info():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    description = (data.get("description") or "").strip()

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id FROM store_info WHERE user_id = %s", (user_id,))
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE store_info SET description = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                    (description, user_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO store_info (user_id, description) VALUES (%s, %s)",
                    (user_id, description)
                )
            conn.commit()

        return jsonify({
            "success": True,
            "message": "Informasi toko berhasil disimpan!",
            "data": {"description": description}
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# ==========================================================
# 2. KATEGORI PRODUK (CRUD)
# ==========================================================

DEFAULT_PRODUCT_CATEGORIES = [
    "Sembako & Bahan Pokok",
    "Bumbu Dapur & Penyedap",
    "Rokok & Korek Api",
    "Minuman",
    "Makanan Ringan & Roti Kemasan",
    "Perawatan Diri",
    "Kebersihan Rumah Tangga",
    "Kebutuhan Bayi & Anak",
    "Obat-obatan Bebas & P3K",
    "Kosmetik & Skincare Dasar",
    "ATK, Listrik & Kebutuhan Harian",
    "Produk Segar",
    "Daging, Ayam & Hasil Laut",
    "Makanan Dingin & Beku",
    "Roti Segar & Kue",
    "Peralatan Rumah Tangga & Non-Pangan",
    "Lainnya",
]

def init_categories_table(cursor):
    cursor.execute("SELECT COUNT(*) as cnt FROM categories")
    row = cursor.fetchone()
    if row and row.get("cnt", 0) == 0:
        for cat in DEFAULT_PRODUCT_CATEGORIES:
            try:
                cursor.execute("INSERT INTO categories (name) VALUES (%s) ON CONFLICT (name) DO NOTHING", (cat,))
            except Exception:
                pass

@app.route("/api/categories", methods=["GET"])
@jwt_required()
def get_categories():
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            init_categories_table(cursor)
            conn.commit()
            cursor.execute("SELECT id, name FROM categories ORDER BY id ASC")
            cats = cursor.fetchall()
        return jsonify({"success": True, "data": cats}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/api/categories", methods=["POST"])
@jwt_required()
def add_category():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "message": "Nama kategori wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id FROM categories WHERE name = %s", (name,))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Kategori sudah ada!"}), 409

            cursor.execute("INSERT INTO categories (name) VALUES (%s) RETURNING id", (name,))
            cat_id = cursor.fetchone()["id"]
            conn.commit()

        return jsonify({
            "success": True,
            "message": "Kategori berhasil ditambahkan!",
            "data": {"id": cat_id, "name": name}
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/api/categories/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_category(id):
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id, name FROM categories WHERE id = %s", (id,))
            cat = cursor.fetchone()
            if not cat:
                return jsonify({"success": False, "message": "Kategori tidak ditemukan!"}), 404

            cat_name = cat["name"]
            cursor.execute(
                "UPDATE products SET category = 'Lainnya' WHERE category = %s",
                (cat_name,)
            )
            cursor.execute("DELETE FROM categories WHERE id = %s", (id,))
            conn.commit()
        return jsonify({
            "success": True,
            "message": f"Kategori '{cat_name}' berhasil dihapus!"
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# ==========================================================
# 3. PRODUK / BARANG (CRUD)
# ==========================================================

@app.route("/api/products", methods=["GET"])
@jwt_required()
def get_products():
    search = request.args.get("search", "").strip()
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cond = "AND (is_deleted = FALSE OR is_deleted IS NULL)"
            where_base = "WHERE (is_deleted = FALSE OR is_deleted IS NULL)"

            if search:
                cursor.execute(
                    f"SELECT * FROM products WHERE (name ILIKE %s OR category ILIKE %s OR barcode ILIKE %s) {cond} ORDER BY name ASC",
                    (f"%{search}%", f"%{search}%", f"%{search}%")
                )
            else:
                cursor.execute(f"SELECT * FROM products {where_base} ORDER BY id DESC")
            products = cursor.fetchall()

        return jsonify({"success": True, "data": products}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Cari Produk Berdasarkan Barcode
@app.route("/api/products/barcode/<string:barcode>", methods=["GET"])
@jwt_required()
def get_product_by_barcode(barcode):
    barcode = (barcode or "").strip()
    if not barcode:
        return jsonify({"success": False, "message": "Barcode tidak valid!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cond = "AND (is_deleted = FALSE OR is_deleted IS NULL)"
            # Pencocokan fleksibel: exact trim, atau padding 13 digit (EAN-13 vs UPC 12 digit)
            cursor.execute(
                f"""SELECT * FROM products 
                    WHERE (
                        TRIM(barcode) = %s 
                        OR LPAD(TRIM(barcode), 13, '0') = LPAD(%s, 13, '0')
                    ) {cond}
                    LIMIT 1""",
                (barcode, barcode)
            )
            product = cursor.fetchone()

        if not product:
            return jsonify({"success": False, "message": "Produk dengan barcode ini belum terdaftar."}), 404

        return jsonify({"success": True, "data": product}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Tambah Produk Baru
@app.route("/api/products", methods=["POST"])
@jwt_required()
def add_product():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    barcode_raw = data.get("barcode")
    barcode = str(barcode_raw).strip() if barcode_raw is not None and str(barcode_raw).strip() else None
    category = data.get("category", "Umum")
    buy_price = data.get("buy_price", 0)
    sell_price = data.get("sell_price", 0)
    stock = data.get("stock", 0)

    if not name or sell_price is None:
        return jsonify({"success": False, "message": "Nama dan harga jual wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute(
                """INSERT INTO products (name, barcode, category, buy_price, sell_price, stock)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (name, barcode, category, buy_price, sell_price, stock)
            )
            product_id = cursor.fetchone()["id"]
            conn.commit()

        return jsonify({
            "success": True,
            "message": "Produk berhasil ditambahkan!",
            "product_id": product_id
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Tambah Stok Produk (Restock via Barcode / ID)
@app.route("/api/products/<int:id>/add-stock", methods=["POST"])
@jwt_required()
def add_product_stock(id):
    data = request.get_json() or {}
    additional_stock = int(data.get("additional_stock", 0))

    if additional_stock <= 0:
        return jsonify({"success": False, "message": "Jumlah tambahan stok harus lebih dari 0!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id, name, stock FROM products WHERE id = %s", (id,))
            product = cursor.fetchone()
            if not product:
                return jsonify({"success": False, "message": "Produk tidak ditemukan!"}), 404

            new_stock = product["stock"] + additional_stock
            cursor.execute("UPDATE products SET stock = %s WHERE id = %s", (new_stock, id))
            conn.commit()

        return jsonify({
            "success": True,
            "message": f"Stok '{product['name']}' berhasil ditambah +{additional_stock} (Total sekarang: {new_stock})",
            "new_stock": new_stock
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Edit Produk
@app.route("/api/products/<int:id>", methods=["PUT"])
@jwt_required()
def update_product(id):
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    barcode_raw = data.get("barcode")
    barcode = str(barcode_raw).strip() if barcode_raw is not None and str(barcode_raw).strip() else None
    category = data.get("category")
    buy_price = data.get("buy_price")
    sell_price = data.get("sell_price")
    stock = data.get("stock")

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id FROM products WHERE id = %s", (id,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Produk tidak ditemukan!"}), 404

            cursor.execute(
                """UPDATE products 
                   SET name = %s, barcode = %s, category = %s, buy_price = %s, sell_price = %s, stock = %s, updated_at = CURRENT_TIMESTAMP
                   WHERE id = %s""",
                (name, barcode, category, buy_price, sell_price, stock, id)
            )
            conn.commit()

        return jsonify({"success": True, "message": "Produk berhasil diperbarui!"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Hapus Produk
@app.route("/api/products/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_product(id):
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute("SELECT id, name FROM products WHERE id = %s", (id,))
            prod = cursor.fetchone()
            if not prod:
                return jsonify({"success": False, "message": "Produk tidak ditemukan!"}), 404

            cursor.execute("SELECT id FROM transaction_items WHERE product_id = %s LIMIT 1", (id,))
            has_transactions = cursor.fetchone() is not None

            if has_transactions:
                cursor.execute(
                    "UPDATE products SET is_deleted = TRUE, barcode = NULL WHERE id = %s",
                    (id,)
                )
                conn.commit()
                return jsonify({
                    "success": True,
                    "message": f"Produk '{prod['name']}' berhasil dihapus dari daftar stok!"
                }), 200
            else:
                cursor.execute("DELETE FROM products WHERE id = %s", (id,))
                conn.commit()
                return jsonify({
                    "success": True,
                    "message": f"Produk '{prod['name']}' berhasil dihapus permanen!"
                }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# ==========================================================
# 4. TRANSAKSI KASIR (CHECKOUT & RIWAYAT)
# ==========================================================

# Simpan Transaksi Penjualan (Checkout)
@app.route("/api/transactions", methods=["POST"])
@jwt_required()
def create_transaction():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}

    items = data.get("items", [])
    pay_amount = float(data.get("pay_amount", 0))

    if not items:
        return jsonify({"success": False, "message": "Keranjang belanja kosong!"}), 400

    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            total_amount = 0
            order_items = []

            # 1. Validasi produk & stok
            for item in items:
                p_id = item.get("product_id")
                qty = int(item.get("quantity", 1))

                cursor.execute(
                    "SELECT id, name, sell_price, stock FROM products WHERE id = %s AND (is_deleted = FALSE OR is_deleted IS NULL) FOR UPDATE",
                    (p_id,)
                )
                prod = cursor.fetchone()

                if not prod:
                    conn.rollback()
                    return jsonify({"success": False, "message": f"Produk dengan ID {p_id} tidak ditemukan!"}), 404

                if prod["stock"] < qty:
                    conn.rollback()
                    return jsonify({"success": False, "message": f"Stok '{prod['name']}' tidak cukup! Sisa: {prod['stock']}"}), 400

                subtotal = float(prod["sell_price"]) * qty
                total_amount += subtotal

                order_items.append({
                    "product_id": prod["id"],
                    "product_name": prod["name"],
                    "price": prod["sell_price"],
                    "quantity": qty,
                    "subtotal": subtotal
                })

            if pay_amount < total_amount:
                conn.rollback()
                return jsonify({
                    "success": False,
                    "message": f"Uang bayar kurang! Total: {total_amount}, Dibayar: {pay_amount}"
                }), 400

            change_amount = pay_amount - total_amount
            invoice_no = "TRX-" + datetime.now().strftime("%Y%m%d%H%M%S")

            # 2. Simpan Header Transaksi
            cursor.execute(
                """INSERT INTO transactions (invoice_number, user_id, total_amount, pay_amount, change_amount)
                   VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                (invoice_no, user_id, total_amount, pay_amount, change_amount)
            )
            trx_id = cursor.fetchone()["id"]

            # 3. Simpan Detail Item & Kurangi Stok
            for item in order_items:
                cursor.execute(
                    """INSERT INTO transaction_items (transaction_id, product_id, product_name, price, quantity, subtotal)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (trx_id, item["product_id"], item["product_name"], item["price"], item["quantity"], item["subtotal"])
                )
                cursor.execute(
                    "UPDATE products SET stock = stock - %s WHERE id = %s",
                    (item["quantity"], item["product_id"])
                )

            conn.commit()

        return jsonify({
            "success": True,
            "message": "Transaksi berhasil disimpan!",
            "data": {
                "invoice_number": invoice_no,
                "total_amount": total_amount,
                "pay_amount": pay_amount,
                "change_amount": change_amount
            }
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Riwayat Transaksi (bisa filter per user via ?user_id=...)
@app.route("/api/transactions", methods=["GET"])
@jwt_required()
def get_transactions():
    user_id_param = request.args.get("user_id")
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            query = """SELECT t.id, t.invoice_number, t.user_id, t.total_amount, t.pay_amount, t.change_amount, 
                              t.created_at, u.name as cashier_name, u.email as cashier_email
                       FROM transactions t
                       JOIN users u ON t.user_id = u.id"""
            params = []
            if user_id_param:
                query += " WHERE t.user_id = %s"
                params.append(user_id_param)

            query += " ORDER BY t.created_at DESC"
            cursor.execute(query, tuple(params))
            transactions = cursor.fetchall()

        return jsonify({"success": True, "data": transactions}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Detail Satu Transaksi
@app.route("/api/transactions/<int:id>", methods=["GET"])
@jwt_required()
def get_transaction_detail(id):
    conn = get_db_connection()
    try:
        with get_db_cursor(conn) as cursor:
            cursor.execute(
                """SELECT t.*, u.name as cashier_name, u.email as cashier_email 
                   FROM transactions t 
                   JOIN users u ON t.user_id = u.id 
                   WHERE t.id = %s""", (id,)
            )
            trx = cursor.fetchone()
            if not trx:
                return jsonify({"success": False, "message": "Transaksi tidak ditemukan!"}), 404

            cursor.execute("SELECT * FROM transaction_items WHERE transaction_id = %s", (id,))
            trx["items"] = cursor.fetchall()

        return jsonify({"success": True, "data": trx}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Inisialisasi skema tabel otomatis saat aplikasi start
try:
    init_all_tables()
except Exception as e:
    print("Warning on startup init_all_tables:", e)

# ==========================================================
# MENJALANKAN SERVER
# ==========================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
