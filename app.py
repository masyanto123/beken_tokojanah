from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Konfigurasi JWT
app.config["JWT_SECRET_KEY"] = "kunci-rahasia-warungku-ganti-ini-ya"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
jwt = JWTManager(app)

# Koneksi Database MySQL
def get_db_connection():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="warungku",
        cursorclass=pymysql.cursors.DictCursor
    )

# ==========================================================
# 1. AUTHENTICATION (REGISTER & LOGIN)
# ==========================================================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "Nama, email, dan password wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Email sudah terdaftar!"}), 409

            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                (name, email, hashed_password)
            )
            conn.commit()

        return jsonify({"success": True, "message": "Registrasi berhasil! Silakan login."}), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email dan password wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user["password"], password):
                return jsonify({"success": False, "message": "Email atau password salah!"}), 401

            token = create_access_token(identity=str(user["id"]))

        return jsonify({
            "success": True,
            "message": "Login berhasil!",
            "token": token,
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
    user_id = get_jwt_identity()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, name, email, created_at FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "message": "User tidak ditemukan!"}), 404

        return jsonify({"success": True, "user": user}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# ==========================================================
# 2. PRODUK / BARANG (CRUD)
# ==========================================================

# Ambil Semua Produk (Bisa cari berdasarkan nama/kategori/barcode via ?search=...)
@app.route("/api/products", methods=["GET"])
@jwt_required()
def get_products():
    search = request.args.get("search", "")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if search:
                cursor.execute(
                    "SELECT * FROM products WHERE name LIKE %s OR category LIKE %s OR barcode LIKE %s ORDER BY name ASC",
                    (f"%{search}%", f"%{search}%", f"%{search}%")
                )
            else:
                cursor.execute("SELECT * FROM products ORDER BY id DESC")
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
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM products WHERE barcode = %s", (barcode,))
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
    name = data.get("name")
    barcode = data.get("barcode") or None
    category = data.get("category", "Umum")
    buy_price = data.get("buy_price", 0)
    sell_price = data.get("sell_price", 0)
    stock = data.get("stock", 0)

    if not name or sell_price is None:
        return jsonify({"success": False, "message": "Nama dan harga jual wajib diisi!"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO products (name, barcode, category, buy_price, sell_price, stock)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (name, barcode, category, buy_price, sell_price, stock)
            )
            conn.commit()
            product_id = cursor.lastrowid

        return jsonify({
            "success": True,
            "message": "Produk berhasil ditambahkan!",
            "product_id": product_id
        }), 201
    except Exception as e:
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
        with conn.cursor() as cursor:
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
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Edit Produk
@app.route("/api/products/<int:id>", methods=["PUT"])
@jwt_required()
def update_product(id):
    data = request.get_json() or {}
    name = data.get("name")
    barcode = data.get("barcode") or None
    category = data.get("category")
    buy_price = data.get("buy_price")
    sell_price = data.get("sell_price")
    stock = data.get("stock")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM products WHERE id = %s", (id,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Produk tidak ditemukan!"}), 404

            cursor.execute(
                """UPDATE products 
                   SET name = %s, barcode = %s, category = %s, buy_price = %s, sell_price = %s, stock = %s
                   WHERE id = %s""",
                (name, barcode, category, buy_price, sell_price, stock, id)
            )
            conn.commit()

        return jsonify({"success": True, "message": "Produk berhasil diperbarui!"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# Hapus Produk
@app.route("/api/products/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_product(id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM products WHERE id = %s", (id,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Produk tidak ditemukan!"}), 404

            cursor.execute("DELETE FROM products WHERE id = %s", (id,))
            conn.commit()

        return jsonify({"success": True, "message": "Produk berhasil dihapus!"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500
    finally:
        conn.close()

# ==========================================================
# 3. TRANSAKSI KASIR (CHECKOUT & RIWAYAT)
# ==========================================================

# Simpan Transaksi Penjualan (Checkout)
@app.route("/api/transactions", methods=["POST"])
@jwt_required()
def create_transaction():
    user_id = get_jwt_identity()
    data = request.get_json() or {}

    items = data.get("items", [])  # list of { product_id, quantity }
    pay_amount = float(data.get("pay_amount", 0))

    if not items:
        return jsonify({"success": False, "message": "Keranjang belanja kosong!"}), 400

    conn = get_db_connection()
    try:
        conn.begin()  # Memulai Transaction DB
        with conn.cursor() as cursor:
            total_amount = 0
            order_items = []

            # 1. Validasi produk & stok
            for item in items:
                p_id = item.get("product_id")
                qty = int(item.get("quantity", 1))

                cursor.execute("SELECT id, name, sell_price, stock FROM products WHERE id = %s FOR UPDATE", (p_id,))
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
                   VALUES (%s, %s, %s, %s, %s)""",
                (invoice_no, user_id, total_amount, pay_amount, change_amount)
            )
            trx_id = cursor.lastrowid

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

# Riwayat Transaksi
@app.route("/api/transactions", methods=["GET"])
@jwt_required()
def get_transactions():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT t.id, t.invoice_number, t.total_amount, t.pay_amount, t.change_amount, 
                          t.created_at, u.name as cashier_name
                   FROM transactions t
                   JOIN users u ON t.user_id = u.id
                   ORDER BY t.created_at DESC"""
            )
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
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT t.*, u.name as cashier_name 
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

# ==========================================================
# MENJALANKAN SERVER
# ==========================================================
if __name__ == "__main__":
    # host="0.0.0.0" agar bisa diakses oleh Emulator & HP Flutter
    app.run(host="0.0.0.0", port=5000, debug=True)
