"""
Climax Lounge Makindye — Secure Flask API
==========================================
Database : PostgreSQL (Railway) — orders persist forever
Security : API key auth, rate limiting, input validation, CORS
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
from functools import wraps
from collections import defaultdict
import json, uuid, os, time, re

# PostgreSQL driver
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────

API_KEY      = os.environ.get("API_SECRET_KEY", "climax-secret-2025")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# CORS — open to all origins, security via API key
CORS(app, resources={r"/api/*": {
    "origins": "*",
    "allow_headers": ["Content-Type", "X-API-Key"],
    "methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
}})

# ─────────────────────────────────────────
# DATABASE — PostgreSQL
# ─────────────────────────────────────────

def get_db():
    """Open a PostgreSQL connection."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    """Create the orders table if it doesn't exist."""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id          TEXT PRIMARY KEY,
            table_name  TEXT,
            table_num   INTEGER,
            customer    TEXT,
            note        TEXT DEFAULT '',
            items       TEXT,
            total       INTEGER DEFAULT 0,
            status      TEXT DEFAULT 'pending',
            created_at  TEXT
        )
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("  Database ready (PostgreSQL)")

def row_to_dict(row):
    """Convert a DB row to a plain dict, parsing items JSON."""
    d = dict(row)
    try:
        d["items"] = json.loads(d.get("items") or "[]")
    except Exception:
        d["items"] = []
    return d

# ─────────────────────────────────────────
# SECURITY — API KEY
# ─────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("apikey")
        if not key or key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────
# SECURITY — RATE LIMITING
# ─────────────────────────────────────────

request_counts = defaultdict(list)

def rate_limit(max_per_minute=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip  = request.remote_addr or "unknown"
            now = time.time()
            request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
            if len(request_counts[ip]) >= max_per_minute:
                return jsonify({"error": "Too many requests. Slow down."}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─────────────────────────────────────────
# SECURITY — INPUT VALIDATION
# ─────────────────────────────────────────

def sanitise(text, max_len=200):
    if not isinstance(text, str):
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[^\w\s\.,\-\'\"!?#@+:/()]', '', text)
    return text.strip()[:max_len]

def validate_order(data):
    if not isinstance(data, dict):
        return False, "Invalid request body"
    table_num = data.get("table_num")
    if not isinstance(table_num, int) or not (1 <= table_num <= 20):
        return False, "table_num must be between 1 and 20"
    customer = data.get("customer", "").strip()
    if not customer:
        return False, "customer name is required"
    items = data.get("items", [])
    if not isinstance(items, list) or len(items) == 0:
        return False, "items cannot be empty"
    if len(items) > 30:
        return False, "too many items in one order"
    for item in items:
        if not isinstance(item, dict):
            return False, "invalid item format"
        if not item.get("name"):
            return False, "each item must have a name"
        price = item.get("price", 0)
        qty   = item.get("qty", 0)
        if not isinstance(price, (int, float)) or price < 0:
            return False, "invalid item price"
        if not isinstance(qty, int) or qty < 1 or qty > 50:
            return False, "invalid item quantity"
    return True, None

# ─────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────

@app.route("/api/ping")
def ping():
    return jsonify({"status": "ok", "service": "Climax Lounge API", "db": "postgresql"})


@app.route("/api/orders", methods=["GET"])
@require_api_key
@rate_limit(60)
def get_orders():
    status = request.args.get("status")
    conn = get_db()
    cur  = conn.cursor()
    if status:
        cur.execute("SELECT * FROM orders WHERE status=%s ORDER BY created_at DESC", (status,))
    else:
        cur.execute("SELECT * FROM orders ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])


@app.route("/api/orders", methods=["POST"])
@require_api_key
@rate_limit(30)
def place_order():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    ok, err = validate_order(data)
    if not ok:
        return jsonify({"error": err}), 400

    customer   = sanitise(data.get("customer", "Guest"), 60)
    note       = sanitise(data.get("note", ""), 200)
    table_name = sanitise(data.get("table_name", ""), 30)
    table_num  = int(data["table_num"])

    clean_items = []
    total = 0
    for i in data["items"]:
        qty   = int(i.get("qty", 1))
        price = int(i.get("price", 0))
        clean_items.append({
            "id":    sanitise(str(i.get("id","")),   20),
            "name":  sanitise(str(i.get("name","")), 60),
            "emoji": sanitise(str(i.get("emoji","")), 5),
            "price": price,
            "qty":   qty
        })
        total += price * qty

    order_id = uuid.uuid4().hex[:8].upper()
    now      = datetime.now().isoformat()

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        """INSERT INTO orders
           (id,table_name,table_num,customer,note,items,total,status,created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (order_id, table_name, table_num, customer, note,
         json.dumps(clean_items), total, "pending", now)
    )
    conn.commit()
    cur.close()
    conn.close()

    print(f"  New order #{order_id} — {table_name} — {customer} — UGX {total:,}")
    return jsonify({"success": True, "id": order_id}), 201


@app.route("/api/orders/<oid>", methods=["PATCH"])
@require_api_key
@rate_limit(60)
def update_order(oid):
    data   = request.get_json(force=True, silent=True)
    status = (data or {}).get("status")
    if status not in ["pending", "preparing", "ready", "delivered"]:
        return jsonify({"error": "invalid status"}), 400
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE orders SET status=%s WHERE id=%s", (status, oid))
    updated = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    if updated == 0:
        return jsonify({"error": "order not found"}), 404
    return jsonify({"success": True})


@app.route("/api/orders/<oid>", methods=["DELETE"])
@require_api_key
@rate_limit(60)
def delete_order(oid):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM orders WHERE id=%s", (oid,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/orders/delivered", methods=["DELETE"])
@require_api_key
@rate_limit(10)
def clear_delivered():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM orders WHERE status='delivered'")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/stats")
@require_api_key
@rate_limit(60)
def get_stats():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT status, total FROM orders")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    p=pr=rd=d=rev=0
    for r in rows:
        if   r["status"] == "pending":   p  += 1
        elif r["status"] == "preparing": pr += 1
        elif r["status"] == "ready":     rd += 1
        elif r["status"] == "delivered": d  += 1; rev += r["total"] or 0
    return jsonify({
        "total": len(rows), "pending": p, "preparing": pr,
        "ready": rd, "delivered": d, "revenue": rev
    })

# ─────────────────────────────────────────
# STARTUP — init DB on every start
# ─────────────────────────────────────────
init_db()

# ─────────────────────────────────────────
# RUN
# ─────────────────────────────────────────
if __name__ == "__main__":
    print()
    print("  Climax Lounge API — Running")
    print("  http://localhost:5000/api/ping")
    print()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
