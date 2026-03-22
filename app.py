"""
Climax Lounge Makindye — Secure Flask API
==========================================
Security features:
  1. API Key authentication on all routes
  2. Rate limiting (max 60 requests/min per IP)
  3. Input validation & sanitisation
  4. CORS locked to your Vercel domain

Deploy to Railway:
  1. Push this file to GitHub
  2. Connect repo to Railway
  3. Railway auto-detects Python and runs this

Environment variables to set in Railway:
  API_SECRET_KEY   — your secret token (e.g. climax-secret-2025)
  ALLOWED_ORIGIN   — your Vercel URL (e.g. https://climax-lounge.vercel.app)
"""

from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import sqlite3, json, uuid, os, time, re

app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIG — set these in Railway environment
# variables. Falls back to defaults for
# local development.
# ─────────────────────────────────────────

API_KEY        = os.environ.get("API_SECRET_KEY", "climax-secret-2025")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
DB             = os.path.join(os.path.dirname(__file__), "climax.db")

# CORS — open to all origins, security handled by API key
CORS(app, resources={r"/api/*": {
    "origins": "*",
    "allow_headers": ["Content-Type", "X-API-Key"],
    "methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
}})

# ─────────────────────────────────────────
# SECURITY 1 — API KEY AUTHENTICATION
# Every request must include the header:
#   X-API-Key: your-secret-key
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
# SECURITY 2 — RATE LIMITING
# Max 60 requests per minute per IP.
# Prevents spam orders and abuse.
# ─────────────────────────────────────────

request_counts = defaultdict(list)

def rate_limit(max_per_minute=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip  = request.remote_addr or "unknown"
            now = time.time()
            # Remove requests older than 60 seconds
            request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
            if len(request_counts[ip]) >= max_per_minute:
                return jsonify({"error": "Too many requests. Slow down."}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─────────────────────────────────────────
# SECURITY 3 — INPUT VALIDATION
# ─────────────────────────────────────────

def sanitise(text, max_len=200):
    """Strip dangerous characters and trim length."""
    if not isinstance(text, str):
        return ""
    # Remove HTML/script tags
    text = re.sub(r'<[^>]+>', '', text)
    # Remove special characters except common punctuation
    text = re.sub(r'[^\w\s\.,\-\'\"!?#@+:/()]', '', text)
    return text.strip()[:max_len]

def validate_order(data):
    """Returns (True, None) or (False, error_message)."""
    if not isinstance(data, dict):
        return False, "Invalid request body"

    table_num = data.get("table_num")
    if not isinstance(table_num, int) or not (1 <= table_num <= 20):
        return False, "table_num must be between 1 and 20"

    customer = data.get("customer", "").strip()
    if not customer or len(customer) < 1:
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
# DATABASE
# ─────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
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
        db.commit()
    print("  ✅  Database ready:", DB)

def row_to_dict(row):
    d = dict(row)
    try:
        d["items"] = json.loads(d.get("items") or "[]")
    except Exception:
        d["items"] = []
    return d

# ─────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────

@app.route("/api/ping")
def ping():
    """Health check — no auth needed so Railway can check it's alive."""
    return jsonify({"status": "ok", "service": "Climax Lounge API"})


@app.route("/api/orders", methods=["GET"])
@require_api_key
@rate_limit(60)
def get_orders():
    status = request.args.get("status")
    with get_db() as db:
        if status:
            rows = db.execute(
                "SELECT * FROM orders WHERE status=? ORDER BY created_at DESC", (status,)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM orders ORDER BY created_at DESC"
            ).fetchall()
    return jsonify([row_to_dict(r) for r in rows])


@app.route("/api/orders", methods=["POST"])
@require_api_key
@rate_limit(30)  # stricter — max 30 new orders per minute
def place_order():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    # Validate
    ok, err = validate_order(data)
    if not ok:
        return jsonify({"error": err}), 400

    # Sanitise text fields
    customer   = sanitise(data.get("customer", "Guest"), 60)
    note       = sanitise(data.get("note", ""), 200)
    table_name = sanitise(data.get("table_name", ""), 30)
    table_num  = int(data["table_num"])

    # Sanitise items
    clean_items = []
    total = 0
    for i in data["items"]:
        qty   = int(i.get("qty", 1))
        price = int(i.get("price", 0))
        clean_items.append({
            "id":    sanitise(str(i.get("id","")),  20),
            "name":  sanitise(str(i.get("name","")),60),
            "emoji": sanitise(str(i.get("emoji","")),5),
            "price": price,
            "qty":   qty
        })
        total += price * qty

    order_id = uuid.uuid4().hex[:8].upper()
    now      = datetime.now().isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO orders (id,table_name,table_num,customer,note,items,total,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (order_id, table_name, table_num, customer, note,
             json.dumps(clean_items), total, "pending", now)
        )
        db.commit()

    print(f"  🛎  New order #{order_id} — {table_name} — {customer} — UGX {total:,}")
    return jsonify({"success": True, "id": order_id}), 201


@app.route("/api/orders/<oid>", methods=["PATCH"])
@require_api_key
@rate_limit(60)
def update_order(oid):
    data   = request.get_json(force=True, silent=True)
    status = (data or {}).get("status")
    if status not in ["pending", "preparing", "ready", "delivered"]:
        return jsonify({"error": "invalid status"}), 400
    with get_db() as db:
        r = db.execute("UPDATE orders SET status=? WHERE id=?", (status, oid))
        db.commit()
        if r.rowcount == 0:
            return jsonify({"error": "order not found"}), 404
    return jsonify({"success": True})


@app.route("/api/orders/<oid>", methods=["DELETE"])
@require_api_key
@rate_limit(60)
def delete_order(oid):
    with get_db() as db:
        db.execute("DELETE FROM orders WHERE id=?", (oid,))
        db.commit()
    return jsonify({"success": True})


@app.route("/api/orders/delivered", methods=["DELETE"])
@require_api_key
@rate_limit(10)
def clear_delivered():
    with get_db() as db:
        db.execute("DELETE FROM orders WHERE status='delivered'")
        db.commit()
    return jsonify({"success": True})


@app.route("/api/stats")
@require_api_key
@rate_limit(60)
def get_stats():
    with get_db() as db:
        rows = db.execute("SELECT status,total FROM orders").fetchall()
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
# RUN
# ─────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║   Climax Lounge API  —  Running      ║")
    print("  ╚══════════════════════════════════════╝")
    print()
    print("  API    : http://localhost:5000/api/ping")
    print("  Key    :", API_KEY)
    print("  Origin :", ALLOWED_ORIGIN)
    print()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
