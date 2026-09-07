"""
Daily Save - Stripe Billing & User Database Server

This Flask server:
1. Creates Stripe Checkout Sessions for the Daily Save Plus plan
2. Maintains a SQLite database of users and their purchases
3. Uses Stripe webhooks to automatically attribute purchases to users
4. Provides user/purchase lookup endpoints
5. Provides username/password registration and login endpoints

Setup:
    pip install flask stripe flask-cors
    set STRIPE_SECRET_KEY=sk_live_...
    set STRIPE_WEBHOOK_SECRET=whsec_...
    python app.py
"""

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps

import stripe
from flask import Flask, g, jsonify, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STRIPE_SECRET_KEY = os.environ.get(
    "STRIPE_SECRET_KEY",
    "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",
)
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.environ.get(
    "STRIPE_PRICE_ID", "price_1UCUmwBhlvxaw0DLEmQzj4Wm"
)
DATABASE_PATH = os.environ.get(
    "DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dailysave.db")
)
PORT = int(os.environ.get("PORT", "8080"))

stripe.api_key = STRIPE_SECRET_KEY

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def get_db():
    """Get a thread-local SQLite connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of each request."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Create the users and purchases tables if they don't exist."""
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                provider      TEXT NOT NULL,
                username      TEXT UNIQUE,
                password_hash TEXT,
                email         TEXT,
                display_name  TEXT,
                zip_code      TEXT,
                plan          TEXT NOT NULL DEFAULT 'free',
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS purchases (
                id                 TEXT PRIMARY KEY,
                user_id            TEXT NOT NULL,
                stripe_session_id  TEXT UNIQUE,
                stripe_customer_id TEXT,
                plan               TEXT NOT NULL,
                amount_total       INTEGER,
                currency           TEXT,
                status             TEXT NOT NULL,
                created_at         TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            CREATE INDEX IF NOT EXISTS idx_purchases_user
                ON purchases (user_id);

            CREATE TABLE IF NOT EXISTS community_items (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT NOT NULL UNIQUE COLLATE NOCASE,
                category       TEXT NOT NULL DEFAULT 'Other',
                reference_price REAL,
                created_at     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS community_posts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                zip_code       TEXT NOT NULL,
                user_id        TEXT,
                display_name   TEXT NOT NULL,
                item_id        INTEGER NOT NULL,
                store_name     TEXT NOT NULL,
                price          REAL NOT NULL,
                message        TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                FOREIGN KEY (item_id) REFERENCES community_items (id)
            );

            CREATE INDEX IF NOT EXISTS idx_community_posts_zip
                ON community_posts (zip_code, created_at DESC);
            """
        )
        # Lightweight migration for databases created before the plan column.
        columns = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
        if "plan" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'")
        for store, item, price, _, category, _ in STORE_CATALOG:
            db.execute(
                """
                INSERT OR IGNORE INTO community_items
                    (name, category, reference_price, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (item, category, price, _now_iso()),
            )
        db.commit()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password):
    """Hash a password with a random salt using SHA-256."""
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${password_hash}"


def _verify_password(password, stored_hash):
    """Verify a password against a stored hash."""
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, expected_hash = stored_hash.split("$", 1)
    actual_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return secrets.compare_digest(actual_hash, expected_hash)


def _upsert_user(user_id, provider, zip_code, email=None, display_name=None, username=None, password_hash=None):
    """Insert or update a user record. Returns the user row."""
    db = get_db()
    now = _now_iso()
    db.execute(
        """
        INSERT INTO users (id, provider, username, password_hash, email, display_name, zip_code, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            provider = excluded.provider,
            username = COALESCE(excluded.username, users.username),
            password_hash = COALESCE(excluded.password_hash, users.password_hash),
            email = COALESCE(excluded.email, users.email),
            display_name = COALESCE(excluded.display_name, users.display_name),
            zip_code = COALESCE(excluded.zip_code, users.zip_code)
        """,
        (user_id, provider, username, password_hash, email, display_name, zip_code, now),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return row


def _record_purchase(
    user_id,
    stripe_session_id,
    stripe_customer_id,
    plan,
    amount_total,
    currency,
    status,
):
    """Insert a purchase record linked to a user."""
    db = get_db()
    purchase_id = str(uuid.uuid4())
    now = _now_iso()
    db.execute(
        """
        INSERT INTO purchases
            (id, user_id, stripe_session_id, stripe_customer_id,
             plan, amount_total, currency, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            purchase_id,
            user_id,
            stripe_session_id,
            stripe_customer_id,
            plan,
            amount_total,
            currency,
            status,
            now,
        ),
    )
    db.commit()
    return purchase_id


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@app.route("/auth/register", methods=["POST"])
def register():
    """
    Register a new user with username and password.

    Expected JSON body:
        {
            "username": "johndoe",
            "password": "secret123",
            "zipCode": "10001",
            "email": "john@example.com",   # optional
            "displayName": "John Doe"      # optional
        }

    Returns:
        { "userId": "...", "username": "johndoe", "email": "...", "displayName": "..." }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    zip_code = str(data.get("zipCode", ""))
    email = data.get("email")
    display_name = data.get("displayName")

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing is not None:
        return jsonify({"error": "Username is already taken."}), 409

    user_id = str(uuid.uuid4())
    password_hash = _hash_password(password)
    row = _upsert_user(
        user_id=user_id,
        provider="username",
        zip_code=zip_code,
        email=email,
        display_name=display_name or username,
        username=username,
        password_hash=password_hash,
    )

    return jsonify({
        "userId": row["id"],
        "username": row["username"],
        "email": row["email"],
        "displayName": row["display_name"],
        "zipCode": row["zip_code"],
    }), 201


@app.route("/auth/login", methods=["POST"])
def login():
    """
    Log in an existing user with username and password.

    Expected JSON body:
        {
            "username": "johndoe",
            "password": "secret123"
        }

    Returns:
        { "userId": "...", "username": "johndoe", "email": "...", "displayName": "..." }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not _verify_password(password, row["password_hash"]):
        return jsonify({"error": "Invalid username or password."}), 401

    return jsonify({
        "userId": row["id"],
        "username": row["username"],
        "email": row["email"],
        "displayName": row["display_name"],
        "zipCode": row["zip_code"],
    }), 200


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


STORE_CATALOG = [
    ("FreshMart", "Milk", 3.49, 4.29, "Dairy", "Save $0.80"),
    ("FreshMart", "Large eggs", 2.79, 3.49, "Dairy", "Save $0.70"),
    ("FreshMart", "Bananas", 0.59, 0.69, "Produce", "10% off"),
    ("FreshMart", "Avocado", 0.99, 1.49, "Produce", "Save $0.50"),
    ("Green Basket", "Chicken breast", 5.99, 7.49, "Meat", "Save $1.50"),
    ("Green Basket", "Ground beef", 5.49, 6.99, "Meat", "Save $1.50"),
    ("Green Basket", "Whole grain bread", 2.49, 3.29, "Bakery", "Save $0.80"),
    ("Green Basket", "Cheddar cheese", 3.99, 4.99, "Dairy", "Save $1.00"),
    ("Value Foods", "Long grain rice", 2.99, 4.49, "Pantry", "Save $1.50"),
    ("Value Foods", "Pasta", 1.29, 1.99, "Pantry", "Save $0.70"),
    ("Value Foods", "Pasta sauce", 2.19, 2.99, "Pantry", "Save $0.80"),
    ("Value Foods", "Coffee", 7.99, 10.49, "Pantry", "Save $2.50"),
    ("Market Square", "Strawberries", 2.99, 4.49, "Produce", "Save $1.50"),
    ("Market Square", "Broccoli", 1.79, 2.49, "Produce", "Save $0.70"),
    ("Market Square", "Greek yogurt", 4.49, 5.99, "Dairy", "Save $1.50"),
    ("Market Square", "Sparkling water", 3.49, 4.99, "Drinks", "Save $1.50"),
]


@app.route("/store-data", methods=["GET"])
def store_data():
    """Return the complete normalized deal and price catalog for a ZIP area."""
    zip_code = request.args.get("zip", "").strip()
    categories = {
        category.strip().lower()
        for category in request.args.get("categories", "").split(",")
        if category.strip()
    }
    if not zip_code or not zip_code.isdigit() or len(zip_code) != 5:
        return jsonify({"error": "A 5-digit zip query parameter is required."}), 400

    filtered_rows = [
        row for row in STORE_CATALOG
        if not categories or row[4].lower() in categories
    ]
    # Interest labels are broader than product categories. Keep the catalog
    # useful when a user's interests do not have an exact category match.
    rows = filtered_rows or STORE_CATALOG
    prices = [
        {
            "item": item,
            "store": store,
            "price": price,
            "regularPrice": regular_price,
            "available": True,
            "category": category,
        }
        for store, item, price, regular_price, category, _ in rows
    ]
    offers = [
        {
            "merchant": store,
            "title": f"{item}: {label}",
            "description": f"Local {category} price near ZIP {zip_code}.",
            "discount": label,
            "category": category,
        }
        for store, item, _, _, category, label in rows
    ]
    deals = [
        {
            "item": item.lower(),
            "store": store,
            "amount": round(regular_price - price, 2),
            "label": label,
            "isCoupon": True,
        }
        for store, item, price, regular_price, _, label in rows
        if regular_price > price
    ]
    return jsonify({"zip": zip_code, "offers": offers, "prices": prices, "deals": deals})


@app.route("/community/items", methods=["GET", "POST"])
def community_items():
    """List shared items or add one to the community item catalog."""
    db = get_db()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        category = str(data.get("category", "Other")).strip() or "Other"
        reference_price = data.get("referencePrice")
        if not name or len(name) > 80:
            return jsonify({"error": "Item name is required and must be 80 characters or fewer."}), 400
        try:
            reference_price = float(reference_price) if reference_price not in (None, "") else None
            if reference_price is not None and reference_price < 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "referencePrice must be a positive number."}), 400
        try:
            cursor = db.execute(
                "INSERT INTO community_items (name, category, reference_price, created_at) VALUES (?, ?, ?, ?)",
                (name, category, reference_price, _now_iso()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            row = db.execute(
                "SELECT * FROM community_items WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
            return jsonify(dict(row)), 200
        row = db.execute("SELECT * FROM community_items WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201

    rows = db.execute(
        "SELECT id, name, category, reference_price, created_at FROM community_items ORDER BY name"
    ).fetchall()
    return jsonify([dict(row) for row in rows]), 200


@app.route("/community/posts", methods=["GET", "POST"])
def community_posts():
    """Read or create price sightings shared with people in one ZIP code."""
    db = get_db()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        zip_code = str(data.get("zipCode", "")).strip()
        display_name = str(data.get("displayName", "Neighbor")).strip() or "Neighbor"
        user_id = str(data.get("userId", "")).strip() or None
        store_name = str(data.get("storeName", "")).strip()
        message = str(data.get("message", "")).strip()
        try:
            item_id = int(data.get("itemId"))
            price = float(data.get("price"))
        except (TypeError, ValueError):
            return jsonify({"error": "itemId and price are required."}), 400
        if not zip_code.isdigit() or len(zip_code) != 5:
            return jsonify({"error": "A valid 5-digit ZIP code is required."}), 400
        if not store_name or len(store_name) > 80 or not message or len(message) > 280:
            return jsonify({"error": "Store and message are required; message limit is 280 characters."}), 400
        if price < 0 or price > 100000:
            return jsonify({"error": "Price must be a valid positive amount."}), 400
        item = db.execute("SELECT id FROM community_items WHERE id = ?", (item_id,)).fetchone()
        if item is None:
            return jsonify({"error": "That community item does not exist."}), 404
        cursor = db.execute(
            """
            INSERT INTO community_posts
                (zip_code, user_id, display_name, item_id, store_name, price, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (zip_code, user_id, display_name[:60], item_id, store_name, price, message, _now_iso()),
        )
        db.commit()
        row = db.execute(
            """
            SELECT p.id, p.zip_code, p.user_id, p.display_name, p.store_name,
                   p.price, p.message, p.created_at, i.name AS item_name,
                   i.category, i.reference_price,
                   CASE WHEN i.reference_price IS NULL THEN NULL
                        ELSE ROUND(i.reference_price - p.price, 2) END AS difference
            FROM community_posts p
            JOIN community_items i ON i.id = p.item_id
            WHERE p.id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        return jsonify(dict(row)), 201

    zip_code = request.args.get("zip", "").strip()
    if not zip_code.isdigit() or len(zip_code) != 5:
        return jsonify({"error": "A valid 5-digit ZIP query parameter is required."}), 400
    rows = db.execute(
        """
        SELECT p.id, p.zip_code, p.user_id, p.display_name, p.store_name,
               p.price, p.message, p.created_at, i.name AS item_name,
               i.category, i.reference_price,
               CASE WHEN i.reference_price IS NULL THEN NULL
                    ELSE ROUND(i.reference_price - p.price, 2) END AS difference
        FROM community_posts p
        JOIN community_items i ON i.id = p.item_id
        WHERE p.zip_code = ?
        ORDER BY p.created_at DESC
        LIMIT 100
        """,
        (zip_code,),
    ).fetchall()
    return jsonify([dict(row) for row in rows]), 200


@app.route("/billing/checkout", methods=["POST"])
def create_checkout():
    """
    Create a Stripe Checkout Session for the Daily Save Plus plan.

    Expected JSON body:
        {
            "provider": "username" | "Guest" | "assistant",
            "zipCode": "10001",
            "plan": "plus",
            "productId": "prod_...",        # optional, kept for compatibility
            "priceId": "price_...",          # optional, overrides default
            "userId": "user-uuid",           # the user to attribute the purchase to
            "email": "user@example.com",     # optional
            "displayName": "Jane Doe"        # optional
        }

    Returns:
        { "checkoutUrl": "https://checkout.stripe.com/..." }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    provider = str(data.get("provider", "Guest"))
    zip_code = str(data.get("zipCode", ""))
    plan = str(data.get("plan", "plus"))
    user_id = str(data.get("userId", "")).strip()
    email = data.get("email")
    display_name = data.get("displayName")
    price_id = str(data.get("priceId", STRIPE_PRICE_ID)).strip()

    # Guests may not have a persistent user id yet; create one for them so the
    # purchase is still attributed to exactly one user record.
    if not user_id:
        user_id = str(uuid.uuid4())
        provider = provider or "Guest"

    if not price_id:
        return jsonify({"error": "priceId is required"}), 400

    # Ensure the user exists in our database before checkout.
    _upsert_user(
        user_id=user_id,
        provider=provider,
        zip_code=zip_code,
        email=email,
        display_name=display_name,
    )

    origin = request.origin or request.host_url.rstrip("/")
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                }
            ],
            success_url=origin + "/billing/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=origin + "/billing/cancel",
            client_reference_id=user_id,
            customer_email=email if email else None,
            metadata={
                "user_id": user_id,
                "provider": provider,
                "zip_code": zip_code,
                "plan": plan,
            },
            subscription_data={
                "metadata": {
                    "user_id": user_id,
                    "provider": provider,
                    "zip_code": zip_code,
                    "plan": plan,
                }
            },
        )
    except stripe.StripeError as e:
        return jsonify({"error": f"Stripe error: {getattr(e, 'user_message', None) or e}"}), 400

    return jsonify({"checkoutUrl": session.url, "userId": user_id}), 200


@app.route("/billing/webhook", methods=["POST"])
def stripe_webhook():
    """
    Stripe webhook endpoint.

    Automatically attributes completed purchases to the correct user using
    the `client_reference_id` (our user ID) set on the Checkout Session.

    Configure this URL in the Stripe Dashboard:
        https://dashboard.stripe.com/webhooks
    Events to listen for:
        - checkout.session.completed
        - customer.subscription.updated
        - customer.subscription.deleted
    """
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature", "")

    if not STRIPE_WEBHOOK_SECRET:
        # In development without a webhook secret, fall back to parsing the
        # raw event. This is NOT safe for production.
        try:
            event = json.loads(payload)
        except Exception:
            return jsonify({"error": "Invalid payload"}), 400
    else:
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except stripe.SignatureVerificationError:
            return jsonify({"error": "Invalid signature"}), 400

    event_type = event.get("type", "")
    event_data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        session = event_data
        user_id = session.get("client_reference_id") or (
            session.get("metadata") or {}
        ).get("user_id")
        stripe_session_id = session.get("id")
        stripe_customer_id = session.get("customer")
        plan = (session.get("metadata") or {}).get("plan", "plus")
        amount_total = session.get("amount_total")
        currency = session.get("currency")

        if not user_id:
            return jsonify({"error": "No user_id on session"}), 400

        # Make sure the user exists (they should already from checkout).
        _upsert_user(
            user_id=user_id,
            provider=(session.get("metadata") or {}).get("provider", "Guest"),
            zip_code=(session.get("metadata") or {}).get("zip_code", ""),
            email=session.get("customer_details", {}).get("email"),
            display_name=session.get("customer_details", {}).get("name"),
        )

        # Record the purchase so we know exactly which user bought what.
        _record_purchase(
            user_id=user_id,
            stripe_session_id=stripe_session_id,
            stripe_customer_id=stripe_customer_id,
            plan=plan,
            amount_total=amount_total,
            currency=currency,
            status="completed",
        )

        # Mark this single user as a Plus subscriber.
        db = get_db()
        db.execute(
            "UPDATE users SET plan = 'plus' WHERE id = ?", (user_id,)
        )
        db.commit()

        return jsonify({"received": True}), 200

    if event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        subscription = event_data
        customer_id = subscription.get("customer")
        status = subscription.get("status", "unknown")

        # Find the user by Stripe customer ID and update their subscription status.
        db = get_db()
        db.execute(
            "UPDATE purchases SET status = ? WHERE stripe_customer_id = ?",
            (status, customer_id),
        )
        db.commit()
        return jsonify({"received": True}), 200

    # Return a response to acknowledge receipt of the event.
    return jsonify({"received": True}), 200


@app.route("/billing/success", methods=["GET"])
def billing_success():
    return jsonify({"message": "Payment successful! Your Plus plan is active."})


@app.route("/billing/cancel", methods=["GET"])
def billing_cancel():
    return jsonify({"message": "Checkout cancelled. You can try again anytime."})


@app.route("/users/<user_id>/subscription", methods=["GET"])
def get_subscription(user_id):
    """
    Get the subscription state for one specific user.

    Only returns active when THAT user has a completed/active purchase, so a
    subscription can never leak to another account.
    """
    db = get_db()
    row = db.execute(
        """
        SELECT plan, status FROM purchases
        WHERE user_id = ? AND status IN ('completed', 'active')
        ORDER BY created_at DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    active = row is not None
    return jsonify(
        {
            "userId": user_id,
            "active": active,
            "plan": row["plan"] if row else "free",
        }
    ), 200


@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    """Get a user record by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(row)), 200


@app.route("/users/<user_id>/purchases", methods=["GET"])
def get_user_purchases(user_id):
    """Get all purchases for a user, newest first."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM purchases WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows]), 200


@app.route("/users", methods=["GET"])
def list_users():
    """List all users (admin/debug helper)."""
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows]), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print(f"Daily Save billing server running on port {PORT}")
    print(f"Database: {DATABASE_PATH}")
    print(f"Stripe price ID: {STRIPE_PRICE_ID}")
    app.run(host="0.0.0.0", port=PORT, debug=True)