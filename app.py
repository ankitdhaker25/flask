from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message

from datetime import datetime, timedelta
import os
import re
import secrets
import sqlite3

# ================= ENV =================
def load_env_file(path=".env"):
    if not os.path.exists(path):
        return

    with open(path) as env_file:
        for line in env_file:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


load_env_file()

APP_ENV = os.environ.get("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

# ================= APP INIT =================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY must be set when APP_ENV=production")

    app.secret_key = "dev-change-this-secret-key"

# ================= BASE DIR =================
basedir = os.path.abspath(os.path.dirname(__file__))

# ================= DATABASE =================
DATABASE_PATH = os.path.join(basedir, 'instance', 'users.db')
BACKUP_FOLDER = os.path.join(basedir, 'backups')

app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + DATABASE_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ================= UPLOAD =================
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'profile_pics')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ================= EMAIL =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME", "")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD", "")
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

# ================= SECURITY =================
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION or os.environ.get("HTTPS", "").lower() == "true"

# ================= EXTENSIONS =================
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
mail = Mail(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
)

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    if app.config['SESSION_COOKIE_SECURE']:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

# ================= MODEL =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    phone = db.Column(db.String(20), default="")
    profile_image = db.Column(db.String(200), default="default.png")
    role = db.Column(db.String(20), default="user")


class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    otp_hash = db.Column(db.String(200), nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Float, nullable=False)
    item_count = db.Column(db.Integer, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CustomerPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Inventory')


with app.app_context():
    db.create_all()

# ================= HELPERS =================
def backup_database():
    if not os.path.exists(DATABASE_PATH):
        return

    os.makedirs(BACKUP_FOLDER, exist_ok=True)

    backup_name = f"users-{datetime.now().strftime('%Y-%m-%d')}.db"
    backup_path = os.path.join(BACKUP_FOLDER, backup_name)

    if os.path.exists(backup_path):
        return

    source = sqlite3.connect(DATABASE_PATH)
    target = sqlite3.connect(backup_path)

    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


with app.app_context():
    backup_database()


@app.before_request
def ensure_daily_backup():
    backup_database()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['png','jpg','jpeg','gif']

def valid_image_file(file):
    header = file.stream.read(12)
    file.stream.seek(0)

    return (
        header.startswith(b"\xff\xd8\xff") or
        header.startswith(b"\x89PNG\r\n\x1a\n") or
        header.startswith(b"GIF87a") or
        header.startswith(b"GIF89a")
    )

def valid_email(email):
    return bool(email and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))

def strong_password(password):
    return bool(
        password and
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password)
    )

def email_configured():
    return (
        app.config['MAIL_USERNAME'] != "" and
        app.config['MAIL_PASSWORD'] != ""
    )

def delete_reset_otp(email):
    reset_otp = db.session.execute(
        db.select(PasswordResetOTP).filter_by(email=email)
    ).scalar_one_or_none()

    if reset_otp:
        db.session.delete(reset_otp)
        db.session.commit()

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    flash("File is too large. Maximum size is 2 MB.")
    return redirect(request.referrer or url_for("profile"))

# ================= ADMIN =================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for("Login"))

        user = db.session.get(User, session['user'])

        if not user or user.role != "admin":
            abort(403)

        return f(*args, **kwargs)
    return wrapper

# ================= SHOPOWNER =================
def shopowner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for("Login"))

        user = db.session.get(User, session['user'])

        if not user or (user.role != "shopowner" and user.role != "admin"):
            abort(403)

        return f(*args, **kwargs)
    return wrapper

# ================= HOME =================
@app.route("/")
def Home():
    user = None
    if 'user' in session:
        user = db.session.get(User, session['user'])
    return render_template("Home.html", user=user)

# ================= REGISTER =================
@app.route("/Register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def Register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        role = request.form.get("role") or "user"

        if role not in ["user", "shopowner"]:
            role = "user"

        if not username or not valid_email(email) or not strong_password(password):
            flash("Use a valid username, email, and password with 8+ characters, uppercase, lowercase, and a number")
            return redirect(url_for("Register"))

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("Register"))

        if db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none():
            flash("User exists ❌")
            return redirect(url_for("Register"))

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role
        )

        db.session.add(user)
        db.session.commit()

        flash(f"Registered as {role} 🎉")
        return redirect(url_for("Login"))

    return render_template("Register.html")

# ================= LOGIN =================
@app.route("/Login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def Login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password")

        user = db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none()

        if user and check_password_hash(user.password, password):
            session.clear()
            session['user'] = user.id
            return redirect(url_for("Home"))

        flash("Invalid ❌")
        return redirect(url_for("Login"))

    return render_template("Login.html")

# ================= LOGOUT =================
@app.route("/Logout")
def Logout():
    session.clear()
    return redirect(url_for("Login"))

# ================= PROFILE =================
@app.route("/profile")
def profile():
    if 'user' not in session:
        return redirect(url_for("Login"))

    user = db.session.get(User, session['user'])
    return render_template("profile.html", user=user)

# ================= UPDATE PROFILE =================
@app.route("/update_user", methods=["POST"])
@limiter.limit("10 per minute")
def update_user():
    if 'user' not in session:
        return redirect(url_for("Login"))

    user = db.session.get(User, session['user'])

    user.username = request.form.get("username") or user.username
    user.phone = request.form.get("phone") or user.phone

    if request.form.get("remove_image") == "1":
        user.profile_image = "default.png"
    else:
        image = request.files.get("profile_image")
        if image and image.filename and allowed_file(image.filename):
            if not valid_image_file(image):
                flash("Uploaded file is not a valid image")
                return redirect(url_for("profile"))

            filename = secure_filename(image.filename)
            if not filename:
                flash("Invalid image filename")
                return redirect(url_for("profile"))

            unique = f"{user.id}_{int(datetime.now().timestamp())}_{filename}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], unique))
            user.profile_image = unique
        elif image and image.filename:
            flash("Only png, jpg, jpeg, and gif images are allowed")
            return redirect(url_for("profile"))

    db.session.commit()
    flash("Updated 🎉")
    return redirect(url_for("profile"))

# ================= ADMIN PANEL =================
@app.route("/admin")
@admin_required
def admin_dashboard():
    search = request.args.get("search")

    if search:
        users = db.session.execute(
            db.select(User).filter(
                (User.username.like(f"%{search}%")) |
                (User.email.like(f"%{search}%"))
            )
        ).scalars().all()
    else:
        users = db.session.execute(db.select(User)).scalars().all()

    return render_template("admin.html", users=users, search=search)

# ================= DELETE USER =================
@app.route("/delete_user/<int:id>", methods=["POST"])
@admin_required
def delete_user(id):
    user = db.session.get(User, id)

    if user and user.role != "admin":
        db.session.delete(user)
        db.session.commit()
        flash("Deleted 🗑️")
    else:
        flash("Cannot delete admin ❌")

    return redirect(url_for("admin_dashboard"))

# ================= SHOPOWNER PANEL =================
@app.route("/shopowner")
@shopowner_required
def shopowner_dashboard():
    user = db.session.get(User, session['user'])
    
    customers = db.session.execute(
        db.select(Customer).filter_by(shop_id=user.id).order_by(Customer.customer_name)
    ).scalars().all()
    
    inventory = db.session.execute(
        db.select(Inventory).filter_by(shop_id=user.id)
    ).scalars().all()

    # Calculate Total Sales
    total_sales = db.session.execute(
        db.select(db.func.sum(CustomerPurchase.price * CustomerPurchase.quantity))
        .join(Customer, CustomerPurchase.customer_id == Customer.id)
        .filter(Customer.shop_id == user.id)
    ).scalar() or 0.0

    # Calculate Low Stock (threshold <= 5)
    low_stock_count = sum(1 for item in inventory if item.item_count <= 5)

    return render_template("shopowner_dashboard.html", 
                           user=user, 
                           customers=customers,
                           inventory=inventory,
                           total_sales=total_sales,
                           low_stock_count=low_stock_count)


@app.route("/shopowner/customer/add", methods=["POST"])
@shopowner_required
def add_customer():
    user_id = session['user']
    name = (request.form.get("customer_name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()

    if not name:
        flash("Customer name is required")
        return redirect(url_for("shopowner_dashboard"))

    customer = Customer(
        shop_id=user_id,
        customer_name=name,
        email=email
    )
    db.session.add(customer)
    db.session.commit()
    
    flash(f"Customer {name} added! 🎉")
    return redirect(url_for("shopowner_dashboard"))


@app.route("/shopowner/customer/<int:id>")
@shopowner_required
def customer_account(id):
    user = db.session.get(User, session['user'])
    customer = db.session.get(Customer, id)

    if not customer or customer.shop_id != user.id:
        abort(403)

    # Sidebar needs customers too
    customers = db.session.execute(
        db.select(Customer).filter_by(shop_id=user.id).order_by(Customer.customer_name)
    ).scalars().all()
    
    inventory = db.session.execute(
        db.select(Inventory).filter_by(shop_id=user.id)
    ).scalars().all()

    # Get purchases using new relationship
    purchases = db.session.execute(
        db.select(CustomerPurchase)
        .filter_by(customer_id=id)
        .order_by(CustomerPurchase.purchase_date.desc())
    ).scalars().all()

    total_spent = sum(p.price * p.quantity for p in purchases)

    return render_template("customer_account.html", 
                           user=user, 
                           customer=customer, 
                           customers=customers,
                           inventory=inventory,
                           purchases=purchases,
                           total_spent=total_spent)


@app.route("/shopowner/customer/<int:customer_id>/purchase/add", methods=["POST"])
@shopowner_required
def add_purchase(customer_id):
    user_id = session['user']
    customer = db.session.get(Customer, customer_id)
    
    if not customer or customer.shop_id != user_id:
        abort(403)

    product_id = request.form.get("product_id")
    quantity = int(request.form.get("quantity") or 1)
    
    product = db.session.get(Inventory, product_id)
    if not product or product.shop_id != user_id:
        flash("Invalid product selection")
        return redirect(url_for("customer_account", id=customer_id))

    # Business Logic: Check stock availability
    if product.item_count < quantity:
        flash(f"Insufficient stock! Only {product.item_count} available.")
        return redirect(url_for("customer_account", id=customer_id))

    # Business Logic: Reduce inventory stock
    product.item_count -= quantity

    purchase = CustomerPurchase(
        customer_id=customer_id,
        product_id=product.id,
        quantity=quantity,
        price=product.item_price # Record price at time of purchase
    )
    
    db.session.add(purchase)
    db.session.commit()
    
    flash("Purchase added! 🛍️")
    return redirect(url_for("customer_account", id=customer_id))


@app.route("/shopowner/purchase/delete/<int:id>", methods=["POST"])
@shopowner_required
def delete_purchase(id):
    user_id = session['user']
    purchase = db.session.get(CustomerPurchase, id)
    
    if not purchase:
        abort(404)
        
    customer = db.session.get(Customer, purchase.customer_id)
    if not customer or customer.shop_id != user_id:
        abort(403)

    db.session.delete(purchase)
    db.session.commit()
    
    flash("Purchase deleted 🗑️")
    return redirect(url_for("customer_account", id=customer.id))


@app.route("/shopowner/inventory/add", methods=["POST"])
@shopowner_required
def add_inventory_item():
    user_id = session['user']
    name = request.form.get("item_name")
    price = float(request.form.get("item_price") or 0)
    count = int(request.form.get("item_count") or 0)

    item = Inventory(
        shop_id=user_id,
        item_name=name,
        item_price=price,
        item_count=count
    )
    db.session.add(item)
    db.session.commit()
    
    flash("Item added to inventory!")
    return redirect(request.referrer or url_for("shopowner_dashboard"))


@app.route("/shopowner/inventory/delete/<int:id>", methods=["POST"])
@shopowner_required
def delete_inventory_item(id):
    user_id = session['user']
    item = db.session.get(Inventory, id)
    
    if not item or item.shop_id != user_id:
        abort(404)

    db.session.delete(item)
    db.session.commit()
    
    flash(f"Item '{item.item_name}' removed from inventory.")
    return redirect(url_for("shopowner_dashboard"))

# ================= FORGOT PASSWORD (FIXED ERROR HERE) =================
@app.route("/forgot_password")
def forgot_password():
    return render_template("forgot_password.html")

# ================= SEND OTP =================
@app.route("/send_otp", methods=["POST"])
@limiter.limit("3 per hour")
def send_otp():
    email = (request.form.get("email") or "").strip().lower()

    generic_message = "If that email exists, an OTP was sent."

    if not valid_email(email):
        flash(generic_message)
        return redirect(url_for("forgot_password"))

    user = db.session.execute(
        db.select(User).filter_by(email=email)
    ).scalar_one_or_none()

    if not user:
        flash(generic_message)
        return redirect(url_for("forgot_password"))

    otp = secrets.randbelow(900000) + 100000

    delete_reset_otp(email)

    reset_otp = PasswordResetOTP(
        email=email,
        otp_hash=generate_password_hash(str(otp)),
        expires_at=datetime.now() + timedelta(minutes=5)
    )

    db.session.add(reset_otp)
    db.session.commit()

    msg = Message(
        "OTP Verification",
        recipients=[email]
    )
    msg.body = f"Your OTP is {otp}"

    if email_configured():
        try:
            mail.send(msg)
            flash("OTP sent to your email")
        except Exception:
            app.logger.exception("Could not send OTP email")

            if not app.debug:
                delete_reset_otp(email)
                flash("Could not send OTP. Check your email settings.")
                return redirect(url_for("forgot_password"))

            flash(f"Email could not be sent. Test OTP: {otp}")
    else:
        if not app.debug:
            delete_reset_otp(email)
            flash("Email settings are not configured.")
            return redirect(url_for("forgot_password"))

        flash(f"Email settings are not configured. Test OTP: {otp}")

    return render_template("verify_otp.html", email=email)

# ================= VERIFY OTP =================
@app.route("/verify_otp", methods=["POST"])
@limiter.limit("10 per minute")
def verify_otp():
    email = (request.form.get("email") or "").strip().lower()
    otp = (request.form.get("otp") or "").strip()

    reset_otp = db.session.execute(
        db.select(PasswordResetOTP).filter_by(email=email)
    ).scalar_one_or_none()

    if not reset_otp:
        flash("Invalid OTP ❌")
        return redirect(url_for("forgot_password"))

    if datetime.now() >= reset_otp.expires_at:
        db.session.delete(reset_otp)
        db.session.commit()
        flash("OTP expired. Please request a new OTP.")
        return redirect(url_for("forgot_password"))

    reset_otp.attempts += 1
    db.session.commit()

    if reset_otp.attempts > 5:
        db.session.delete(reset_otp)
        db.session.commit()
        flash("Too many OTP attempts. Please request a new OTP.")
        return redirect(url_for("forgot_password"))

    if check_password_hash(reset_otp.otp_hash, otp):
        session['reset_email'] = email
        db.session.delete(reset_otp)
        db.session.commit()
        return redirect(url_for("reset_password"))

    flash("Invalid OTP ❌")
    return render_template("verify_otp.html", email=email)

# ================= RESET PASSWORD =================
@app.route("/reset_password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def reset_password():
    email = session.get("reset_email")

    if not email:
        return redirect(url_for("Login"))

    if request.method == "POST":
        new_pass = request.form.get("password")

        if not strong_password(new_pass):
            flash("Password must have 8+ characters, uppercase, lowercase, and a number")
            return redirect(url_for("reset_password"))

        user = db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none()

        if user:
            user.password = generate_password_hash(new_pass)
            db.session.commit()

        session.pop("reset_email", None)

        return redirect(url_for("Login"))

    return render_template("reset_password.html")

# ================= UPGRADE TO SHOPOWNER =================
@app.route("/upgrade_to_shopowner", methods=["POST"])
def upgrade_to_shopowner():
    if 'user' not in session:
        return redirect(url_for("Login"))

    user = db.session.get(User, session['user'])
    if user and user.role == "user":
        user.role = "shopowner"
        db.session.commit()
        flash("You are now a Shopowner! 🏪")
    
    return redirect(url_for("profile"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(
        debug=not IS_PRODUCTION,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "50000"))
    )
