from flask import Flask, redirect, url_for, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
import re
from faker import Faker

fake = Faker()

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = "Secret-key-123_i7"

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/hashuka'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"  # redirect when not logged in

class Users (UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'
    
def seed(count=10):
 """Generates a specified number of fake users and adds them to the database."""
 with app.app_context():
         for _ in range(count):
             
            db.session.add(Users(name=fake.name(), email=fake.email(), phone_number=fake.random_int(), password_hash=bcrypt.generate_password_hash(fake.password()).decode()))
        
         db.session.commit()
 print(f'Added {count} dummy users to the database.')

def validate_user_details(name, email, phone_number, password, confirm_password):
    errors = []

    if not name or len(name) < 2:
        errors.append("Name must be at least 2 characters long.")

    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        errors.append("Invalid email format.")
    elif Users.query.filter_by(email=email).first():
        errors.append("Email already exists. Please use a different one.")

    if len(password) < 6:
        errors.append("Password must be at least 6 characters long.")
    if not re.search(r"[a-zA-Z]", password):
        errors.append("Password must contain at least one letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one number.")
    if password != confirm_password:
        errors.append("Password and password confirmation do not match.")

    if not re.fullmatch(r'[0-9-]+', phone_number):
        errors.append("Phone must only contain numbers and hyphens.")
    digits_only = re.sub(r'\D', '', phone_number)
    if len(digits_only) < 7:
        errors.append("Phone number has too few digits.")
    elif len(digits_only) > 15:
        errors.append("Phone number has too many digits.")
    return errors


def register_user(name, email, phone_number, password, confirm_password):
    errors = validate_user_details(name, email, phone_number, password, confirm_password)
    if errors:
        return render_template("signup.html", errors=errors)
    # no errors => register user to database
    db.session.add(Users(name=name,
                          email=email,
                          phone_number=phone_number,
                          password_hash=bcrypt.generate_password_hash(password).decode()))
    db.session.commit()
    login_user(Users.query.filter_by(email=request.form.get('email')).first(), remember=True)
    return redirect(url_for("home"))
    
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("signin"))
 
@app.route("/")
def index():
    return redirect(url_for('home'))

@app.route("/signin", methods = ['GET', 'POST'])
def signin():
    if request.method == 'POST':    # handle sign-in request
        user = Users.query.filter_by(email=request.form.get('email')).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user, remember=True)
            return redirect(url_for("home"))
        return render_template('signin.html', error="Invalid email or password.")
    return render_template("signin.html")

@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        return register_user(request.form.get('name'),
                             request.form.get('email'),
                             request.form.get('phone'),
                             request.form.get('password'),
                             request.form.get('confirm_password'))
    return render_template("signup.html")

@app.route("/forgot_password")
def forgot_password():
    return "tbd"

@app.route("/home")
@login_required
def home():
    return f"Hello <b>{current_user.name}</b>!"


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # seed()

    app.run(host="0.0.0.0", debug=True)
