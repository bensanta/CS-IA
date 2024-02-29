from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from flask import request, jsonify
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import request, redirect, url_for, render_template, flash
from flask_mail import Mail, Message

# Create a Flask app instance
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace 'your_secret_key' with a real secret key

bcrypt = Bcrypt(app)

#email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'email'
app.config['MAIL_PASSWORD'] = 'password'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


# Basic configuration for the Flask app and Flask-SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create a SQLAlchemy db instance
db = SQLAlchemy(app)


# Define the User model with additional fields
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200))
    phone = db.Column(db.String(20), unique=True, nullable=False)
    rank = db.Column(db.String(50))

    def check_password(self, passwordInput):
        return bcrypt.check_password_hash(self.password, passwordInput)

    def __init__(self, first_name, last_name, username, email, password, phone, rank):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.email = email
        self.password = password
        self.phone = phone
        self.rank = rank

    def __repr__(self):
        return f'<User {self.username}>'


# Define the LoginManager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Send Mail
# @app.route('/send-mail/')
# def send_mail():
#     mail = Mail(app)
#     msg = Message('Hello', sender='[EMAIL]', recipients=['[RECIPIENT EMAIL]'])
#     msg.body = "This is the email body"
#     mail.send(msg)
#     return "Sent"

@app.route('/user', methods=['POST'])
def create_user():
    data = request.form
    new_user = User(
        first_name=data['firstname'],
        last_name=data['lastname'],
        username=data['username'],
        email=data['email'],
        password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8'),
        phone=data['phone'],
        rank="Customer"
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('bookingsList'))



class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    day = db.Column(db.Integer, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, unique=False, nullable=False)
    type = db.Column(db.String(120), unique=False, nullable=False)
    phone = db.Column(db.String(20), unique=False, nullable=False)

    def __init__(self, day, month, year, type, phone, username):
        self.username = username
        self.day = day
        self.month = month
        self.year = year
        self.type = type
        self.phone = phone

    def __repr__(self):
        return f'<Booking {self.id}>'


@app.route('/booking', methods=['POST'])
def create_booking():
    data = request.form
    new_booking = Booking(
        username=data['username'],
        day=data['day'],
        month=data['month'],
        year=data['year'],
        type=data['appointment_type'],
        phone=data['phone']
    )
    db.session.add(new_booking)
    db.session.commit()
    return redirect(url_for('bookingsList'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user != "Customer":
                return redirect(url_for('user'))  # Redirect to the protected page
            else:
                return redirect(url_for('bookingsList'))  # Redirect to the protected page
        else:
            flash('Invalid username or password')
    return render_template('loginPage.html')  # The template with your login form



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))  # Redirect to the homepage or login page


@app.route('/cal')
def calendarBooking():
    return render_template('CalBookPage.html')


@app.route('/booklist')
def bookingsList():
    all_bookings = db.session.query(Booking).all()
    return render_template('BookingsList2.html', bookings=all_bookings)


@app.route('/signup')
def signup():
    return render_template('signUpPage.html')


@app.route('/')
def index():
    return render_template('contactPage.html')


@app.route('/newBooking')
def newBooking():
    return render_template('NewBooking.html')


@app.route('/userList')
@login_required
def user():
    all_users = db.session.query(User).all()
    return render_template('UserList.html', users=all_users)


# Create the database and tables if they don't exist
with app.app_context():
    db.create_all()

# Run the Flask application
if __name__ == "__main__":
    app.run(debug=True)

