from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter.util import get_remote_address
import os
import io
import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from dotenv import load_dotenv
from flask_limiter import Limiter
import logging
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash

logging.basicConfig(level=logging.INFO)

# Load environment variables from .env
load_dotenv()

# Initialize Flask application
application = Flask(__name__)
application.secret_key = os.getenv("FLASK_SECRET_KEY")

# Enable CSRF protection
csrf = CSRFProtect(application)

# Enable rate limiting
limiter = Limiter(
    get_remote_address,
    app=application,
    default_limits=["200 per day", "50 per hour"]
)

METHOD_NOT_ALLOWED_MESSAGE = "Method Not Allowed"


# Define base directory
base_dir = os.path.abspath(os.path.dirname(__file__))

# Configuration for SQLite database
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'turf_system.db')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(application)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin', 'manager', 'user'


class Turf(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    time_slots = db.Column(db.String(500), nullable=False)  # Comma-separated slots
    photo_data = db.Column(db.LargeBinary, nullable=True)  # Store image as binary
    photo_name = db.Column(db.String(120), nullable=True)  # Optional: to store file name
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bookings = db.relationship('Booking', backref='turf', cascade="all, delete-orphan")


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    turf_id = db.Column(db.Integer, db.ForeignKey('turf.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_slot = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')




# Routes
@application.route('/')
def home():
    return render_template('home.html')




@application.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # CSRF protection is disabled for demonstration; consider enabling it.
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    # Retrieve admin credentials from environment variables
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_username or not admin_password:
        raise ValueError("Admin username or password environment variables are not set")

    # Handle GET request to display the login form
    if request.method == 'GET':
        return render_template('login.html')

    # Handle POST request to process login
    elif request.method == 'POST':
        # Validate the origin of the request
        origin = request.headers.get('Origin')
        if not origin or "yourdomain.com" not in origin:
            return "Invalid origin", 403

        # Sanitize inputs
        username = escape(request.form.get('username', '').strip())
        password = escape(request.form.get('password', '').strip())
        role = escape(request.form.get('role', '').strip())

        # Admin Login
        if role == "admin":
            if username == admin_username and password == admin_password:
                session['role'] = 'admin'
                session['user_id'] = 0
                flash('Logged in as Admin.')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid Admin credentials!')

        # Manager/User Login
        else:
            user = User.query.filter_by(username=username, password=password, role=role).first()
            if user:
                session['user_id'] = user.id
                session['role'] = user.role
                flash(f"Logged in as {role.capitalize()}.")
                if role == "manager":
                    return redirect(url_for('manager_dashboard'))
                elif role == "user":
                    return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid credentials or role selection!')

        return redirect(url_for('login'))

    # Reject other HTTP methods explicitly
    return METHOD_NOT_ALLOWED_MESSAGE, 405


@application.route('/register', methods=['GET', 'POST'])
@csrf.exempt  # Remove this line if you want to enable CSRF for both GET and POST
@limiter.limit("3 per minute")  # Limit to 3 registration attempts per minute
def register():
    if request.method == 'GET':
        # Render the registration form
        return render_template('register.html')

    elif request.method == 'POST':
        # Sanitize and validate inputs
        username = escape(request.form['username'].strip())
        email = escape(request.form['email'].strip())
        password = escape(request.form['password'].strip())

        # Basic validation
        if not username or not email or not password:
            flash("All fields are required!")
            return redirect(url_for('register'))

        # Check for unique username and email
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists!')
            return redirect(url_for('register'))

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Create a new user
        new_user = User(username=username, email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    

@application.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))


@application.route('/admin', methods=['GET'])
@limiter.limit("10 per minute")
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        managers = User.query.filter_by(role='manager').all()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            new_manager = User(username=username, password=password, role='manager')
            db.session.add(new_manager)
            db.session.commit()
            flash('Turf Manager added successfully.')
        return render_template('admin_dashboard.html', managers=managers)
    return redirect(url_for('login'))

@application.route('/admin/add_manager', methods=['POST'])
def add_manager():
    if 'role' in session and session['role'] == 'admin':
        username = request.form['username']
        email = request.form['email']  # Retrieve the email
        password = request.form['password']

        # Check for existing email or username
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists!')
            return redirect(url_for('admin_dashboard'))

        # Add the new manager
        new_manager = User(username=username, email=email, password=password, role='manager')
        db.session.add(new_manager)
        db.session.commit()
        flash('Turf Manager added successfully.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@application.route('/admin/edit_manager/<int:manager_id>', methods=['GET'])

def edit_manager(manager_id):
    if 'role' in session and session['role'] == 'admin':
        manager = User.query.get(manager_id)
        if manager and manager.role == 'manager':
            return render_template('edit_manager.html', manager=manager)
        flash('Turf Manager not found.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@application.route('/admin/update_manager', methods=['POST'])
def update_manager():
    if 'role' in session and session['role'] == 'admin':
        manager_id = request.form['manager_id']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']  # New password, if provided

        manager = User.query.get(manager_id)
        if manager and manager.role == 'manager':
            # Update fields
            manager.username = username
            manager.email = email
            if password:  # Only update password if a new one is provided
                manager.password = password

            try:
                db.session.commit()
                flash('Turf Manager updated successfully.')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating manager: {str(e)}')
            return redirect(url_for('admin_dashboard'))

        flash('Turf Manager not found.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@application.route('/admin/delete_manager', methods=['POST'])
def delete_manager():
    if 'role' in session and session['role'] == 'admin':
        manager_id = request.form['manager_id']
        manager = User.query.get(manager_id)
        if manager:
            db.session.delete(manager)
            db.session.commit()
            flash('Turf Manager deleted successfully.')
        return redirect(url_for('admin_dashboard'))
        
        
        
@application.route('/manager_dashboard', methods=['GET'])
@limiter.limit("10 per minute")  # Limit GET requests to prevent abuse
def manager_dashboard():
    if session.get('role') != 'manager':
        return redirect(url_for('login'))

    # Fetch all turfs managed by the logged-in manager
    turfs = Turf.query.filter_by(manager_id=session['user_id']).all()
    print(f"Manager ID: {session['user_id']}, Turfs Count: {len(turfs)}")
    return render_template('manager_dashboard.html', turfs=turfs)


@application.route('/manager_dashboard/add_turf', methods=['POST'])
@csrf.exempt  # Remove this line if CSRF protection is enabled
@limiter.limit("5 per minute")  # Limit POST requests to prevent abuse
def add_turf():
    if session.get('role') != 'manager':
        return redirect(url_for('login'))

    # Validate and sanitize inputs
    name = escape(request.form.get('name', '').strip())
    location = escape(request.form.get('location', '').strip())
    price = request.form.get('price', '').strip()
    photo = request.files.get('photo')
    time_slots = request.form.getlist('time_slots[]')  # Fetch list of time slots

    try:
        # Validate required fields
        if not name or not location or not price or not time_slots or not photo:
            flash('All fields are required.')
            return redirect(url_for('manager_dashboard'))

        # Validate price
        try:
            price = float(price)
            if price <= 0:
                raise ValueError("Price must be positive.")
        except ValueError:
            flash('Invalid price. Please enter a positive number.')
            return redirect(url_for('manager_dashboard'))

        # Process time slots
        time_slots_str = ','.join([escape(slot) for slot in time_slots])

        # Process photo data
        photo_data = photo.read()
        photo_name = secure_filename(photo.filename)

        # Add new turf
        turf = Turf(
            name=name,
            location=location,
            price=price,
            time_slots=time_slots_str,
            photo_data=photo_data,
            photo_name=photo_name,
            manager_id=session['user_id']
        )
        db.session.add(turf)
        db.session.commit()
        flash('Turf added successfully!')

    except Exception as e:
        flash(f"Error adding turf: {str(e)}")
        db.session.rollback()

    return redirect(url_for('manager_dashboard'))
    
    
# Route to serve the image from the database
@application.route('/turf_image/<int:turf_id>')
def turf_image(turf_id):
    turf = Turf.query.get(turf_id)
    if turf and turf.photo_data:
        return send_file(
            io.BytesIO(turf.photo_data),
            mimetype='image/jpeg',  # Adjust MIME type based on your images
            as_attachment=False,
            download_name=turf.photo_name
        )
    return METHOD_NOT_ALLOWED_MESSAGE, 405
    

@application.route('/view_turfs', methods=['GET'])
def view_turfs():
    if 'user_id' in session and session.get('role') == 'manager':
        # Fetch turfs for the logged-in manager
        turfs = Turf.query.filter_by(manager_id=session['user_id']).all()

        for turf in turfs:
            # Split the time_slots string into a list
            turf.time_slots_list = turf.time_slots.split(',') if turf.time_slots else []

            # Fetch valid bookings for this turf
            turf.bookings = Booking.query.filter_by(turf_id=turf.id).all()

            # Attach user details to bookings
            for booking in turf.bookings:
                booking.user = User.query.get(booking.user_id)  # Fetch and attach user details

            # Mark booked slots
            turf.booked_slots = [
                booking.time_slot for booking in turf.bookings if booking.status == 'Accepted'
            ]

        return render_template('view_turfs.html', turfs=turfs)
    return redirect(url_for('login'))
    
    
@application.route('/debug_turfs', methods=['GET'])
@csrf.exempt  # CSRF is disabled, but additional safeguards are implemented
@limiter.limit("2 per minute")
def debug_turfs():
    # Log access for auditing
    logging.info(f"Debug turfs accessed by user: {session.get('user_id')}, role: {session.get('role')}")

    # Restrict access to admins only
    if 'role' not in session or session['role'] != 'admin':
        return "Unauthorized", 403

    # Fetch turfs and return limited data
    turfs = Turf.query.all()
    return jsonify({turf.id: {"name": turf.name} for turf in turfs})  



@application.route('/manager/edit_turf/<int:turf_id>', methods=['GET', 'POST'])
@csrf.exempt  # Remove this line if enabling CSRF protection
@limiter.limit("5 per minute")  # Limit editing attempts to 5 per minute
def edit_turf(turf_id):
    def validate_price(price):
        """Validate the price input."""
        try:
            price = float(price)
            if price <= 0:
                raise ValueError("Price must be positive.")
            return price
        except ValueError:
            return None

    # Ensure the user is logged in and is a manager
    if 'user_id' not in session or session.get('role') != 'manager':
        flash("Unauthorized access. Please log in as a manager.")
        return redirect(url_for('login'))

    # Fetch the turf by ID
    turf = Turf.query.get(turf_id)
    if not turf or turf.manager_id != session['user_id']:
        flash('Unauthorized access or Turf not found.')
        return redirect(url_for('view_turfs'))

    if request.method == 'GET':
        # Prepare time slots for the edit form
        time_slots_list = turf.time_slots.split(',') if turf.time_slots else []
        return render_template('edit_turf.html', turf=turf, time_slots_list=time_slots_list)

    # Handle POST request
    try:
        # Validate and sanitize inputs
        turf.name = escape(request.form.get('name', '').strip())
        turf.location = escape(request.form.get('location', '').strip())

        # Validate and update price
        price = validate_price(request.form.get('price', '').strip())
        if price is None:
            flash('Invalid price. Please enter a positive number.')
            return redirect(url_for('edit_turf', turf_id=turf_id))
        turf.price = price

        # Handle photo upload
        photo = request.files.get('photo')
        if photo:
            filename = secure_filename(photo.filename)
            turf.photo_data = photo.read()
            turf.photo_name = filename

        # Save changes to the database
        db.session.commit()
        flash('Turf updated successfully!')
        return redirect(url_for('view_turfs'))

    except Exception as e:
        db.session.rollback()
        flash(f"Error updating turf: {str(e)}")
        return redirect(url_for('edit_turf', turf_id=turf_id))

   

@application.route('/manager/delete_turf', methods=['POST'])
def delete_turf():
    if 'user_id' in session and session['role'] == 'manager':
        turf_id = request.form['turf_id']
        turf = Turf.query.get(turf_id)
        if turf and turf.manager_id == session['user_id']:
            db.session.delete(turf)
            db.session.commit()
            flash('Turf and its bookings deleted successfully.')
        else:
            flash('Unauthorized action or Turf not found.')
    return redirect(url_for('manager_dashboard'))


@application.route('/manager/accept_booking', methods=['POST'])
def accept_booking():
    if 'user_id' in session and session.get('role') == 'manager':
        booking_id = request.form['booking_id']
        booking = Booking.query.get(booking_id)
        if booking:
            # Check if the booking belongs to a turf managed by the current manager
            turf = Turf.query.get(booking.turf_id)
            if turf and turf.manager_id == session['user_id']:
                booking.status = 'Accepted'
                db.session.commit()
                flash('Booking accepted successfully!')
            else:
                flash('Unauthorized action.')
        else:
            flash('Booking not found.')
        return redirect(url_for('view_turfs'))
    return redirect(url_for('login'))


@application.route('/user_dashboard', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Limit user dashboard access to 10 requests per minute
def user_dashboard():
    if session.get('role') != 'user':
        flash("Unauthorized access. Please log in as a user.")
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_user_dashboard()

    if request.method == 'POST':
        return process_booking_request()

    return "Method Not Allowed", 405


def render_user_dashboard():
    """Retrieve and render turfs for the user dashboard."""
    turfs = Turf.query.all()

    # Process turfs to include available and booked slots
    for turf in turfs:
        turf.time_slots_list = turf.time_slots.split(',') if turf.time_slots else []
        turf.booked_slots = [
            b.time_slot for b in Booking.query.filter_by(turf_id=turf.id, status='Accepted').all()
        ]

    return render_template('user_dashboard.html', turfs=turfs)


def process_booking_request():
    """Handle booking requests from the user."""
    try:
        turf_id = validate_and_get_turf_id(request.form.get('turf_id', '').strip())
        time_slot = escape(request.form.get('time_slot', '').strip())
        if not validate_and_create_booking(turf_id, time_slot):
            return redirect(url_for('user_dashboard'))
    except ValueError:
        flash("Invalid input. Please select a valid turf and time slot.")
    except Exception as e:
        db.session.rollback()
        flash(f"Error processing booking: {str(e)}")
    return redirect(url_for('user_dashboard'))


def validate_and_get_turf_id(turf_id):
    """Validate and parse the turf ID."""
    try:
        return int(turf_id)
    except ValueError:
        raise ValueError("Invalid turf ID")


def validate_and_create_booking(turf_id, time_slot):
    """Validate the booking and create it if valid."""
    turf = Turf.query.get(turf_id)
    if not turf:
        flash("Invalid turf selection.")
        return False

    existing_booking = Booking.query.filter_by(
        turf_id=turf_id, time_slot=time_slot, status='Accepted'
    ).first()
    if existing_booking:
        flash("This slot is already booked!")
        return False

    create_booking(turf_id, time_slot)
    return True


def create_booking(turf_id, time_slot):
    """Create a new booking."""
    booking = Booking(
        turf_id=turf_id,
        user_id=session['user_id'],
        time_slot=time_slot
    )
    db.session.add(booking)
    db.session.commit()
    flash("Booking request submitted successfully!")
    

@application.route('/user/book_turf', methods=['POST'])
def book_turf():
    if 'user_id' in session:
        turf_id = request.form['turf_id']
        time_slot = request.form['time_slot']
        booking = Booking(
            turf_id=turf_id,
            user_id=session['user_id'],
            time_slot=time_slot,
            status='Pending'
        )
        db.session.add(booking)
        db.session.commit()
        flash('Booking request submitted!')
        return redirect(url_for('user_dashboard'))
    else:
        return redirect(url_for('login'))


@application.route('/history', methods=['GET'])
def booking_history():
    if 'user_id' in session:
        bookings = Booking.query.filter_by(user_id=session['user_id']).all()
        for booking in bookings:
            # Fetch additional details about the turf
            turf = Turf.query.get(booking.turf_id)
            booking.turf_name = turf.name
            booking.price = turf.price
        return render_template('booking_history.html', bookings=bookings)
    else:
        return redirect(url_for('user_dashboard.html'))

@application.route('/delete_booking', methods=['POST'])
def delete_booking():
    if 'user_id' in session and session['role'] == 'user':
        booking_id = request.form['booking_id']
        booking = Booking.query.get(booking_id)

        if booking and booking.user_id == session['user_id']:
            db.session.delete(booking)
            db.session.commit()
            flash('Booking deleted successfully.')
        else:
            flash('Unauthorized action or booking not found.')

    return redirect(url_for('booking_history'))
    
@application.route('/debug')
def debug():
    turfs = Turf.query.all()
    return {turf.id: turf.photo for turf in turfs}
    


if __name__ == '__main__':
    # Ensure the database is initialized
    with application.app_context():
        db.create_all()

    # Use environment variables to manage configurations
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8080"))

    # Run the application with debug mode disabled by default
    application.run(debug=debug_mode, host=host, port=port)

