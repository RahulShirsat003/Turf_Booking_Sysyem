"""
This is a flask based application for DeVopsSec
"""
import os
import io
from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError 


"""
A Flask application for a turf booking system.
Handles user authentication, turf management, and booking functionalities.
"""

# Load environment variables
load_dotenv()

# Initialize the Flask application
application = Flask(__name__)
application.secret_key = os.getenv('SECRET_KEY')

# Configure the SQLite database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
application.config['SQLALCHEMY_DATABASE_URI'] = (
    f'sqlite:///{os.path.join(BASE_DIR, "turf_system.db")}'
)
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(application)


class User(db.Model):
    """Model for user accounts."""
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)


class Turf(db.Model):
    """Model for turf details."""
    __tablename__ = 'turf'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    time_slots = db.Column(db.String(500), nullable=False)
    photo_data = db.Column(db.LargeBinary, nullable=True)
    photo_name = db.Column(db.String(120), nullable=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bookings = db.relationship('Booking', backref='turf', cascade="all, delete-orphan")


class Booking(db.Model):
    """Model for turf bookings."""
    __tablename__ = 'booking'
    id = db.Column(db.Integer, primary_key=True)
    turf_id = db.Column(db.Integer, db.ForeignKey('turf.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_slot = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')


def validate_admin_credentials(username, password):
    """
    Validate admin credentials from environment variables.

    Args:
        username (str): Admin username.
        password (str): Admin password.

    Returns:
        bool: True if credentials are valid, otherwise False.
    """
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if not admin_username or not admin_password:
        raise ValueError("Admin username or password environment variables are not set")
    return username == admin_username and password == admin_password


@application.route('/')
def home():
    """Render the home page."""
    return render_template('home.html')


@application.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.

    Allows admin, managers, and users to log in based on their roles.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if role == "admin" and validate_admin_credentials(username, password):
            session['role'] = 'admin'
            session['user_id'] = 0
            flash('Logged in as Admin.')
            return redirect(url_for('admin_dashboard'))

        user = User.query.filter_by(username=username, password=password, role=role).first()
        if user:
            session['user_id'] = user.id
            session['role'] = user.role
            flash(f"Logged in as {role.capitalize()}.")
            return redirect(url_for(f"{role}_dashboard"))

        flash('Invalid credentials or role selection!')
    return render_template('login.html')


@application.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))


@application.route('/register', methods=['GET', 'POST'])
def register():
    """
    Register a new user.

    Validates and creates a user account.
    """
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists!')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@application.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    """
    Admin dashboard to manage turf managers.

    Allows admin to add and view managers.
    """
    if session.get('role') == 'admin':
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
    """
    Add a new turf manager.

    This route is accessible only to admins. Checks if the username or email 
    already exists before adding the new manager.
    """
    if session.get('role') == 'admin':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the user already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash('Username or email already exists!')
            return redirect(url_for('admin_dashboard'))

        # Create a new manager
        new_manager = User(username=username, email=email, password=password, role='manager')
        db.session.add(new_manager)
        db.session.commit()
        flash('Turf Manager added successfully.')
        return redirect(url_for('admin_dashboard'))
    flash('you dont have Unauthorized access.')
    return redirect(url_for('login'))


@application.route('/admin/edit_manager/<int:manager_id>', methods=['GET'])
def edit_manager(manager_id):
    """
    Edit a turf manager's details.

    Args:
        manager_id (int): ID of the manager to edit.

    Returns:
        Renders the edit manager page if the manager exists and the user 
        has admin privileges.
    """
    if session.get('role') == 'admin':
        manager = User.query.get(manager_id)
        if manager and manager.role == 'manager':
            return render_template('edit_manager.html', manager=manager)
        flash('Turf Manager not found.')
        return redirect(url_for('admin_dashboard'))
    flash('Unauthorized access.')
    return redirect(url_for('login'))


@application.route('/admin/update_manager', methods=['POST'])
def update_manager():
    """
    Update a turf manager's details.

    Args:
        manager_id (int): ID of the manager to update.
        username (str): New username.
        email (str): New email.
        password (str, optional): New password.

    Returns:
        Redirects to the admin dashboard after updating the manager.
    """
    if session.get('role') == 'admin':
        manager_id = request.form['manager_id']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Fetch the manager to update
        manager = User.query.get(manager_id)
        if manager and manager.role == 'manager':
            manager.username = username
            manager.email = email
            if password:
                manager.password = password

            try:
                db.session.commit()
                flash('Turf Manager updated successfully.')
            except SQLAlchemyError as db_error:  # Catch specific SQLAlchemy errors
                db.session.rollback()
                flash(f'Error updating manager: {db_error}')
            return redirect(url_for('admin_dashboard'))

        flash('manager not found.')
        return redirect(url_for('admin_dashboard'))
    flash('not have access.')
    return redirect(url_for('login'))
    

@application.route('/admin/delete_manager', methods=['POST'])
def delete_manager():
    """
    Delete a turf manager.

    Args:
        manager_id (int): ID of the manager to delete.

    Returns:
        Redirects to the admin dashboard after deletion.
    """
    if session.get('role') == 'admin':
        manager_id = request.form['manager_id']
        manager = User.query.get(manager_id)
        if manager:
            db.session.delete(manager)
            db.session.commit()
            flash('Turf Manager deleted successfully.')
        else:
            flash('No turf manager.')
        return redirect(url_for('admin_dashboard'))
    flash('no access.')
    return redirect(url_for('login'))
    
@application.route('/manager_dashboard', methods=['GET', 'POST'])
def manager_dashboard():
    """Dashboard for turf managers."""
    if session.get('role') == 'manager':
        if request.method == 'POST':
            name = request.form['name']
            location = request.form['location']
            price = float(request.form['price'])
            time_slots = request.form.getlist('time_slots[]')
            photo = request.files['photo']

            if not time_slots:
                flash('Please add at least one time slot.')
                return redirect(url_for('manager_dashboard'))

            turf = Turf(
                name=name,
                location=location,
                price=price,
                time_slots=','.join(time_slots),
                photo_data=photo.read(),
                photo_name=secure_filename(photo.filename),
                manager_id=session['user_id']
            )
            db.session.add(turf)
            db.session.commit()
            flash('Turf added successfully.')

        turfs = Turf.query.filter_by(manager_id=session['user_id']).all()
        return render_template('manager_dashboard.html', turfs=turfs)
    return redirect(url_for('login'))
    
@application.route('/turf_image/<int:turf_id>')
def turf_image(turf_id):
    """
    Retrieve the image for a specified turf.

    Args:
        turf_id (int): ID of the turf.

    Returns:
        Flask response: The image file if available, or a 404 error.
    """
    turf = Turf.query.get(turf_id)
    if turf and turf.photo_data:
        return send_file(
            io.BytesIO(turf.photo_data),
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=turf.photo_name
        )
    return 'No image available', 404


@application.route('/view_turfs', methods=['GET'])
def view_turfs():
    """
    Display all turfs for the logged-in manager.

    Returns:
        Renders the turfs view page if the user is a manager,
        otherwise redirects to the login page.
    """
    if 'user_id' in session and session.get('role') == 'manager':
        turfs = Turf.query.filter_by(manager_id=session['user_id']).all()

        for turf in turfs:
            # Parse time slots into a list
            turf.time_slots_list = turf.time_slots.split(',') if turf.time_slots else []

            # Retrieve bookings for the turf
            turf.bookings = Booking.query.filter_by(turf_id=turf.id).all()

            # Assign users to bookings
            for booking in turf.bookings:
                booking.user = User.query.get(booking.user_id)

            # Get booked slots
            turf.booked_slots = [
                booking.time_slot
                for booking in turf.bookings if booking.status == 'Accepted'
            ]

        return render_template('view_turfs.html', turfs=turfs)

    return redirect(url_for('login'))


@application.route('/debug_turfs')
def debug_turfs():
    """
    Debug endpoint to view all turfs.

    Returns:
        dict: A dictionary with turf details.
    """
    turfs = Turf.query.all()
    return {
        turf.id: {
            "name": turf.name,
            "manager_id": turf.manager_id,
            "time_slots": turf.time_slots
        }
        for turf in turfs
    }


@application.route('/manager/edit_turf/<int:turf_id>', methods=['GET', 'POST'])
def edit_turf(turf_id):
    """
    Edit a specific turf for the logged-in manager.

    Args:
        turf_id (int): ID of the turf to edit.

    Returns:
        Renders the edit turf page or redirects based on the session and input.
    """
    if 'user_id' in session and session.get('role') == 'manager':
        turf = Turf.query.get(turf_id)

        if not turf or turf.manager_id != session['user_id']:
            flash('Unauthorized access or Turf not found.')
            return redirect(url_for('view_turfs'))

        if request.method == 'POST':
            turf.name = request.form['name']
            turf.location = request.form['location']
            turf.price = request.form['price']

            photo = request.files['photo']

            if photo:
                # Update photo data if provided
                filename = secure_filename(photo.filename)
                turf.photo_name = filename
                turf.photo_data = photo.read()

            db.session.commit()
            flash('Turf updated successfully!')
            return redirect(url_for('view_turfs'))

        # Parse time slots into a list
        time_slots_list = turf.time_slots.split(',') if turf.time_slots else []
        return render_template('edit_turf.html', turf=turf, time_slots_list=time_slots_list)

    return redirect(url_for('login'))


@application.route('/manager/delete_turf', methods=['POST'])
def delete_turf():
    """
    Delete a turf for the logged-in manager.

    Returns:
        Redirects to the manager dashboard.
    """
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
    """
    Allow a manager to accept a booking for their turf.

    Returns:
        Redirects to the turfs view page after updating booking status.
    """
    if 'user_id' in session and session.get('role') == 'manager':
        booking_id = request.form['booking_id']
        booking = Booking.query.get(booking_id)

        if booking:
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
def user_dashboard():
    """
    Display the user dashboard and handle turf booking requests.

    Returns:
        Renders the user dashboard or redirects to login if not authenticated.
    """
    if session.get('role') != 'user':
        return redirect(url_for('login'))

    turfs = Turf.query.all()

    for turf in turfs:
        # Parse time slots into a list
        turf.time_slots_list = turf.time_slots.split(',') if turf.time_slots else []

        # Identify already booked slots
        bookings = Booking.query.filter_by(turf_id=turf.id, status='Accepted').all()
        turf.booked_slots = [booking.time_slot for booking in bookings]

    if request.method == 'POST':
        turf_id = int(request.form['turf_id'])
        time_slot = request.form['time_slot']

        # Check if the time slot is already booked
        existing_booking = Booking.query.filter_by(
            turf_id=turf_id, time_slot=time_slot, status='Accepted'
        ).first()
        if existing_booking:
            flash("This slot is already booked!")
        else:
            booking = Booking(
                turf_id=turf_id,
                user_id=session['user_id'],
                time_slot=time_slot
            )
            db.session.add(booking)
            db.session.commit()
            flash("Booking request submitted!")

    return render_template('user_dashboard.html', turfs=turfs)


@application.route('/user/book_turf', methods=['POST'])
def book_turf():
    """
    Handle turf booking requests from users.

    Returns:
        Redirects to the user dashboard after booking.
    """
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

    return redirect(url_for('login'))


@application.route('/history', methods=['GET'])
def booking_history():
    """
    Display the booking history for the logged-in user.

    Returns:
        Renders the booking history page.
    """
    if 'user_id' in session:
        bookings = Booking.query.filter_by(user_id=session['user_id']).all()

        for booking in bookings:
            turf = Turf.query.get(booking.turf_id)
            booking.turf_name = turf.name
            booking.price = turf.price

        return render_template('booking_history.html', bookings=bookings)

    return redirect(url_for('user_dashboard'))


@application.route('/delete_booking', methods=['POST'])
def delete_booking():
    """
    Allow a user to delete a booking.

    Returns:
        Redirects to the booking history page after deletion.
    """
    if 'user_id' in session and session.get('role') == 'user':
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
    """
    Debug endpoint to view turf photo details.

    Returns:
        dict: Turf details including ID and photo.
    """
    turfs = Turf.query.all()
    return {turf.id: turf.photo for turf in turfs}


if __name__ == '__main__':
    # Create database tables if they don't exist
    with application.app_context():
        db.create_all()

    application.run(
        debug=os.getenv("FLASK_DEBUG", "False").lower() == "true",
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "8080"))
    )
    