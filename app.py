import os
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import boto3
import uuid
from botocore.exceptions import NoCredentialsError

app = Flask(__name__)
app.secret_key = 'turfbookingsecret'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/ec2-user/environment/TurfBookingSystem/database/turf_system.db'
app.config['UPLOAD_FOLDER'] = '/home/ec2-user/TurfBookingSystem/environment/static/uploads'
db = SQLAlchemy(app)  # Initialize SQLAlchemy only once

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Ensure the database folder exists
if not os.path.exists('/home/ec2-user/environment/TurfBookingSystem/database'):
    os.makedirs('/home/ec2-user/environment/TurfBookingSystem/database')
    

app.config['AWS_S3_BUCKET'] = 'turfbucket'
app.config['AWS_REGION'] = 'eu-west-1'  # e.g., 'us-east-1'

# Initialize S3 client
s3_client = boto3.client('s3', region_name=app.config['AWS_REGION'])


def upload_file_to_s3(file, bucket_name):
    filename = secure_filename(file.filename)
    new_filename = f"{uuid.uuid4().hex}_{filename}"  # Generate a unique filename
    try:
        s3_client.upload_fileobj(
            file,
            bucket_name,
            new_filename,
            ExtraArgs={"ACL": "public-read", "ContentType": file.content_type}
        )
        return f"https://{bucket_name}.s3.{app.config['AWS_REGION']}.amazonaws.com/{new_filename}"
    except Exception as e:
        print(f"Error uploading file to S3: {e}")
        return None


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
    photo = db.Column(db.String(120), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bookings = db.relationship('Booking', backref='turf', cascade="all, delete-orphan")


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    turf_id = db.Column(db.Integer, db.ForeignKey('turf.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_slot = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    admin_username = "admin"
    admin_password = "admin123"

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Handle Admin Login
        if role == "admin":
            if username == admin_username and password == admin_password:
                session['role'] = 'admin'
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid Admin credentials!')

        # Handle Turf Manager and User Login
        else:
            user = User.query.filter_by(username=username, password=password).first()
            if user and user.role == role:
                session['user_id'] = user.id
                session['role'] = user.role
                if role == 'manager':
                    return redirect(url_for('manager_dashboard'))
                elif role == 'user':
                    return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid credentials or role selection!')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check for unique username and email
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists!')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(username=username, email=email, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
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

@app.route('/admin/add_manager', methods=['POST'])
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

@app.route('/admin/edit_manager/<int:manager_id>', methods=['GET'])
def edit_manager(manager_id):
    if 'role' in session and session['role'] == 'admin':
        manager = User.query.get(manager_id)
        if manager and manager.role == 'manager':
            return render_template('edit_manager.html', manager=manager)
        flash('Turf Manager not found.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/admin/update_manager', methods=['POST'])
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

@app.route('/admin/delete_manager', methods=['POST'])
def delete_manager():
    if 'role' in session and session['role'] == 'admin':
        manager_id = request.form['manager_id']
        manager = User.query.get(manager_id)
        if manager:
            db.session.delete(manager)
            db.session.commit()
            flash('Turf Manager deleted successfully.')
        return redirect(url_for('admin_dashboard'))


@app.route('/manager_dashboard', methods=['GET', 'POST'])
def manager_dashboard():
    if 'user_id' in session and session['role'] == 'manager':
        if request.method == 'POST':
            name = request.form['name']
            location = request.form['location']
            price = request.form['price']
            photo = request.files['photo']

            # Combine custom slots into a comma-separated string
            custom_slots = request.form.getlist('custom_slots[]')
            time_slots = ','.join(custom_slots)

            if photo:
                # Upload photo to S3
                s3_url = upload_file_to_s3(photo, app.config['AWS_S3_BUCKET'])
                if not s3_url:
                    flash('Failed to upload image to S3.')
                    return redirect(url_for('manager_dashboard'))

                # Save turf details to the database
                turf = Turf(
                    name=name,
                    location=location,
                    price=float(price),
                    time_slots=time_slots,
                    photo=s3_url,  # Store the S3 URL in the database
                    manager_id=session['user_id']
                )
                db.session.add(turf)
                db.session.commit()
                flash('Turf added successfully!')
        turfs = Turf.query.filter_by(manager_id=session['user_id']).all()
        return render_template('manager_dashboard.html', turfs=turfs)
    return redirect(url_for('login'))


@app.route('/view_turfs', methods=['GET'])
def view_turfs():
    if 'user_id' in session and session.get('role') == 'manager':
        turfs = Turf.query.filter_by(manager_id=session['user_id']).all()
        for turf in turfs:
            # Split the time_slots string into a list
            turf.time_slots_list = turf.time_slots.split(',') if turf.time_slots else []

            # Fetch valid bookings for this turf
            turf.bookings = (
                Booking.query.filter_by(turf_id=turf.id)
                .filter(Booking.status != 'Deleted')  # Ensure we filter out deleted bookings
                .all()
            )

            # Attach user details to bookings
            for booking in turf.bookings:
                booking.user = User.query.get(booking.user_id)

            # Mark booked slots
            turf.booked_slots = [
                booking.time_slot for booking in turf.bookings if booking.status == 'Accepted'
            ]

        return render_template('view_turfs.html', turfs=turfs)
    return redirect(url_for('login'))

@app.route('/manager/edit_turf/<int:turf_id>', methods=['GET', 'POST'])
def edit_turf(turf_id):
    if 'user_id' in session and session.get('role') == 'manager':
        turf = Turf.query.get(turf_id)

        if not turf or turf.manager_id != session['user_id']:
            flash('Unauthorized access or Turf not found.')
            return redirect(url_for('view_turfs'))

        if request.method == 'POST':
            turf.name = request.form['name']
            turf.location = request.form['location']
            turf.price = request.form['price']
            time_slots = ','.join(request.form.getlist('custom_slots[]'))

            photo = request.files['photo']
            if photo:
                s3_url = upload_file_to_s3(photo, app.config['AWS_S3_BUCKET'])
                if s3_url:
                    turf.photo = s3_url  # Update photo URL if a new image is uploaded

            turf.time_slots = time_slots
            db.session.commit()
            flash('Turf updated successfully!')
            return redirect(url_for('view_turfs'))

        time_slots_list = turf.time_slots.split(',') if turf.time_slots else []
        return render_template('edit_turf.html', turf=turf, time_slots_list=time_slots_list)
    else:
        return redirect(url_for('login'))
        

@app.route('/manager/delete_turf', methods=['POST'])
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


@app.route('/manager/accept_booking', methods=['POST'])
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


@app.route('/user', methods=['GET', 'POST'])
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        turfs = Turf.query.all()
        for turf in turfs:
            turf.time_slots_list = turf.time_slots.split(',')
            bookings = Booking.query.filter_by(turf_id=turf.id, status='Accepted').all()
            turf.booked_slots = [b.time_slot for b in bookings]

        if request.method == 'POST':
            turf_id = request.form['turf_id']
            time_slot = request.form['time_slot']
            booked_slots = [b.time_slot for b in Booking.query.filter_by(turf_id=turf_id, status='Accepted').all()]
            if time_slot in booked_slots:
                flash('Slot already booked. Choose another slot.')
            else:
                booking = Booking(turf_id=turf_id, user_id=session['user_id'], time_slot=time_slot, status='Pending')
                db.session.add(booking)
                db.session.commit()
                flash('Booking submitted!')
        return render_template('user_dashboard.html', turfs=turfs)
    return redirect(url_for('login'))

@app.route('/user/book_turf', methods=['POST'])
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


@app.route('/history', methods=['GET'])
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
        return redirect(url_for('login'))

@app.route('/delete_booking', methods=['POST'])
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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database tables are created within the app context.
    app.run(debug=True, host='0.0.0.0', port=8080)
# Paste the revised app.py here (already provided earlier)
