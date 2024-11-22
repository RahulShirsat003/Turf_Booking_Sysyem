
import uuid
from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal  # Import Decimal to handle numeric values for DynamoDB


application = Flask(__name__)
application.secret_key = 'turfbookingsecret'

# AWS Configuration
application.config['AWS_REGION'] = 'eu-west-1'
application.config['AWS_S3_BUCKET'] = 'turfbucket'
application.config['DYNAMO_DB_USERS_TABLE'] = 'Users_turfbooking'
application.config['DYNAMO_DB_TURFS_TABLE'] = 'Turfs_turfbooking'
application.config['DYNAMO_DB_BOOKINGS_TABLE'] = 'Bookings_turfbooking'

# Initialize AWS Clients
s3_client = boto3.client('s3', region_name=application.config['AWS_REGION'])
dynamodb = boto3.resource('dynamodb', region_name=application.config['AWS_REGION'])

# Helper Functions to Create Tables
def create_table_if_not_exists(table_name, key_schema, attribute_definitions, provisioned_throughput):
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            ProvisionedThroughput=provisioned_throughput
        )
        table.wait_until_exists()
        print(f"Table {table_name} created successfully!")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table {table_name} already exists.")
        else:
            print(f"Error creating table {table_name}: {e}")

# Create DynamoDB Tables
def initialize_dynamo_tables():
    create_table_if_not_exists(
        application.config['DYNAMO_DB_USERS_TABLE'],
        key_schema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        attribute_definitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        provisioned_throughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
    )

    create_table_if_not_exists(
        application.config['DYNAMO_DB_TURFS_TABLE'],
        key_schema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        attribute_definitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        provisioned_throughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
    )

    create_table_if_not_exists(
        application.config['DYNAMO_DB_BOOKINGS_TABLE'],
        key_schema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        attribute_definitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        provisioned_throughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
    )

# Helper Functions for DynamoDB
def get_table(table_name):
    return dynamodb.Table(table_name)

def get_item(table_name, key):
    table = get_table(table_name)
    try:
        response = table.get_item(Key=key)
        return response.get('Item', None)
    except ClientError as e:
        print(f"Error getting item from {table_name}: {e}")
        return None

def put_item(table_name, item):
    table = get_table(table_name)
    try:
        table.put_item(Item=item)
    except ClientError as e:
        print(f"Error putting item into {table_name}: {e}")
        
        
# S3 Helper Function for File Upload
def upload_file_to_s3(file, bucket_name):
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    try:
        s3_client.upload_fileobj(
            file,
            bucket_name,
            unique_filename,
            ExtraArgs={"ACL": "public-read", "ContentType": file.content_type}
        )
        return f"https://{bucket_name}.s3.{application.config['AWS_REGION']}.amazonaws.com/{unique_filename}"
    except Exception as e:
        print(f"Error uploading file to S3: {e}")
        return None
        

# Routes
@application.route('/')
def home():
    return render_template('home.html')

@application.route('/login', methods=['GET', 'POST'])
def login():
    # Hardcoded admin credentials
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if admin is logging in
        if role == "admin":
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session['user_id'] = "admin-id"  # A unique identifier for admin
                session['role'] = "admin"
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid admin credentials!")

        else:
            # Check for non-admin users in the DynamoDB table
            table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
            try:
                response = table.scan(
                    FilterExpression="#username = :u AND password = :p AND #role = :r",
                    ExpressionAttributeValues={
                        ":u": username,
                        ":p": password,
                        ":r": role
                    },
                    ExpressionAttributeNames={
                        "#username": "username",
                        "#role": "role"
                    }
                )
                user = response['Items'][0] if response['Items'] else None

                if user:
                    session['user_id'] = user['id']
                    session['role'] = user['role']
                    if role == 'manager':
                        return redirect(url_for('manager_dashboard'))
                    elif role == 'user':
                        return redirect(url_for('user_dashboard'))
                else:
                    flash("Invalid credentials!")
            except ClientError as e:
                print(f"Error during login: {e}")
                flash("An error occurred while logging in.")
    return render_template('login.html')

@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_id = str(uuid.uuid4())

        table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
        response = table.scan(FilterExpression="username = :u OR email = :e",
                              ExpressionAttributeValues={":u": username, ":e": email})
        if response['Items']:
            flash('Username or email already exists!')
            return redirect(url_for('register'))

        put_item(application.config['DYNAMO_DB_USERS_TABLE'], {
            'id': user_id,
            'username': username,
            'email': email,
            'password': password,
            'role': 'user'
        })
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@application.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))


@application.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
        try:
            response = table.scan(
                FilterExpression="#role = :r",
                ExpressionAttributeValues={":r": "manager"},
                ExpressionAttributeNames={"#role": "role"}  # Alias the reserved keyword
            )
            managers = response.get('Items', [])
        except ClientError as e:
            print(f"Error fetching managers: {e}")
            flash("An error occurred while fetching managers.")
            managers = []

        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            manager_id = str(uuid.uuid4())

            # Check for existing email or username
            try:
                existing_user_response = table.scan(
                    FilterExpression="#username = :u OR email = :e",
                    ExpressionAttributeValues={":u": username, ":e": email},
                    ExpressionAttributeNames={"#username": "username"}  # Alias reserved keyword if needed
                )
                if existing_user_response.get('Items'):
                    flash('Username or email already exists!')
                    return redirect(url_for('admin_dashboard'))

                # Add the new manager
                table.put_item(Item={
                    'id': manager_id,
                    'username': username,
                    'email': email,
                    'password': password,
                    'role': 'manager'
                })
                flash('Turf Manager added successfully.')
            except ClientError as e:
                print(f"Error adding manager: {e}")
                flash("An error occurred while adding the manager.")
            return redirect(url_for('admin_dashboard'))

        return render_template('admin_dashboard.html', managers=managers)
    return redirect(url_for('login'))

@application.route('/admin/add_manager', methods=['POST'])
def add_manager():
    if 'role' in session and session['role'] == 'admin':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        manager_id = str(uuid.uuid4())  # Generate a unique ID for the manager

        # Check for existing email or username
        table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
        response = table.scan(FilterExpression="username = :u OR email = :e",
                              ExpressionAttributeValues={":u": username, ":e": email})
        if response['Items']:
            flash('Username or email already exists!')
            return redirect(url_for('admin_dashboard'))

        # Add the new manager
        put_item(application.config['DYNAMO_DB_USERS_TABLE'], {
            'id': manager_id,
            'username': username,
            'email': email,
            'password': password,
            'role': 'manager'
        })
        flash('Turf Manager added successfully.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))


@application.route('/admin/edit_manager/<manager_id>', methods=['GET'])
def edit_manager(manager_id):
    if 'role' in session and session['role'] == 'admin':
        table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
        manager = get_item(application.config['DYNAMO_DB_USERS_TABLE'], {'id': manager_id})

        if manager and manager['role'] == 'manager':
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
        password = request.form['password']

        table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
        manager = get_item(application.config['DYNAMO_DB_USERS_TABLE'], {'id': manager_id})

        if manager and manager['role'] == 'manager':
            # Update fields
            updated_data = {
                'id': manager_id,
                'username': username,
                'email': email,
                'role': 'manager'
            }
            if password:
                updated_data['password'] = password

            try:
                put_item(application.config['DYNAMO_DB_USERS_TABLE'], updated_data)
                flash('Turf Manager updated successfully.')
            except Exception as e:
                flash(f'Error updating manager: {str(e)}')
            return redirect(url_for('admin_dashboard'))

        flash('Turf Manager not found.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))


@application.route('/admin/delete_manager', methods=['POST'])
def delete_manager():
    if 'role' in session and session['role'] == 'admin':
        manager_id = request.form['manager_id']
        table = get_table(application.config['DYNAMO_DB_USERS_TABLE'])
        manager = get_item(application.config['DYNAMO_DB_USERS_TABLE'], {'id': manager_id})

        if manager and manager['role'] == 'manager':
            try:
                table.delete_item(Key={'id': manager_id})
                flash('Turf Manager deleted successfully.')
            except Exception as e:
                flash(f'Error deleting manager: {str(e)}')
        else:
            flash('Turf Manager not found.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))


@application.route('/manager_dashboard', methods=['GET', 'POST'])
def manager_dashboard():
    if 'user_id' in session and session['role'] == 'manager':
        if request.method == 'POST':
            name = request.form.get('name', '')
            location = request.form.get('location', '')
            price = request.form.get('price', '0.0')
            photo = request.files.get('photo', None)
            custom_slots = request.form.getlist('custom_slots[]')
            time_slots = ','.join(custom_slots) if custom_slots else ''

            if photo:
                s3_url = upload_file_to_s3(photo, application.config['AWS_S3_BUCKET'])
                if not s3_url:
                    flash('Failed to upload image to S3.')
                    return redirect(url_for('manager_dashboard'))

                # Convert price to Decimal before inserting into DynamoDB
                table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])
                turf_id = str(uuid.uuid4())
                table.put_item(Item={
                    'id': turf_id,
                    'name': name,
                    'location': location,
                    'price': Decimal(price),  # Convert price to Decimal
                    'time_slots': time_slots,
                    'photo': s3_url,
                    'manager_id': session['user_id']
                })
                flash('Turf added successfully!')

        # Fetch turfs managed by the current manager
        table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])
        response = table.scan(
            FilterExpression="manager_id = :m_id",
            ExpressionAttributeValues={":m_id": session['user_id']}
        )
        turfs = response.get('Items', [])
        for turf in turfs:
            turf['time_slots_list'] = turf.get('time_slots', '').split(',') if turf.get('time_slots') else []

        return render_template('manager_dashboard.html', turfs=turfs)
    return redirect(url_for('login'))
    
@application.route('/view_turfs', methods=['GET'])
def view_turfs():
    if 'user_id' in session and session.get('role') == 'manager':
        turfs_table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])
        bookings_table = get_table(application.config['DYNAMO_DB_BOOKINGS_TABLE'])

        # Fetch turfs managed by the current manager
        response = turfs_table.scan(
            FilterExpression="manager_id = :m_id",
            ExpressionAttributeValues={":m_id": session['user_id']}
        )
        turfs = response.get('Items', [])

        for turf in turfs:
            turf['time_slots_list'] = turf.get('time_slots', '').split(',') if turf.get('time_slots') else []

            # Fetch bookings for the current turf
            bookings_response = bookings_table.scan(
                FilterExpression="turf_id = :t AND #st <> :d",
                ExpressionAttributeNames={"#st": "status"},  # Alias for reserved keyword
                ExpressionAttributeValues={
                    ":t": turf['id'],
                    ":d": "Deleted"
                }
            )
            bookings = bookings_response.get('Items', [])

            # Attach user details to bookings
            for booking in bookings:
                user = get_item(application.config['DYNAMO_DB_USERS_TABLE'], {'id': booking['user_id']})
                booking['user'] = user

            # Mark booked slots
            turf['booked_slots'] = [
                booking['time_slot'] for booking in bookings if booking['status'] == 'Accepted'
            ]
            turf['bookings'] = bookings

        return render_template('view_turfs.html', turfs=turfs)
    return redirect(url_for('login'))

@application.route('/manager/edit_turf/<turf_id>', methods=['GET', 'POST'])
def edit_turf(turf_id):
    if 'user_id' in session and session.get('role') == 'manager':
        turfs_table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])
        turf = get_item(application.config['DYNAMO_DB_TURFS_TABLE'], {'id': turf_id})

        if not turf or turf['manager_id'] != session['user_id']:
            flash('Unauthorized access or Turf not found.')
            return redirect(url_for('view_turfs'))

        if request.method == 'POST':
            name = request.form['name']
            location = request.form['location']
            price = request.form['price']
            time_slots = ','.join(request.form.getlist('custom_slots[]'))

            # Handle photo upload
            photo = request.files['photo']
            if photo:
                s3_url = upload_file_to_s3(photo, application.config['AWS_S3_BUCKET'])
                if s3_url:
                    turf['photo'] = s3_url

            # Update turf fields
            turf.update({
                'name': name,
                'location': location,
                'price': float(price),
                'time_slots': time_slots
            })
            put_item(application.config['DYNAMO_DB_TURFS_TABLE'], turf)
            flash('Turf updated successfully!')
            return redirect(url_for('view_turfs'))

        time_slots_list = turf['time_slots'].split(',') if 'time_slots' in turf else []
        return render_template('edit_turf.html', turf=turf, time_slots_list=time_slots_list)
    return redirect(url_for('login'))


@application.route('/manager/delete_turf', methods=['POST'])
def delete_turf():
    if 'user_id' in session and session['role'] == 'manager':
        turf_id = request.form['turf_id']
        turfs_table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])
        bookings_table = get_table(application.config['DYNAMO_DB_BOOKINGS_TABLE'])

        turf = get_item(application.config['DYNAMO_DB_TURFS_TABLE'], {'id': turf_id})
        if turf and turf['manager_id'] == session['user_id']:
            try:
                # Delete related bookings
                bookings_response = bookings_table.scan(FilterExpression="turf_id = :t",
                                                        ExpressionAttributeValues={":t": turf_id})
                for booking in bookings_response['Items']:
                    bookings_table.delete_item(Key={'id': booking['id']})

                # Delete turf
                turfs_table.delete_item(Key={'id': turf_id})
                flash('Turf and its bookings deleted successfully.')
            except Exception as e:
                flash(f'Error deleting turf: {str(e)}')
        else:
            flash('Unauthorized action or Turf not found.')
    return redirect(url_for('manager_dashboard'))


@application.route('/manager/accept_booking', methods=['POST'])
def accept_booking():
    if 'user_id' in session and session.get('role') == 'manager':
        booking_id = request.form['booking_id']
        bookings_table = get_table(application.config['DYNAMO_DB_BOOKINGS_TABLE'])
        turfs_table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])

        booking = get_item(application.config['DYNAMO_DB_BOOKINGS_TABLE'], {'id': booking_id})
        if booking:
            turf = get_item(application.config['DYNAMO_DB_TURFS_TABLE'], {'id': booking['turf_id']})
            if turf and turf['manager_id'] == session['user_id']:
                booking['status'] = 'Accepted'
                put_item(application.config['DYNAMO_DB_BOOKINGS_TABLE'], booking)
                flash('Booking accepted successfully!')
            else:
                flash('Unauthorized action.')
        else:
            flash('Booking not found.')
        return redirect(url_for('view_turfs'))
    return redirect(url_for('login'))


@application.route('/user', methods=['GET', 'POST'])
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        turfs_table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])
        bookings_table = get_table(application.config['DYNAMO_DB_BOOKINGS_TABLE'])

        # Fetch all turfs
        response = turfs_table.scan()
        turfs = response['Items']

        for turf in turfs:
            # Parse time slots into a list
            turf['time_slots_list'] = turf['time_slots'].split(',') if 'time_slots' in turf else []

            # Fetch accepted bookings for this turf
            bookings_response = bookings_table.scan(
                FilterExpression="turf_id = :t AND #st = :s",
                ExpressionAttributeNames={"#st": "status"},  # Alias for reserved keyword
                ExpressionAttributeValues={":t": turf['id'], ":s": "Accepted"}
            )
            accepted_bookings = bookings_response['Items']
            turf['booked_slots'] = [b['time_slot'] for b in accepted_bookings]

        if request.method == 'POST':
            turf_id = request.form['turf_id']
            time_slot = request.form['time_slot']

            # Check if the time slot is already booked
            booked_slots = [
                b['time_slot'] for b in bookings_table.scan(
                    FilterExpression="turf_id = :t AND #st = :s",
                    ExpressionAttributeNames={"#st": "status"},  # Alias for reserved keyword
                    ExpressionAttributeValues={":t": turf_id, ":s": "Accepted"}
                )['Items']
            ]
            if time_slot in booked_slots:
                flash('Slot already booked. Choose another slot.')
            else:
                # Create a new booking
                booking_id = str(uuid.uuid4())
                put_item(application.config['DYNAMO_DB_BOOKINGS_TABLE'], {
                    'id': booking_id,
                    'turf_id': turf_id,
                    'user_id': session['user_id'],
                    'time_slot': time_slot,
                    'status': 'Pending'
                })
                flash('Booking submitted!')

        return render_template('user_dashboard.html', turfs=turfs)
    return redirect(url_for('login'))


@application.route('/user/book_turf', methods=['POST'])
def book_turf():
    if 'user_id' in session:
        turf_id = request.form['turf_id']
        time_slot = request.form['time_slot']
        booking_id = str(uuid.uuid4())  # Generate a unique ID for the booking

        # Add booking to the DynamoDB table
        put_item(application.config['DYNAMO_DB_BOOKINGS_TABLE'], {
            'id': booking_id,
            'turf_id': turf_id,
            'user_id': session['user_id'],
            'time_slot': time_slot,
            'status': 'Pending'
        })

        flash('Booking request submitted!')
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))


@application.route('/history', methods=['GET'])
def booking_history():
    if 'user_id' in session:
        bookings_table = get_table(application.config['DYNAMO_DB_BOOKINGS_TABLE'])
        turfs_table = get_table(application.config['DYNAMO_DB_TURFS_TABLE'])

        # Fetch bookings for the logged-in user
        response = bookings_table.scan(FilterExpression="user_id = :u", ExpressionAttributeValues={":u": session['user_id']})
        bookings = response['Items']

        for booking in bookings:
            # Fetch turf details for each booking
            turf = get_item(application.config['DYNAMO_DB_TURFS_TABLE'], {'id': booking['turf_id']})
            if turf:
                booking['turf_name'] = turf['name']
                booking['price'] = turf['price']

        return render_template('booking_history.html', bookings=bookings)
    return redirect(url_for('login'))


@application.route('/delete_booking', methods=['POST'])
def delete_booking():
    if 'user_id' in session and session['role'] == 'user':
        booking_id = request.form['booking_id']
        bookings_table = get_table(application.config['DYNAMO_DB_BOOKINGS_TABLE'])

        # Fetch the booking to verify ownership
        booking = get_item(application.config['DYNAMO_DB_BOOKINGS_TABLE'], {'id': booking_id})
        if booking and booking['user_id'] == session['user_id']:
            try:
                bookings_table.delete_item(Key={'id': booking_id})
                flash('Booking deleted successfully.')
            except Exception as e:
                flash(f'Error deleting booking: {str(e)}')
        else:
            flash('Unauthorized action or booking not found.')

    return redirect(url_for('booking_history'))

if __name__ == '__main__':
    # Initialize DynamoDB tables at application startup
    initialize_dynamo_tables()
    
    # Run the Flask application
    application.run(debug=True, host='0.0.0.0', port=8080)