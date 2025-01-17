from flask import Flask, render_template, request, Response, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import pytz
from ipaddress import ip_address, ip_network
from flask import make_response, request
import time

app = Flask(__name__)

# Configure app and database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'
db = SQLAlchemy(app)


# Define database model
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)


# Initialize the database
with app.app_context():
    db.create_all()


# Function to get the client IP
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


# Function to check if the client IP is allowed
def is_allowed_ip():
    allowed_ips = ['192.168.0.0/24', '127.0.0.1', '175.140.188.177']
    client_ip = get_client_ip()
    print(f"Client IP: {client_ip}")  # Debugging: Log the detected client IP

    for ip_range in allowed_ips:
        if ip_address(client_ip) in ip_network(ip_range):
            return True
    return False


@app.route('/')
def index():
    return "Welcome to the HD Attendance System!"


@app.route('/reset_restriction', methods=['POST'])
def reset_restriction():
    if not session.get('admin'):
        flash('You must log in to access this feature.')
        return redirect(url_for('login'))

    # Get the record ID from the form
    record_id = request.form.get('record_id')
    record = Attendance.query.get(record_id)

    if record:
        # Log the reset action (optional)
        flash(f"Restriction for {record.name} has been reset.")

        # Set a session flag to bypass restriction for this session
        session['restriction_reset'] = True

        # Redirect back to the admin panel
        return redirect(url_for('admin'))
    else:
        flash("Record not found. Unable to reset restriction.")
        return redirect(url_for('admin'))


@app.route('/clear_restriction', methods=['POST'])
def clear_restriction():
    # Extract the browser_id from the form
    browser_id = request.form.get('browser_id')

    if browser_id:
        # Clear the restriction from the database
        restriction = Restriction.query.filter_by(
            browser_id=browser_id).first()
        if restriction:
            db.session.delete(restriction)
            db.session.commit()
            flash(
                f"Restrictions for Browser ID {browser_id} cleared successfully.",
                "success")
        else:
            flash("No restriction found for the given Browser ID.", "error")
    else:
        flash("Invalid Browser ID.", "error")

    return redirect('/admin')


@app.route('/delete_entry', methods=['POST'])
def delete_entry():
    # Ensure only admins can perform this action
    if not session.get('admin'):
        flash('You must log in to access this feature.')
        return redirect(url_for('login'))

    # Get the record ID from the form
    record_id = request.form.get('record_id')
    record = Attendance.query.get(record_id)

    if record:
        # Delete the entry from the database
        db.session.delete(record)
        db.session.commit()

        # Log the action and inform the admin
        flash(
            f"Entry for {record.name} has been deleted, and the restriction has been cleared."
        )

        # Create a response to redirect back to the admin panel
        response = redirect(url_for('admin'))

        # Clear the browser restriction by deleting the cookie
        response.delete_cookie('last_signin')  # Clear the restriction cookie
        return response
    else:
        # Handle cases where the record is not found
        flash("Record not found. Unable to delete entry.")
        return redirect(url_for('admin'))


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if not is_allowed_ip():
        return render_template('denied.html')

    if request.method == 'POST':
        name = request.form['name']
        action = request.form['action']
        malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
        timestamp = datetime.now(malaysia_tz)

        # Handle Sign In
        if action.lower() == 'sign in':
            # Check for restriction reset session flag
            restriction_reset = session.pop('restriction_reset', False)

            # Check if the browser has signed in within the last 8 hours
            if not restriction_reset and request.cookies.get('last_signin'):
                last_signin = float(request.cookies.get('last_signin'))
                elapsed_hours = (time.time() - last_signin) / 3600
                if elapsed_hours < 8:
                    return render_template('deny_signin.html')

            # Proceed with sign-in
            new_entry = Attendance(name=name,
                                   action=action,
                                   timestamp=timestamp)
            db.session.add(new_entry)
            db.session.commit()

            # Set a cookie to restrict further sign-ins for 8 hours
            response = make_response(
                render_template(
                    'thank_you.html',
                    name=name,
                    action=action,
                    timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S')))
            response.set_cookie('last_signin',
                                str(time.time()),
                                max_age=8 * 3600)
            return response

        # Handle Sign Out
        if action.lower() == 'sign out':
            # Allow unlimited sign-outs
            new_entry = Attendance(name=name,
                                   action=action,
                                   timestamp=timestamp)
            db.session.add(new_entry)
            db.session.commit()
            return render_template(
                'thank_you.html',
                name=name,
                action=action,
                timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S'))

        # Default case (invalid action)
        return render_template('deny_signin.html')

    # Render the scan form for GET requests
    return render_template('scan.html')


@app.route('/submit', methods=['POST'])
def submit():
    name = request.form['name']
    action = request.form['action']
    malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
    timestamp = datetime.now(malaysia_tz)

    # Handle Sign In
    if action.lower() == 'sign in':
        # Check if the browser has signed in within the last 8 hours
        if request.cookies.get('last_signin'):
            last_signin = float(request.cookies.get('last_signin'))
            elapsed_hours = (time.time() - last_signin) / 3600
            if elapsed_hours < 8:
                return render_template(
                    'deny_signin.html')  # Redirect to new denial page

        # Proceed with sign-in
        new_entry = Attendance(name=name, action=action, timestamp=timestamp)
        db.session.add(new_entry)
        db.session.commit()

        # Set a cookie to restrict further sign-ins from this browser for 8 hours
        response = make_response(
            render_template('thank_you.html',
                            name=name,
                            action=action,
                            timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S')))
        response.set_cookie('last_signin', str(time.time()), max_age=8 * 3600)
        return response

    # Handle Sign Out
    if action.lower() == 'sign out':
        # Sign out without restrictions
        new_entry = Attendance(name=name, action=action, timestamp=timestamp)
        db.session.add(new_entry)
        db.session.commit()
        return render_template(
            'thank_you.html',
            name=name,
            action=action,
            timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S'))

    # Default case (if action is not recognized)
    return render_template('deny_signin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'Hd55000':
            session['admin'] = True
            return redirect(url_for('admin'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('admin', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('admin'):
        flash('You must log in to access this page.')
        return redirect(url_for('login'))

    query = Attendance.query
    name_filter = request.args.get('name')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    if name_filter:
        query = query.filter(Attendance.name.ilike(f"%{name_filter}%"))
    if date_from:
        query = query.filter(
            Attendance.timestamp >= datetime.strptime(date_from, "%Y-%m-%d"))
    if date_to:
        query = query.filter(
            Attendance.timestamp <= datetime.strptime(date_to, "%Y-%m-%d"))

    records = query.order_by(Attendance.timestamp.desc()).all()
    return render_template('admin.html', records=records)


@app.route('/reset', methods=['POST'])
def reset():
    if not session.get('admin'):
        flash('You must log in to access this page.')
        return redirect(url_for('login'))

    try:
        db.session.query(Attendance).delete()
        db.session.commit()
        flash('All attendance records have been successfully deleted.')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while trying to delete records: {str(e)}')

    return redirect(url_for('admin'))


@app.route('/delete_selected', methods=['POST'])
def delete_selected():
    if not session.get('admin'):
        flash('You must log in to access this page.')
        return redirect(url_for('login'))

    record_ids = request.form.getlist(
        'record_ids')  # Get list of selected record IDs
    if record_ids:
        try:
            # Convert IDs to integers and delete records
            db.session.query(Attendance).filter(
                Attendance.id.in_(map(
                    int, record_ids))).delete(synchronize_session=False)
            db.session.commit()
            flash(f'Successfully deleted {len(record_ids)} records.')
        except Exception as e:
            db.session.rollback()
            flash(
                f'An error occurred while trying to delete records: {str(e)}')
    else:
        flash('No records selected for deletion.')

    return redirect(url_for('admin'))


@app.route('/export', methods=['GET'])
def export():
    if not session.get('admin'):
        flash('You must log in to access this page.')
        return redirect(url_for('login'))

    query = Attendance.query
    name_filter = request.args.get('name')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    if name_filter:
        query = query.filter(Attendance.name.ilike(f"%{name_filter}%"))
    if date_from:
        query = query.filter(
            Attendance.timestamp >= datetime.strptime(date_from, "%Y-%m-%d"))
    if date_to:
        query = query.filter(
            Attendance.timestamp <= datetime.strptime(date_to, "%Y-%m-%d"))

    records = query.order_by(Attendance.timestamp.desc()).all()

    def generate_csv():
        data = [["ID", "Name", "Action", "Timestamp"]]
        for record in records:
            data.append(
                [record.id, record.name, record.action, record.timestamp])
        for row in data:
            yield ",".join(map(str, row)) + "\n"

    return Response(
        generate_csv(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=attendance.csv"})


if __name__ == '__main__':
    app.run(debug=True)
