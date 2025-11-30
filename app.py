import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'parkspot_secret_key_bucuresti_2024' # Schimbă în producție


db_url = os.environ.get('DATABASE_URL', 'postgresql://postgres:0799044133@localhost/parkspot')

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False) # Pentru validare email
    cars = db.relationship('Car', backref='owner', lazy=True)
    reservations = db.relationship('Reservation', backref='user', lazy=True)

class Car(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plate_number = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) # Ex: "Piața Victoriei B3"
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    is_occupied = db.Column(db.Boolean, default=False)
    reservations = db.relationship('Reservation', backref='spot', lazy=True)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    car_id = db.Column(db.Integer, db.ForeignKey('car.id'), nullable=False)
    active = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email-ul există deja.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, is_active=False) 
        db.session.add(user)
        db.session.commit()
        
        validation_link = url_for('validate_email', user_id=user.id, _external=True)
        print(f"\n[DEMO] Email trimis către {email}. Link validare: {validation_link}\n")
        flash(f'Cont creat! Verifica consola pentru link-ul de activare (Simulare Email).', 'success')
        
        return redirect(url_for('login'))
        
    return render_template('auth.html', mode='register')

@app.route('/validate_email/<int:user_id>')
def validate_email(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    flash('Cont validat cu succes! Te poți autentifica.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_active:
                flash('Te rugăm să validezi adresa de email înainte de autentificare.', 'warning')
                return redirect(url_for('login'))
                
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login eșuat. Verifică email și parola.', 'danger')
            
    return render_template('auth.html', mode='login')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('map.html')

@app.route('/api/spots')
def get_spots():
    spots = ParkingSpot.query.all()
    spots_data = []
    now = datetime.utcnow()
    
    for spot in spots:
        active_res = Reservation.query.filter(
            Reservation.spot_id == spot.id,
            Reservation.active == True,
            Reservation.end_time > now
        ).first()
        
        status = 'occupied' if active_res else 'free'
        
        spots_data.append({
            'id': spot.id,
            'name': spot.name,
            'lat': spot.lat,
            'lng': spot.lng,
            'status': status
        })
    return jsonify(spots_data)

@app.route('/reserve', methods=['POST'])
@login_required
def reserve():
    data = request.json
    spot_id = data.get('spot_id')
    car_id = data.get('car_id')
    duration_hours = int(data.get('duration'))
    is_new_location = data.get('is_new_location', False) 
    lat = data.get('lat')
    lng = data.get('lng')

    if is_new_location and lat and lng:
        new_spot = ParkingSpot(name=f"Spot User {current_user.id}", lat=lat, lng=lng)
        db.session.add(new_spot)
        db.session.commit()
        spot_id = new_spot.id

    spot = ParkingSpot.query.get_or_404(spot_id)
    
    now = datetime.utcnow()
    conflict = Reservation.query.filter(
        Reservation.spot_id == spot.id,
        Reservation.active == True,
        Reservation.end_time > now
    ).first()
    
    if conflict:
        return jsonify({'success': False, 'message': 'Locul este deja rezervat.'})

    end_time = now + timedelta(hours=duration_hours)
    
    reservation = Reservation(
        user_id=current_user.id,
        spot_id=spot.id,
        car_id=car_id,
        end_time=end_time
    )
    
    db.session.add(reservation)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Loc rezervat pentru {duration_hours}h!'})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        plate = request.form.get('plate_number')
        if plate:
            plate = plate.upper().strip()
            existing = Car.query.filter_by(plate_number=plate, user_id=current_user.id).first()
            if not existing:
                new_car = Car(plate_number=plate, owner=current_user)
                db.session.add(new_car)
                db.session.commit()
                flash('Mașină adăugată cu succes!', 'success')
            else:
                flash('Această mașină există deja în contul tău.', 'warning')
        return redirect(url_for('profile'))
        
    my_reservations = Reservation.query.filter_by(user_id=current_user.id).order_by(Reservation.start_time.desc()).all()
    return render_template('profile.html', reservations=my_reservations, now=datetime.utcnow())

@app.route('/delete_car/<int:car_id>')
@login_required
def delete_car(car_id):
    car = Car.query.get_or_404(car_id)
    if car.owner != current_user:
        flash('Nu ai permisiunea.', 'danger')
        return redirect(url_for('profile'))
    
    db.session.delete(car)
    db.session.commit()
    flash('Mașina a fost ștearsă.', 'info')
    return redirect(url_for('profile'))


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Acces interzis.', 'danger')
        return redirect(url_for('index'))
        
    users = User.query.all()
    spots = ParkingSpot.query.all()
    reservations = Reservation.query.all()
    return render_template('admin.html', users=users, spots=spots, reservations=reservations)

@app.route('/admin/add_spot', methods=['POST'])
@login_required
def admin_add_spot():
    if not current_user.is_admin:
        return jsonify({'success': False})
    
    data = request.json
    new_spot = ParkingSpot(
        name=data.get('name'),
        lat=data.get('lat'),
        lng=data.get('lng')
    )
    db.session.add(new_spot)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Utilizator șters.', 'success')
    return redirect(url_for('admin'))

def create_initial_data():
    
    if not User.query.first():
        admin = User(email='admin@parkspot.ro', password=bcrypt.generate_password_hash('admin123').decode('utf-8'), is_admin=True, is_active=True)
        db.session.add(admin)
        
        spots = [
            ParkingSpot(name="Universitate - TNB", lat=44.4355, lng=26.1025),
            ParkingSpot(name="Piața Victoriei", lat=44.4522, lng=26.0864),
            ParkingSpot(name="Unirii - Hanul lui Manuc", lat=44.4297, lng=26.1018),
            ParkingSpot(name="Politehnica - Rectorat", lat=44.4385, lng=26.0494)
        ]
        db.session.add_all(spots)
        db.session.commit()
        print("Baza de date inițializată cu date demo.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_data()
    app.run(debug=True)