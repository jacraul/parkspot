# ParkSpot 🚗📍

ParkSpot is a comprehensive web application designed to simplify parking management in Bucharest. It helps users find, view, and reserve parking spots in real-time using an interactive map, while providing administrators with powerful tools to manage city parking infrastructure.

---

## 👥 Team & Contributions

### **Tudor-Neculai BALBA – Frontend & Map Interaction**
- **Interactive Map Integration:** Implemented OpenStreetMap with Leaflet.js to render the parking map centered on Bucharest.  
- **Geolocation Services:** Developed the **"Park Here (GPS)"** feature using the device’s geolocation API.  
- **UI/UX Design:** Created the responsive interface using Bootstrap 5, with a modern blue/green theme.  
- **Manual Pin Drop:** Implemented **Manual Reservation**, allowing users to drag-and-drop a pin for custom parking locations.

### **Raul-Anton JAC – Backend & Database Architecture**
- **Backend Logic:** Built the Flask backend handling routes, REST APIs, and business logic.  
- **Database Management:** Designed the PostgreSQL schema for Users, Cars, Spots, Reservations (SQLAlchemy ORM).  
- **Authentication System:** Secure login/registration with email validation and hashed passwords (Flask-Bcrypt).  
- **Admin Panel:** Control dashboard for user management, spot creation, and occupancy reports.

---

## 🌟 Key Features

### **For Users**
- **Account Management:** Secure signup/login, manage profile, register multiple cars.  
- **Real-Time Map:** Green = free, Red = occupied.  
- **Smart Reservation:**  
  - **Instant Booking:** Reserve a predefined spot for 1h, 3h, 12h, or 24h.  
  - **GPS Parking:** Book the spot based on live user geolocation.  
  - **Manual Selection:** Drag a pin to reserve unmapped locations.  
- **Live Updates:** Instant feedback for reservation status.

### **For Admins**
- **Dashboard:** Overview of active users, available spots, and current reservations.  
- **User Management:** View and delete users.  
- **Spot Management:** Add permanent parking spots interactively from the map (“Add Mode”).  

---

## 🛠️ Technologies Used

- **Language:** Python 3.x  
- **Framework:** Flask  
- **Database:** PostgreSQL (Production) / SQLite (Dev) via SQLAlchemy  
- **Frontend:** HTML5, CSS3, JavaScript  
- **Libraries:**  
  - Leaflet.js  
  - Bootstrap 5  
  - Flask-Login  
  - Flask-Bcrypt  

---

## 🚀 How to Run (Local / Development)

### 1. Clone the repository
```bash
git clone https://github.com/your-repo/parkspot.git
cd parkspot
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Database
Ensure PostgreSQL is running. On Windows:
```bash
$env:DATABASE_URL="postgresql://user:password@localhost/parkspot"
```

### 4. Run the application
```bash
python app.py
```

### 5. Access the app
Open: http://127.0.0.1:5000

### Security Notes
- Passwords are hashed with Bcrypt (Flask-Bcrypt).
- Use environment variables for sensitive configuration (database URL, secret keys).
- For production, run behind a production WSGI server (e.g., Gunicorn) and use HTTPS.
