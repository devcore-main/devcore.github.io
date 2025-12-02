from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import jwt
import datetime
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-core-secret-key-2025-6-25')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-core-jwt-secret-2025-6-25')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# CORS configuration for production
allowed_origins = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "file://",
    os.environ.get('FRONTEND_URL', '')
]
# Remove empty strings
allowed_origins = [origin for origin in allowed_origins if origin]
CORS(app, origins=allowed_origins)

# Admin credentials
ADMIN_EMAIL = 'devcore.communicate@gmail.com'
ADMIN_PASSWORD = 'dev_core_25.6.2025'

# Database setup - use absolute path for production
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devcore.db')

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Courses table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Enrollments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            progress INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (course_id) REFERENCES courses(id),
            UNIQUE(user_id, course_id)
        )
    ''')
    
    # Course materials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS course_materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            material_type TEXT DEFAULT 'lesson',
            order_index INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id)
        )
    ''')
    
    # Check if admin user exists
    cursor.execute('SELECT * FROM users WHERE email = ?', (ADMIN_EMAIL,))
    admin = cursor.fetchone()
    
    if not admin:
        # Create admin user
        admin_password_hash = generate_password_hash(ADMIN_PASSWORD)
        cursor.execute('''
            INSERT INTO users (fullname, username, email, phone, password, role)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('Admin User', 'admin', ADMIN_EMAIL, '+201000000000', admin_password_hash, 'admin'))
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")

def generate_token(user_id, email, role):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            payload = verify_token(token)
            if not payload:
                return jsonify({'message': 'Invalid or expired token'}), 401
            request.current_user = payload
        except Exception as e:
            return jsonify({'message': 'Token verification failed'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Initialize database on startup
init_db()

# Routes
@app.route('/')
def index():
    return jsonify({'message': 'DEV-CORE API is running', 'version': '1.0.0'})

@app.route('/api/signup', methods=['POST'])
def signup():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['fullname', 'username', 'email', 'phone', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field} is required'}), 400
        
        # Check if user already exists
        conn = get_db()
        cursor = conn.cursor()
        
        # Check email
        cursor.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
        if cursor.fetchone():
            conn.close()
            return jsonify({'message': 'Email already registered'}), 400
        
        # Check username
        cursor.execute('SELECT * FROM users WHERE username = ?', (data['username'],))
        if cursor.fetchone():
            conn.close()
            return jsonify({'message': 'Username already taken'}), 400
        
        # Hash password
        hashed_password = generate_password_hash(data['password'])
        
        # Determine role
        role = 'admin' if data['email'] == ADMIN_EMAIL else 'user'
        
        # Insert user
        cursor.execute('''
            INSERT INTO users (fullname, username, email, phone, password, role)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['fullname'], data['username'], data['email'], data['phone'], hashed_password, role))
        
        user_id = cursor.lastrowid
        conn.commit()
        
        # Generate token
        token = generate_token(user_id, data['email'], role)
        
        # Get user data
        cursor.execute('SELECT id, fullname, username, email, phone, role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        user_dict = {
            'id': user[0],
            'fullname': user[1],
            'username': user[2],
            'email': user[3],
            'phone': user[4],
            'role': user[5]
        }
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': user_dict
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Check password
        # Special handling for admin
        if user[3] == ADMIN_EMAIL:
            if data['password'] != ADMIN_PASSWORD:
                conn.close()
                return jsonify({'message': 'Invalid email or password'}), 401
        else:
            if not check_password_hash(user[5], data['password']):
                conn.close()
                return jsonify({'message': 'Invalid email or password'}), 401
        
        # Generate token
        token = generate_token(user[0], user[3], user[6])
        
        user_dict = {
            'id': user[0],
            'fullname': user[1],
            'username': user[2],
            'email': user[3],
            'phone': user[4],
            'role': user[6]
        }
        
        conn.close()
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user_dict
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/verify', methods=['GET'])
@require_auth
def verify():
    """Verify token and get user info"""
    try:
        user_id = request.current_user['user_id']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, fullname, username, email, phone, role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        user_dict = {
            'id': user[0],
            'fullname': user[1],
            'username': user[2],
            'email': user[3],
            'phone': user[4],
            'role': user[5]
        }
        
        return jsonify({'user': user_dict}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    """Get all users (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, fullname, username, email, phone, role, created_at FROM users')
        users = cursor.fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user[0],
                'fullname': user[1],
                'username': user[2],
                'email': user[3],
                'phone': user[4],
                'role': user[5],
                'created_at': user[6]
            })
        
        return jsonify({'users': users_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/courses', methods=['GET'])
def get_courses():
    """Get all courses"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM courses')
        courses = cursor.fetchall()
        conn.close()
        
        courses_list = []
        for course in courses:
            courses_list.append({
                'id': course[0],
                'title': course[1],
                'description': course[2],
                'price': course[3],
                'category': course[4],
                'created_at': course[5]
            })
        
        return jsonify({'courses': courses_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/courses', methods=['POST'])
@require_auth
def create_course():
    """Create a new course (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        
        data = request.get_json()
        
        if not data.get('title') or not data.get('price'):
            return jsonify({'message': 'Title and price are required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO courses (title, description, price, category)
            VALUES (?, ?, ?, ?)
        ''', (data.get('title'), data.get('description', ''), data.get('price'), data.get('category', '')))
        
        course_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Course created successfully', 'course_id': course_id}), 201
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/enrollments', methods=['GET'])
@require_auth
def get_enrollments():
    """Get user enrollments"""
    try:
        user_id = request.current_user['user_id']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT e.*, c.title, c.description, c.price, c.category
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            WHERE e.user_id = ?
        ''', (user_id,))
        enrollments = cursor.fetchall()
        conn.close()
        
        enrollments_list = []
        for enrollment in enrollments:
            enrollments_list.append({
                'id': enrollment[0],
                'course_id': enrollment[2],
                'course_title': enrollment[6],
                'course_description': enrollment[7],
                'course_price': enrollment[8],
                'course_category': enrollment[9],
                'progress': enrollment[3],
                'status': enrollment[4],
                'enrolled_at': enrollment[5]
            })
        
        return jsonify({'enrollments': enrollments_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/enrollments', methods=['POST'])
@require_auth
def enroll_in_course():
    """Enroll user in a course"""
    try:
        user_id = request.current_user['user_id']
        data = request.get_json()
        
        if not data.get('course_id'):
            return jsonify({'message': 'Course ID is required'}), 400
        
        course_id = data['course_id']
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if course exists
        cursor.execute('SELECT * FROM courses WHERE id = ?', (course_id,))
        course = cursor.fetchone()
        
        if not course:
            conn.close()
            return jsonify({'message': 'Course not found'}), 404
        
        # Check if already enrolled
        cursor.execute('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?', (user_id, course_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return jsonify({'message': 'Already enrolled in this course'}), 400
        
        # Create enrollment
        cursor.execute('''
            INSERT INTO enrollments (user_id, course_id, progress, status)
            VALUES (?, ?, 0, 'active')
        ''', (user_id, course_id))
        
        conn.commit()
        enrollment_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            'message': 'Successfully enrolled in course',
            'enrollment_id': enrollment_id
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/courses/<int:course_id>', methods=['GET'])
def get_course_details(course_id):
    """Get course details with materials"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get course
        cursor.execute('SELECT * FROM courses WHERE id = ?', (course_id,))
        course = cursor.fetchone()
        
        if not course:
            conn.close()
            return jsonify({'message': 'Course not found'}), 404
        
        # Get course materials
        cursor.execute('''
            SELECT * FROM course_materials 
            WHERE course_id = ? 
            ORDER BY order_index ASC
        ''', (course_id,))
        materials = cursor.fetchall()
        
        conn.close()
        
        course_dict = {
            'id': course[0],
            'title': course[1],
            'description': course[2],
            'price': course[3],
            'category': course[4],
            'created_at': course[5],
            'materials': []
        }
        
        for material in materials:
            course_dict['materials'].append({
                'id': material[0],
                'title': material[2],
                'content': material[3],
                'material_type': material[4],
                'order_index': material[5],
                'created_at': material[6]
            })
        
        return jsonify({'course': course_dict}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/courses/<int:course_id>/materials', methods=['POST'])
@require_auth
def add_course_material(course_id):
    """Add material to a course (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        
        data = request.get_json()
        
        if not data.get('title'):
            return jsonify({'message': 'Title is required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if course exists
        cursor.execute('SELECT * FROM courses WHERE id = ?', (course_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'message': 'Course not found'}), 404
        
        # Get max order_index
        cursor.execute('SELECT MAX(order_index) FROM course_materials WHERE course_id = ?', (course_id,))
        max_order = cursor.fetchone()[0] or 0
        
        # Insert material
        cursor.execute('''
            INSERT INTO course_materials (course_id, title, content, material_type, order_index)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            course_id,
            data.get('title'),
            data.get('content', ''),
            data.get('material_type', 'lesson'),
            max_order + 1
        ))
        
        material_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Material added successfully',
            'material_id': material_id
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/courses/<int:course_id>/materials/<int:material_id>', methods=['DELETE'])
@require_auth
def delete_course_material(course_id, material_id):
    """Delete course material (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM course_materials WHERE id = ? AND course_id = ?', (material_id, course_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'message': 'Material not found'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Material deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/courses/<int:course_id>/materials', methods=['GET'])
def get_course_materials(course_id):
    """Get all materials for a course"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM course_materials 
            WHERE course_id = ? 
            ORDER BY order_index ASC
        ''', (course_id,))
        
        materials = cursor.fetchall()
        conn.close()
        
        materials_list = []
        for material in materials:
            materials_list.append({
                'id': material[0],
                'course_id': material[1],
                'title': material[2],
                'content': material[3],
                'material_type': material[4],
                'order_index': material[5],
                'created_at': material[6]
            })
        
        return jsonify({'materials': materials_list}), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    print("Starting DEV-CORE API server...")
    print(f"Admin Email: {ADMIN_EMAIL}")
    print(f"Server running on port {port}")
    app.run(debug=debug, host='0.0.0.0', port=port)

