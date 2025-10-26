from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from flask_bcrypt import Bcrypt
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursorimport logging
import os
import uuid
import json
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_123')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['UPLOAD_FOLDER'] = 'Uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB limit

bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True, ping_timeout=60, ping_interval=25)

connected_users = {}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'pdf', 'doc', 'docx', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class ConnectionPool:
    def __init__(self, size=5):
        self.pool = []
        self.size = size
        # Get DATABASE_URL from environment
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            # Production: Use Render's PostgreSQL
            for _ in range(size):
                conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
                conn.autocommit = True
                self.pool.append(conn)
        else:
            # Local: Use MySQL (your XAMPP)
            import pymysql
            for _ in range(size):
                conn = pymysql.connect(
                    host='localhost',
                    user='root',
                    password='',
                    database='realtimechatdb',
                    cursorclass=pymysql.cursors.DictCursor,
                    autocommit=True
                )
                self.pool.append(conn)

    def get_connection(self):
        for conn in self.pool:
            if not conn.closed:
                return conn
        
        # Create new connection if pool is empty
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
            conn.autocommit = True
            return conn
        else:
            import pymysql
            return pymysql.connect(
                host='localhost',
                user='root',
                password='',
                database='realtimechatdb',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )

    def release_connection(self, conn):
        if len(self.pool) < self.size:
            self.pool.append(conn)

pool = ConnectionPool()

def get_db_connection():
    return pool.get_connection()

@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {error}")
    return jsonify({"success": False, "message": "Internal server error"}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 204  # No Content response to ignore favicon requests

@app.route('/')
def index():
    return send_from_directory('.', 'Sample8.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    username = data.get('username')
    password = data.get('password')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "message": "Invalid credentials"}), 401
            # Try bcrypt first
            try:
                if bcrypt.check_password_hash(user['password'], password):
                    logger.info(f"User logged in: {username}")
                    return jsonify({"success": True, "username": user['username']})
            except ValueError:
                # Fallback to plain text (legacy users from Sample7.py)
                if user['password'] == password:
                    # Rehash and update password
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
                    logger.info(f"User logged in and password rehashed: {username}")
                    return jsonify({"success": True, "username": user['username']})
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"success": False, "message": "Server error"}), 500
    finally:
        pool.release_connection(conn)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    username = data.get('username')
    password = data.get('password')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Username already exists"}), 400
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            logger.info(f"New user registered: {username}")
            return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"success": False, "message": "Registration failed"}), 500
    finally:
        pool.release_connection(conn)

@app.route('/get_messages')
def get_messages():
    username = request.args.get('username', '')
    if not username:
        logger.error("No username provided in get_messages request")
        return jsonify([]), 400
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id AS message_id, username, message, timestamp, media_url, media_filename, recipient, pinned, read_by
                FROM messages 
                WHERE recipient IS NULL OR recipient = %s OR username = %s
                ORDER BY pinned DESC, timestamp ASC
            """, (username, username))
            messages = cursor.fetchall()
            logger.info(f"Fetched {len(messages)} messages for user: {username}")
            return jsonify(messages)
    except Exception as e:
        logger.error(f"Failed to fetch messages for {username}: {e}")
        return jsonify([])
    finally:
        pool.release_connection(conn)

@app.route('/upload_media', methods=['POST'])
def upload_media():
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file provided"}), 400
    file = request.files['file']
    username = request.form.get('username')
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"success": False, "message": "Invalid file type"}), 400
    try:
        filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return jsonify({
            "success": True,
            "media_url": f"/Uploads/{filename}",
            "media_filename": file.filename
        })
    except Exception as e:
        logger.error(f"Media upload error: {e}")
        return jsonify({"success": False, "message": "Failed to upload media"}), 500

@app.route('/Uploads/<filename>')
def serve_media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in connected_users:
        username = connected_users.pop(request.sid)
        logger.info(f"User disconnected: {username}")
        emit('user_left', {
            'username': username,
            'users': list(connected_users.values())
        }, broadcast=True)

@socketio.on('register_user')
def handle_register_user(data):
    try:
        if not isinstance(data, dict) or 'username' not in data:
            raise ValueError("Username required")
        username = data.get('username')
        connected_users[request.sid] = username
        logger.info(f"User registered: {username} (socket: {request.sid})")
        emit('user_joined', {
            'username': username,
            'users': list(connected_users.values())
        }, broadcast=True)
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id AS message_id, username, message, timestamp, media_url, media_filename, recipient, pinned, read_by
                    FROM messages 
                    WHERE recipient IS NULL OR recipient = %s OR username = %s
                    ORDER BY pinned DESC, timestamp DESC 
                    LIMIT 100
                """, (username, username))
                messages = cursor.fetchall()
                emit('initial_data', {
                    'users': list(connected_users.values()),
                    'messages': messages[::-1]
                }, room=request.sid)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Registration error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        if not isinstance(data, dict) or 'message' not in data:
            raise ValueError("Invalid message format")
        if request.sid not in connected_users:
            raise ValueError("User not registered")
        username = connected_users[request.sid]
        message = data.get('message')
        recipient = data.get('recipient', '')
        if not message or not isinstance(message, str):
            raise ValueError("Invalid message")
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO messages (username, message, recipient, read_by) VALUES (%s, %s, %s, %s)",
                    (username, message.strip(), recipient or None, json.dumps([]))
                )
                cursor.execute("SELECT id AS message_id FROM messages ORDER BY id DESC LIMIT 1")
                message_id = cursor.fetchone()['message_id']
            message_data = {
                'message_id': message_id,
                'username': username,
                'message': message.strip(),
                'recipient': recipient,
                'read_by': json.dumps([]),
                'timestamp': datetime.now().isoformat()
            }
            if recipient:
                for sid, user in connected_users.items():
                    if user in [username, recipient]:
                        emit('new_message', message_data, room=sid)
            else:
                emit('new_message', message_data, broadcast=True)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Message handling error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('send_media')
def handle_send_media(data):
    try:
        if not isinstance(data, dict) or 'media_url' not in data:
            raise ValueError("Invalid media message format")
        if request.sid not in connected_users:
            raise ValueError("User not registered")
        username = connected_users[request.sid]
        message = data.get('message', '')
        media_url = data.get('media_url')
        media_filename = data.get('media_filename')
        recipient = data.get('recipient', '')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO messages (username, message, media_url, media_filename, recipient, read_by) VALUES (%s, %s, %s, %s, %s, %s)",
                    (username, message.strip(), media_url, media_filename, recipient or None, json.dumps([]))
                )
                cursor.execute("SELECT id AS message_id FROM messages ORDER BY id DESC LIMIT 1")
                message_id = cursor.fetchone()['message_id']
            message_data = {
                'message_id': message_id,
                'username': username,
                'message': message.strip(),
                'media_url': media_url,
                'media_filename': media_filename,
                'recipient': recipient,
                'read_by': json.dumps([]),
                'timestamp': datetime.now().isoformat()
            }
            if recipient:
                for sid, user in connected_users.items():
                    if user in [username, recipient]:
                        emit('media_message', message_data, room=sid)
            else:
                emit('media_message', message_data, broadcast=True)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Media message handling error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('delete_message')
def handle_delete_message(data):
    try:
        if not isinstance(data, dict) or 'message_id' not in data:
            raise ValueError("Message ID required")
        if request.sid not in connected_users:
            raise ValueError("User not registered")
        username = connected_users[request.sid]
        message_id = data.get('message_id')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT username FROM messages WHERE id = %s", (message_id,))
                message = cursor.fetchone()
                if not message or message['username'] != username:
                    raise ValueError("Unauthorized or message not found")
                cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
            emit('message_deleted', {'message_id': message_id}, broadcast=True)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Delete message error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('edit_message')
def handle_edit_message(data):
    try:
        if not isinstance(data, dict) or 'message_id' not in data or 'message' not in data:
            raise ValueError("Message ID and new message required")
        if request.sid not in connected_users:
            raise ValueError("User not registered")
        username = connected_users[request.sid]
        message_id = data.get('message_id')
        new_message = data.get('message')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT username FROM messages WHERE id = %s", (message_id,))
                message = cursor.fetchone()
                if not message or message['username'] != username:
                    raise ValueError("Unauthorized or message not found")
                cursor.execute("UPDATE messages SET message = %s WHERE id = %s", (new_message.strip(), message_id))
            emit('message_edited', {
                'message_id': message_id,
                'message': new_message.strip()
            }, broadcast=True)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Edit message error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('pin_message')
def handle_pin_message(data):
    try:
        if not isinstance(data, dict) or 'message_id' not in data or 'pinned' not in data:
            raise ValueError("Message ID and pinned status required")
        if request.sid not in connected_users:
            raise ValueError("User not registered")
        username = connected_users[request.sid]
        message_id = data.get('message_id')
        pinned = data.get('pinned', False)
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT username FROM messages WHERE id = %s", (message_id,))
                message = cursor.fetchone()
                if not message or message['username'] != username:
                    raise ValueError("Unauthorized or message not found")
                cursor.execute("UPDATE messages SET pinned = %s WHERE id = %s", (pinned, message_id))
            emit('message_pinned', {
                'message_id': message_id,
                'pinned': pinned
            }, broadcast=True)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Pin message error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

@socketio.on('message_read')
def handle_message_read(data):
    try:
        if not isinstance(data, dict) or 'message_id' not in data:
            raise ValueError("Message ID required")
        if request.sid not in connected_users:
            raise ValueError("User not registered")
        username = connected_users[request.sid]
        message_id = data.get('message_id')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT read_by FROM messages WHERE id = %s", (message_id,))
                message = cursor.fetchone()
                if not message:
                    raise ValueError("Message not found")
                read_by = json.loads(message['read_by'] or '[]')
                if username not in read_by:
                    read_by.append(username)
                    cursor.execute("UPDATE messages SET read_by = %s WHERE id = %s", (json.dumps(read_by), message_id))
                emit('message_read', {
                    'message_id': message_id,
                    'read_count': len(read_by)
                }, broadcast=True)
        finally:
            pool.release_connection(conn)
    except Exception as e:
        logger.error(f"Read receipt error: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    socketio.run(app, host="0.0.0.0", port=port, debug=debug_mode)
