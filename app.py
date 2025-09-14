# ############################################################################
# # FOCUX APP - VERSIÓN FINAL Y COMPLETA PARA RENDER Y POSTGRESQL            #
# ############################################################################

import os
import json
import threading
import traceback
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# ############################################################################
# # SECCIÓN 1: CONFIGURACIÓN DE LA APLICACIÓN Y VARIABLES GLOBALES           #
# ############################################################################

app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')
CORS(app, origins="*")

DATABASE_URL = os.getenv("DATABASE_URL")
db_lock = threading.Lock()

# ############################################################################
# # SECCIÓN 2: MANEJO DE LA BASE DE DATOS                                    #
# ############################################################################

def get_db_connection():
    """Conecta a la base de datos PostgreSQL en la nube."""
    conn = psycopg2.connect(DATABASE_URL)
    conn.cursor_factory = psycopg2.extras.DictCursor
    return conn

def init_db():
    """Inicializa el esquema completo de la base de datos PostgreSQL."""
    commands = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, first_name TEXT, last_name TEXT, email TEXT UNIQUE NOT NULL,
            password TEXT, registration_date TEXT, last_login TEXT, manager_id TEXT, access_expires_on TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS boards (
            id SERIAL PRIMARY KEY, owner_email TEXT, name TEXT, board_data JSONB,
            created_date TEXT, updated_date TEXT, category TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS collaborators (
            board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL, permission_level TEXT NOT NULL DEFAULT 'editor',
            PRIMARY KEY (board_id, user_email)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS stickers (
            id TEXT PRIMARY KEY, name TEXT, category TEXT, url TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY, participants_json TEXT, last_ts TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS direct_messages (
            id SERIAL PRIMARY KEY, conv_id TEXT REFERENCES conversations(id) ON DELETE CASCADE,
            ts TEXT, sender_email TEXT, receiver_email TEXT, text TEXT, is_read INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS focux_messages (
            id TEXT PRIMARY KEY, title TEXT, content TEXT, color TEXT, image_url TEXT,
            button_text TEXT, button_url TEXT, is_active INTEGER DEFAULT 0,
            start_date TEXT, end_date TEXT, target_info TEXT
        )
        """
    ]
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        for command in commands:
            cur.execute(command)
        conn.commit()
        cur.close()
        print("✅ Esquema de PostgreSQL verificado/creado exitosamente.")
    except Exception as error:
        print(f"🚨 Error al inicializar la base de datos: {error}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()

# ############################################################################
# # SECCIÓN 3: ENDPOINTS DE LA APLICACIÓN                                    #
# ############################################################################

@app.route('/', methods=['GET'])
def serve_index():
    return render_template('Index.html')

@app.route('/Tablero.html', methods=['GET'])
def serve_tablero():
    return render_template('Tablero.html')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify(success=True, message="Servidor Focux funcionando")

@app.route('/admin/available-databases', methods=['GET'])
def get_available_databases():
    return jsonify(success=True, databases=[{"filename": "Principal", "display_name": "Principal"}])

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email'].lower().strip()
    if data['password'] != data['confirmPassword']:
        return jsonify(success=False, message="Las contraseñas no coinciden."), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify(success=False, message="El correo ya está registrado."), 409

        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password, registration_date, manager_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (data['firstName'], data['lastName'], email, data['password'], now, data['manager_id'])
        )
        
        default_board_data = {"columns": [{"id": "col-1", "title": "Por hacer"}, {"id": "col-2", "title": "En proceso"}, {"id": "col-3", "title": "Hecho"}], "cards": []}
        cursor.execute(
            "INSERT INTO boards (owner_email, name, board_data, created_date, updated_date, category) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (email, "Mi Primer Tablero", json.dumps(default_board_data), now, now, "Personal")
        )
        board_id = cursor.fetchone()['id']
        
        cursor.execute("INSERT INTO collaborators (board_id, user_email, permission_level) VALUES (%s, %s, %s)", (board_id, email, 'editor'))
        
        conn.commit()
        return jsonify(success=True, message="Registro exitoso"), 201
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en /register: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password')
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()

        if user:
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (now, user['id']))
            conn.commit()
            return jsonify(success=True, message="Login exitoso", user=dict(user))
        else:
            return jsonify(success=False, message="Credenciales incorrectas."), 401
    except Exception as e:
        print(f"🚨 ERROR en /login: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()



@app.route('/boards', methods=['GET'])
def get_boards():
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT b.* FROM boards b JOIN collaborators c ON b.id = c.board_id WHERE c.user_email = %s
        """, (email,))
        user_boards = [dict(row) for row in cursor.fetchall()]

        # --- INICIO DE LA CORRECCIÓN CLAVE ---
        # PostgreSQL con psycopg2 ya devuelve el JSONB como un diccionario de Python.
        # No es necesario usar json.loads(). Este era el error.
        for board in user_boards:
            board['data'] = board.get('board_data') or {}
            if 'board_data' in board:
                del board['board_data']
        # --- FIN DE LA CORRECCIÓN CLAVE ---

        # Obtener stickers y otras cosas que tu app necesita al cargar
        cursor.execute("SELECT id, name, category, url FROM stickers")
        stickers = [dict(row) for row in cursor.fetchall()]

        return jsonify(success=True, boards=user_boards, stickers=stickers)

    except Exception as e:
        print(f"🚨 ERROR en GET /boards: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()


@app.route('/boards/<int:board_id>', methods=['GET'])
def get_single_board(board_id):
    email = request.args.get('email', '').lower().strip()
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        if not cursor.fetchone():
            return jsonify(success=False, message="Acceso denegado a este tablero."), 403

        cursor.execute("SELECT * FROM boards WHERE id = %s", (board_id,))
        board_info = cursor.fetchone()
        if not board_info:
            return jsonify(success=False, message="Tablero no encontrado."), 404
        
        board_to_send = dict(board_info)
        board_to_send['data'] = json.loads(board_to_send['board_data']) if board_to_send.get('board_data') else {}
        if 'board_data' in board_to_send: del board_to_send['board_data']

        cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id,))
        board_to_send['shared_with'] = [dict(r) for r in cursor.fetchall()]
        
        return jsonify(success=True, board=board_to_send)
    except Exception as e:
        print(f"🚨 ERROR en GET /boards/{board_id}: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()
        
@app.route('/boards/<int:board_id>', methods=['PUT'])
def update_board(board_id):
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    board_data = data.get('boardData')
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT permission_level FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        permission = cursor.fetchone()
        if not permission or permission['permission_level'] != 'editor':
            return jsonify(success=False, message="Permiso de editor requerido."), 403

        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "UPDATE boards SET board_data = %s, updated_date = %s WHERE id = %s",
            (json.dumps(board_data), now, board_id)
        )
        conn.commit()
        
        socketio.emit('board_was_updated', {'board_id': board_id, 'boardData': board_data}, room=str(board_id))
        return jsonify(success=True, message="Tablero actualizado")
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en PUT /boards/{board_id}: {e}")
        return jsonify(success=False, message="Error al guardar el tablero."), 500
    finally:
        if conn: conn.close()

# Rutas para stickers, chat, etc.
@app.route('/stickers', methods=['GET'])
def get_stickers_route():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, category, url FROM stickers")
        stickers = [dict(row) for row in cursor.fetchall()]
        return jsonify(success=True, stickers=stickers)
    except Exception as e:
        print(f"Error al cargar stickers: {e}")
        return jsonify(success=False, stickers=[])
    finally:
        if conn: conn.close()

@app.route('/direct-chats/partners', methods=['GET'])
def get_chat_partners():
    email = request.args.get('me', '').lower().strip()
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT
                CASE WHEN sender_email = %s THEN receiver_email ELSE sender_email END as partner_email
            FROM direct_messages
            WHERE sender_email = %s OR receiver_email = %s
        """, (email, email, email))
        partners = [row['partner_email'] for row in cursor.fetchall()]
        return jsonify(success=True, partners=partners)
    except Exception as e:
        print(f"🚨 ERROR en GET /direct-chats/partners: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500
    finally:
        if conn: conn.close()

@app.route('/focux_messages', methods=['GET'])
def get_active_focux_messages():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        now_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT * FROM focux_messages WHERE is_active = 1 
            AND (start_date IS NULL OR start_date <= %s)
            AND (end_date IS NULL OR end_date >= %s)
        """, (now_date, now_date))
        messages = [dict(row) for row in cursor.fetchall()]
        return jsonify(success=True, messages=messages)
    except Exception as e:
        print(f"🚨 ERROR en GET /focux_messages: {e}")
        return jsonify(success=False, messages=[])
    finally:
        if conn: conn.close()
        
# ############################################################################
# # SECCIÓN 4: INICIALIZACIÓN Y EJECUCIÓN DEL SERVIDOR                      #
# ############################################################################

try:
    print("🚀 Inicializando esquema de la base de datos PostgreSQL...")
    init_db()
    print("✅ Esquema de base de datos verificado.")
except Exception as e:
    print(f"🚨 ERROR CRÍTICO DURANTE LA INICIALIZACIÓN: {e}")

if __name__ == '__main__':
    print("🚀 Iniciando servidor de desarrollo local...")
    socketio.run(app, host='0.0.0.0', port=8080)