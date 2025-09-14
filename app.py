# ############################################################################
# # FOCUX APP - VERSIÓN FINAL PARA RENDER Y POSTGRESQL                       #
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

# Variables de Entorno y Globales
DATABASE_URL = os.getenv("DATABASE_URL")
db_lock = threading.Lock()

# ############################################################################
# # SECCIÓN 2: MANEJO DE LA BASE DE DATOS (CONEXIÓN Y ESQUEMA)               #
# ############################################################################

def get_db_connection():
    """Conecta a la base de datos PostgreSQL en la nube."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = psycopg2.extras.DictCursor
        return conn
    except Exception as e:
        print(f"🚨 ERROR CRÍTICO: No se pudo conectar a PostgreSQL: {e}")
        raise

def init_db():
    """
    Inicializa el esquema de la base de datos PostgreSQL.
    Crea todas las tablas necesarias si no existen.
    Esta función es para la base de datos única en la nube.
    """
    # NOTA: En PostgreSQL, 'SERIAL PRIMARY KEY' reemplaza a 'INTEGER PRIMARY KEY AUTOINCREMENT'.
    #       'JSONB' es un tipo de dato binario optimizado para almacenar y consultar JSON.
    commands = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name TEXT,
            last_name TEXT,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            registration_date TEXT,
            last_login TEXT,
            manager_id TEXT,
            access_expires_on TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS boards (
            id SERIAL PRIMARY KEY,
            owner_email TEXT,
            name TEXT,
            board_data JSONB,
            created_date TEXT,
            updated_date TEXT,
            category TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS collaborators (
            board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            permission_level TEXT NOT NULL DEFAULT 'editor',
            PRIMARY KEY (board_id, user_email)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS notes (
            id SERIAL PRIMARY KEY,
            board_id INTEGER REFERENCES boards(id) ON DELETE CASCADE,
            user_email TEXT,
            content TEXT,
            color TEXT,
            created_date TEXT,
            updated_date TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS assistants (
            id TEXT PRIMARY KEY,
            name TEXT,
            avatar_url TEXT,
            description TEXT,
            prompt TEXT,
            knowledge_base TEXT,
            is_public INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS board_chats (
            id SERIAL PRIMARY KEY,
            board_id INTEGER REFERENCES boards(id) ON DELETE CASCADE,
            user_email TEXT,
            user_name TEXT,
            message TEXT,
            timestamp TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS assistant_sharing (
            assistant_id TEXT NOT NULL REFERENCES assistants(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            PRIMARY KEY (assistant_id, user_email)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            title TEXT,
            message TEXT,
            timestamp TEXT,
            type TEXT,
            target_info TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS notification_views (
            notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            PRIMARY KEY (notification_id, user_email)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            participants_json TEXT,
            last_ts TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS direct_messages (
            id SERIAL PRIMARY KEY,
            conv_id TEXT REFERENCES conversations(id) ON DELETE CASCADE,
            ts TEXT,
            sender_email TEXT,
            receiver_email TEXT,
            text TEXT,
            is_read INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS stickers (
            id TEXT PRIMARY KEY,
            name TEXT,
            category TEXT,
            url TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS focux_messages (
            id TEXT PRIMARY KEY,
            title TEXT,
            content TEXT,
            color TEXT,
            image_url TEXT,
            button_text TEXT,
            button_url TEXT,
            is_active INTEGER DEFAULT 0,
            start_date TEXT,
            end_date TEXT,
            target_info TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scheduled_reminders (
            id SERIAL PRIMARY KEY,
            user_email TEXT NOT NULL,
            telegram_chat_id TEXT NOT NULL,
            notification_time TEXT NOT NULL,
            sent INTEGER DEFAULT 0,
            card_title TEXT NOT NULL,
            board_name TEXT,
            card_column TEXT,
            card_description TEXT,
            card_tags TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS telegram_connections (
            id SERIAL PRIMARY KEY,
            user_email TEXT NOT NULL UNIQUE,
            chat_id TEXT NOT NULL,
            connected_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ai_generated_boards (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            board_json JSONB NOT NULL,
            notes_json JSONB NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS documents (
            id SERIAL PRIMARY KEY,
            board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            title TEXT NOT NULL,
            version TEXT,
            google_drive_file_id TEXT,
            cloudinary_public_id TEXT,
            thumbnail_url TEXT,
            password TEXT,
            page_count INTEGER,
            created_date TEXT NOT NULL,
            updated_date TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS "references" (
            id SERIAL PRIMARY KEY,
            board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            created_date TEXT NOT NULL,
            updated_date TEXT NOT NULL
        )
        """
    ]
    
    conn = None
    try:
        with db_lock:
            # Usa la nueva función de conexión a PostgreSQL
            conn = get_db_connection()
            cur = conn.cursor()
            # Ejecuta cada comando de creación de tabla
            for command in commands:
                cur.execute(command)
            
            cur.close()
            # Guarda (commit) los cambios en la base de datos
            conn.commit()
            print("✅ Esquema de PostgreSQL verificado/creado exitosamente.")
            
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"🚨 Error al inicializar la base de datos PostgreSQL: {error}")
        # Si hay un error, revierte cualquier cambio
        if conn:
            conn.rollback()
            
    finally:
        # Asegúrate de cerrar la conexión
        if conn is not None:
            conn.close()

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
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT b.* FROM boards b JOIN collaborators c ON b.id = c.board_id WHERE c.user_email = %s
        """, (email,))
        user_boards = [dict(row) for row in cursor.fetchall()]

        for board in user_boards:
            board['data'] = json.loads(board['board_data']) if board['board_data'] else {}
            del board['board_data']

        return jsonify(success=True, boards=user_boards)
    except Exception as e:
        print(f"🚨 ERROR en GET /boards: {e}")
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
        board_to_send['data'] = json.loads(board_to_send['board_data']) if board_to_send['board_data'] else {}
        del board_to_send['board_data']

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