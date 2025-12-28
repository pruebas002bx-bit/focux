# ############################################################################
# # FOCUX APP - VERSIÓN FINAL Y COMPLETA PARA RENDER Y POSTGRESQL            #
# ############################################################################

import os
import json
import threading
import traceback
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, emit
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
import re
import uuid


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
active_users = {}

# --- PEGA TU BLOQUE DE CÓDIGO AQUÍ ---
try:
    import google.generativeai as genai
    # Configurar la API de Gemini usando la variable de entorno
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        print("✅ API de Gemini configurada exitosamente.")
    else:
        print("⚠️ Advertencia: No se encontró la GEMINI_API_KEY. Las funciones de IA estarán desactivadas.")
        genai = None
except ImportError:
    print("⚠️ Advertencia: La librería 'google-generativeai' no está instalada. Las funciones de IA estarán desactivadas.")
    genai = None
# --- FIN DEL BLOQUE A PEGAR ---

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
            password TEXT, registration_date TEXT, last_login TEXT, manager_id TEXT, access_expires_on TEXT,
            telegram_chat_id TEXT NULL
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
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY, participants_json TEXT, last_ts TEXT
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
        CREATE TABLE IF NOT EXISTS assistant_sharing (
            assistant_id TEXT NOT NULL REFERENCES assistants(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            PRIMARY KEY (assistant_id, user_email)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS direct_messages (
            id SERIAL PRIMARY KEY, conv_id TEXT REFERENCES conversations(id) ON DELETE CASCADE,
            ts TEXT, sender_email TEXT, receiver_email TEXT, text TEXT, is_read INTEGER DEFAULT 0
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
        CREATE TABLE IF NOT EXISTS focux_messages (
            id TEXT PRIMARY KEY, title TEXT, content TEXT, color TEXT, image_url TEXT,
            button_text TEXT, button_url TEXT, is_active INTEGER DEFAULT 0,
            start_date TEXT, end_date TEXT, target_info TEXT
        )
        """,
        # --- INICIO: NUEVAS TABLAS PARA EL PANEL DE ADMIN ---
        """
        CREATE TABLE IF NOT EXISTS admin_notifications (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            target_info JSONB,
            timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            sent_by TEXT,
            viewed_count INTEGER DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ia_boards (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            board_data JSONB,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS manager_settings (
            manager_id TEXT PRIMARY KEY,
            logo_url TEXT,
            background_url TEXT
        )
        """
        # --- FIN: NUEVAS TABLAS PARA EL PANEL DE ADMIN ---
    ]
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        for command in commands:
            cur.execute(command)
        conn.commit()
        cur.close()
        print("✅ Esquema de PostgreSQL (con tablas de admin) verificado/creado exitosamente.")
    except Exception as error:
        print(f"🚨 Error al inicializar la base de datos: {error}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()


def migrate_database():
    """Añade columnas faltantes a tablas existentes para asegurar compatibilidad."""
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT NULL;",
        # Puedes añadir futuras sentencias ALTER TABLE aquí si es necesario
    ]
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        for command in migrations:
            try:
                cur.execute(command)
                print(f"✅ Migración ejecutada exitosamente: {command}")
            except psycopg2.Error as e:
                print(f"⚠️  Advertencia al ejecutar migración '{command}': {e}")
                conn.rollback() # Revierte la transacción fallida
        conn.commit()
        cur.close()
    except Exception as error:
        print(f"🚨 Error durante la migración de la base de datos: {error}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()


def check_editor_permission(conn, board_id, email):
    """Función auxiliar para verificar si un usuario es editor de un tablero."""
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s AND permission_level = 'editor'",
            (board_id, email)
        )
        return cursor.fetchone() is not None


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
        
        # --- LÍNEA MODIFICADA ---
        default_board_data = {
            "columns": [
                {"id": "col-1", "title": "Por hacer (To Do)", "color": "bg-red-200"},
                {"id": "col-2", "title": "En proceso (In Progress)", "color": "bg-yellow-200"},
                {"id": "col-3", "title": "En revisión (In Review)", "color": "bg-indigo-200"},
                {"id": "col-4", "title": "Hecho (Done)", "color": "bg-green-200"}
            ], "cards": [], "boardOptions": {}
        }
        # ------------------------

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


@app.route('/assistants', methods=['GET'])
def get_assistants():
    """Obtiene la lista de asistentes disponibles para un usuario."""
    email = request.args.get('email', '').lower().strip()
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Obtiene todos los asistentes públicos MÁS los privados compartidos con el usuario
        cursor.execute("""
            SELECT * FROM assistants a
            WHERE a.is_public = 1 OR EXISTS (
                SELECT 1 FROM assistant_sharing s
                WHERE s.assistant_id = a.id AND s.user_email = %s
            )
        """, (email,))
        
        assistants = [dict(row) for row in cursor.fetchall()]
        return jsonify(success=True, assistants=assistants)
        
    except Exception as e:
        print(f"🚨 ERROR en GET /assistants: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al cargar asistentes."), 500
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



# ============================================================================
# # SECCIÓN DE SOCKET.IO PARA TIEMPO REAL
# ============================================================================

@app.route('/boards/<int:board_id>/share', methods=['POST'])
def share_board(board_id):
    """Invita a un nuevo usuario a colaborar, aplicando el permiso correcto."""
    data = request.get_json()
    sharer_email = data.get('sharer_email')
    recipient_email = data.get('recipient_email', '').lower().strip()
    permission_level = data.get('permission_level', 'viewer')

    if not all([sharer_email, recipient_email]):
        return jsonify(success=False, message="Faltan datos para compartir."), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT owner_email FROM boards WHERE id = %s", (board_id,))
        board = cursor.fetchone()
        if not board or board['owner_email'] != sharer_email:
            return jsonify(success=False, message="Solo el propietario puede compartir."), 403

        cursor.execute("SELECT id FROM users WHERE email = %s", (recipient_email,))
        if not cursor.fetchone():
            return jsonify(success=False, message=f"El usuario '{recipient_email}' no existe."), 404

        cursor.execute("""
            INSERT INTO collaborators (board_id, user_email, permission_level)
            VALUES (%s, %s, %s)
            ON CONFLICT (board_id, user_email) DO UPDATE SET
                permission_level = EXCLUDED.permission_level
        """, (board_id, recipient_email, permission_level))
        
        cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id,))
        updated_collaborators = [dict(row) for row in cursor.fetchall()]
        
        conn.commit()
        return jsonify(success=True, message="Tablero compartido.", shared_with=updated_collaborators)
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en POST /boards/{board_id}/share: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()



@app.route('/boards/<int:board_id>/collaborators/update', methods=['PUT'])
def update_collaborator_permission(board_id):
    """Actualiza el permiso de un colaborador y le notifica directamente su nuevo rol."""
    data = request.get_json()
    owner_email = data.get('owner_email')
    collaborator_email = data.get('collaborator_email').lower().strip()
    permission_level = data.get('permission_level')

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT owner_email FROM boards WHERE id = %s", (board_id,))
        board = cursor.fetchone()
        if not board or board['owner_email'] != owner_email:
            return jsonify(success=False, message="Solo el propietario puede cambiar permisos."), 403

        cursor.execute(
            "UPDATE collaborators SET permission_level = %s WHERE board_id = %s AND user_email = %s",
            (permission_level, board_id, collaborator_email)
        )
        conn.commit()
        
        # --- INICIO DE LA CORRECCIÓN CLAVE (NUEVO MÉTODO) ---
        # 1. Notifica al usuario afectado su nuevo nivel de permiso de forma DIRECTA.
        #    Se envía a su "sala" personal, que es su propio email.
        socketio.emit('my_permission_updated', {
            'board_id': board_id,
            'new_permission_level': permission_level
        }, room=collaborator_email)

        # 2. Notifica a TODOS los demás para que actualicen la lista de colaboradores.
        socketio.emit('permissions_updated', {'board_id': board_id}, room=str(board_id))
        # --- FIN DE LA CORRECCIÓN CLAVE ---
        
        return jsonify(success=True, message="Permiso actualizado.")

    except Exception as e:
        if conn: conn.rollback()
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()


@app.route('/boards/<int:board_id>/share', methods=['DELETE'])
def remove_collaborator(board_id):
    """Elimina a un colaborador y notifica a los clientes."""
    data = request.get_json()
    remover_by_email = data.get('remover_by_email')
    email_to_remove = data.get('email_to_remove')

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT owner_email FROM boards WHERE id = %s", (board_id,))
        board = cursor.fetchone()
        if not board or board['owner_email'] != remover_by_email:
            return jsonify(success=False, message="Solo el propietario puede quitar acceso."), 403

        if board['owner_email'] == email_to_remove:
            return jsonify(success=False, message="No puedes eliminar al propietario."), 400

        cursor.execute("DELETE FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email_to_remove))
        conn.commit()

        # --- INICIO DE LA CORRECCIÓN CLAVE (MÉTODO ROBUSTO) ---
        # Se emite el mismo evento de invalidación.
        socketio.emit('permissions_updated', {'board_id': board_id}, room=str(board_id))
        # --- FIN DE LA CORRECCIÓN CLAVE ---

        return jsonify(success=True, message="Colaborador eliminado.")

    except Exception as e:
        if conn: conn.rollback()
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()

# ############################################################################
# # SECCIÓN 3.5: NUEVAS RUTAS Y FUNCIONES AUXILIARES PARA CHATS PERSONALES   #
# ############################################################################

def get_conversation_id(email1, email2):
    """Crea un ID de conversación consistente y ordenado para dos emails."""
    return "__".join(sorted([email1.lower().strip(), email2.lower().strip()]))

@app.route('/users/directory', methods=['GET'])
def get_user_directory():
    """Devuelve una lista de todos los usuarios para iniciar nuevos chats."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, first_name, last_name, email FROM users")
        users = [dict(row) for row in cursor.fetchall()]
        return jsonify(success=True, users=users)
    except Exception as e:
        print(f"🚨 ERROR en /users/directory: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()

# ############################################################################
# # SECCIÓN 4: SOCKET.IO PARA COMUNICACIÓN EN TIEMPO REAL
# ############################################################################




# EN: app.py (Reemplazar/Añadir este bloque completo de funciones de socket)

# --- INICIO DEL BLOQUE CORREGIDO ---
@socketio.on('join_board')
def handle_join_board(data):
    """Un usuario se une a la 'sala' de un tablero y se registra como activo."""
    board_id = data.get('board_id')
    email = data.get('email')
    if board_id and email:
        join_room(str(board_id))
        active_users[request.sid] = {'email': email, 'board_id': board_id}
        print(f"SOCKET: Usuario {email} se unió al tablero {board_id}. Activos: {len(active_users)}")
        # Notifica a la sala que el estado de los colaboradores ha cambiado
        socketio.emit('collaborator_status_change', room=str(board_id))

@socketio.on('leave_board')
def handle_leave_board(data):
    """Un usuario deja la 'sala' de un tablero."""
    board_id = data.get('board_id')
    if board_id:
        leave_room(str(board_id))
        if request.sid in active_users:
            active_users[request.sid]['board_id'] = None
        print(f"SOCKET: Usuario dejó la sala del tablero {board_id}.")
        socketio.emit('collaborator_status_change', room=str(board_id))

@socketio.on('disconnect')
def handle_disconnect():
    """Maneja la desconexión de un usuario de la aplicación."""
    if request.sid in active_users:
        user_info = active_users.pop(request.sid)
        board_id = user_info.get('board_id')
        print(f"SOCKET: Usuario {user_info.get('email')} desconectado. Activos: {len(active_users)}")
        if board_id:
            socketio.emit('collaborator_status_change', room=str(board_id))

@socketio.on('get_collaborator_status')
def get_collaborator_status(data):
    """Obtiene la lista de colaboradores de un tablero y su estado de conexión."""
    board_id = data.get('board_id')
    if not board_id: return

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Obtiene todos los colaboradores del tablero desde la DB (incluyendo nombres)
        cursor.execute("""
            SELECT u.first_name, u.last_name, u.email
            FROM collaborators c
            JOIN users u ON c.user_email = u.email
            WHERE c.board_id = %s
        """, (board_id,))
        collaborators = [dict(row) for row in cursor.fetchall()]

        # Obtiene los emails de los usuarios actualmente activos
        active_emails = {user['email'] for user in active_users.values()}

        # Combina la información: añade el estado 'online' u 'offline'
        for collab in collaborators:
            collab['status'] = 'online' if collab['email'] in active_emails else 'offline'
            collab['name'] = f"{collab.get('first_name', '')} {collab.get('last_name', '')}".strip()

        # Enviar la lista de vuelta al usuario que la solicitó
        emit('collaborator_status_updated', {'collaborators': collaborators})
        
    except Exception as e:
        print(f"🚨 ERROR en 'get_collaborator_status': {e}")
        traceback.print_exc()
    finally:
        if conn: conn.close()
# --- FIN DEL BLOQUE CORREGIDO ---





@socketio.on('new_chat_message')
def handle_new_chat_message(data):
    """Recibe, guarda y retransmite un mensaje de chat de un tablero."""
    board_id = data.get('board_id')
    if board_id:
        # Añade la hora del servidor para consistencia
        data['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Guardar el mensaje en la base de datos (¡muy importante!)
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO board_chats (board_id, user_email, user_name, message, timestamp) VALUES (%s, %s, %s, %s, %s)",
                (board_id, data.get('user_email'), data.get('user_name'), data.get('message'), data['timestamp'])
            )
            conn.commit()
        except Exception as e:
            print(f"🚨 ERROR guardando mensaje de chat: {e}")
        finally:
            if conn: conn.close()
            
        # Emite el mensaje a todos en la sala del tablero
        emit('chat_message_received', data, room=str(board_id))
        print(f"SOCKET: Mensaje retransmitido al tablero {board_id}")


# ############################################################################
# # SECCIÓN 4.5: NUEVOS HANDLERS DE SOCKET.IO PARA CHATS PERSONALES          #
# ############################################################################

@socketio.on('subscribe_to_personal_channel')
def handle_subscribe(data):
    """Suscribe a un usuario a su propia sala para recibir mensajes privados."""
    email = data.get('email')
    if email:
        join_room(email)
        print(f"SOCKET: Usuario {email} suscrito a su canal personal.")

@socketio.on('global_chat_list_conversations')
def handle_list_conversations(data):
    """Obtiene y envía la lista de conversaciones personales para un usuario."""
    user_email = data.get('email', '').lower().strip()
    if not user_email:
        return
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Esta consulta es más compleja para ser eficiente:
        # 1. Encuentra todas las conversaciones del usuario.
        # 2. Para cada una, obtiene el último mensaje.
        # 3. Cuenta los mensajes no leídos.
        # 4. Obtiene el nombre del otro participante.
        query = """
            WITH UserConversations AS (
                SELECT DISTINCT conv_id,
                       CASE WHEN sender_email = %s THEN receiver_email ELSE sender_email END AS peer_email
                FROM direct_messages
                WHERE sender_email = %s OR receiver_email = %s
            ),
            LastMessage AS (
                SELECT conv_id, text, ts,
                       ROW_NUMBER() OVER(PARTITION BY conv_id ORDER BY ts DESC) as rn
                FROM direct_messages
            ),
            UnreadCounts AS (
                SELECT conv_id, COUNT(*) as unread_count
                FROM direct_messages
                WHERE receiver_email = %s AND is_read = 0
                GROUP BY conv_id
            )
            SELECT
                uc.conv_id,
                uc.peer_email,
                u.first_name || ' ' || u.last_name AS peer_name,
                lm.text AS last_message,
                lm.ts AS last_ts,
                COALESCE(ucnt.unread_count, 0) AS unread_count
            FROM UserConversations uc
            LEFT JOIN LastMessage lm ON uc.conv_id = lm.conv_id AND lm.rn = 1
            LEFT JOIN UnreadCounts ucnt ON uc.conv_id = ucnt.conv_id
            LEFT JOIN users u ON uc.peer_email = u.email
            ORDER BY lm.ts DESC;
        """
        cursor.execute(query, (user_email, user_email, user_email, user_email))
        conversations = [dict(row) for row in cursor.fetchall()]
        
        emit('global_chat_conversations', {'conversations': conversations})
    except Exception as e:
        print(f"🚨 ERROR en 'global_chat_list_conversations': {e}")
        traceback.print_exc()
    finally:
        if conn: conn.close()

@socketio.on('global_chat_start')
def handle_start_conversation(data):
    """Carga el historial de una conversación específica."""
    user_email = data.get('email')
    partner_email = data.get('partner_email')
    if not user_email or not partner_email:
        return

    conv_id = get_conversation_id(user_email, partner_email)
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT dm.*, u.first_name || ' ' || u.last_name as sender_name FROM direct_messages dm "
            "JOIN users u ON dm.sender_email = u.email WHERE conv_id = %s ORDER BY ts ASC", (conv_id,)
        )
        messages = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT first_name, last_name, email FROM users WHERE email = %s", (partner_email,))
        partner_info = dict(cursor.fetchone())

        emit('global_chat_history', {
            'conv_id': conv_id,
            'peer_name': f"{partner_info['first_name']} {partner_info['last_name']}",
            'peer_email': partner_info['email'],
            'messages': messages
        })
        
        # Marcar mensajes como leídos
        cursor.execute(
            "UPDATE direct_messages SET is_read = 1 WHERE conv_id = %s AND receiver_email = %s",
            (conv_id, user_email)
        )
        conn.commit()

    except Exception as e:
        print(f"🚨 ERROR en 'global_chat_start': {e}")
    finally:
        if conn: conn.close()
        

@socketio.on('global_chat_send')
def handle_global_chat_send(data):
    """Guarda un nuevo mensaje y lo retransmite a ambos participantes."""
    sender_email = data.get('sender_email')
    receiver_email = data.get('receiver_email')
    text = data.get('text')
    if not all([sender_email, receiver_email, text]): return
    
    conv_id = get_conversation_id(sender_email, receiver_email)
    now = datetime.now(timezone.utc).isoformat()
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO conversations (id, participants_json, last_ts) VALUES (%s, %s, %s) ON CONFLICT (id) DO UPDATE SET last_ts = EXCLUDED.last_ts",
            (conv_id, json.dumps(sorted([sender_email, receiver_email])), now)
        )

        cursor.execute(
            "INSERT INTO direct_messages (conv_id, sender_email, receiver_email, text, ts, is_read) VALUES (%s, %s, %s, %s, %s, 0) RETURNING *",
            (conv_id, sender_email, receiver_email, text, now)
        )
        new_message = dict(cursor.fetchone())
        conn.commit()
        
        message_payload = {**new_message, 'sender_name': data.get('sender_name', sender_email)}
        
        # Emite a ambos participantes, lo cual es correcto.
        emit('global_chat_new_message', message_payload, room=sender_email)
        emit('global_chat_new_message', message_payload, room=receiver_email)
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en 'global_chat_send': {e}")
        traceback.print_exc()
    finally:
        if conn: conn.close()


@socketio.on('mark_general_chat_read')
def handle_mark_as_read(data):
    """Marca mensajes de una conversación como leídos para un usuario."""
    conv_id = data.get('conv_id')
    user_email = data.get('user_email')
    if not conv_id or not user_email: return
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE direct_messages SET is_read = 1 WHERE conv_id = %s AND receiver_email = %s AND is_read = 0",
            (conv_id, user_email)
        )
        conn.commit()
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en 'mark_general_chat_read': {e}")
    finally:
        if conn: conn.close()

@app.route('/boards/<int:board_id>/chat', methods=['GET'])
def get_board_chat_history(board_id):
    """Obtiene el historial de chat para un tablero específico."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        if not cursor.fetchone():
            return jsonify(success=False, message="Acceso denegado a este chat."), 403

        cursor.execute("SELECT * FROM board_chats WHERE board_id = %s ORDER BY timestamp ASC", (board_id,))
        messages = [dict(row) for row in cursor.fetchall()]
        return jsonify(success=True, messages=messages)
    except psycopg2.errors.UndefinedTable:
        return jsonify(success=True, messages=[]) # Devuelve vacío si la tabla aún no existe
    except Exception as e:
        print(f"🚨 ERROR en GET /boards/{board_id}/chat: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()


@app.route('/boards', methods=['GET'])
def get_boards():
    """
    [MÉTODO CORREGIDO] Obtiene todos los tableros y sus colaboradores 
    asegurando que board_data sea un JSON válido.
    """
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT
                b.*,
                (
                    SELECT JSON_AGG(json_build_object(
                        'user_email', c.user_email, 
                        'permission_level', c.permission_level,
                        'first_name', u.first_name,
                        'last_name', u.last_name
                    ))
                    FROM collaborators c
                    JOIN users u ON c.user_email = u.email
                    WHERE c.board_id = b.id
                ) as shared_with
            FROM
                boards b
            WHERE
                b.id IN (SELECT board_id FROM collaborators WHERE user_email = %s)
        """, (email,))
        
        user_boards = [dict(row) for row in cursor.fetchall()]

        for board in user_boards:
            if board['shared_with'] is None:
                board['shared_with'] = []
            
            # --- CORRECCIÓN CRÍTICA DE PARSEO JSON ---
            raw_data = board.get('board_data')
            if isinstance(raw_data, str):
                try:
                    board['data'] = json.loads(raw_data)
                except json.JSONDecodeError:
                    print(f"⚠️ Error decodificando board_data para tablero {board.get('id')}")
                    board['data'] = {"columns": [], "cards": []} # Fallback seguro
            elif isinstance(raw_data, dict):
                board['data'] = raw_data
            else:
                board['data'] = {"columns": [], "cards": []} # Fallback si es None

            if 'board_data' in board:
                del board['board_data']

        return jsonify(success=True, boards=user_boards)
        
    except Exception as e:
        print(f"🚨 ERROR en GET /boards: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()
        
@app.route('/boards', methods=['POST'])
def create_board():
    """Crea un nuevo tablero verificando que el nombre no exista previamente."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    board_name = data.get('name', 'Nuevo Tablero').strip()
    template_columns = data.get('columns')

    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # --- VERIFICACIÓN DE NOMBRE DUPLICADO ---
        cursor.execute("SELECT 1 FROM boards WHERE owner_email = %s AND LOWER(name) = LOWER(%s)", (email, board_name))
        if cursor.fetchone():
            return jsonify(success=False, message="DUPLICATE_NAME"), 409
        # ----------------------------------------

        now = datetime.now(timezone.utc).isoformat()
        
        # Si el frontend envía una plantilla de columnas, la usamos. Si no, la por defecto.
        board_columns = template_columns if template_columns and isinstance(template_columns, list) else [
            {"id": "col-1", "title": "Por hacer", "color": "bg-red-200"},
            {"id": "col-2", "title": "En proceso", "color": "bg-yellow-200"},
            {"id": "col-3", "title": "Hecho", "color": "bg-green-200"}
        ]
        
        for i, col in enumerate(board_columns):
            if 'id' not in col:
                col['id'] = f'col-{int(time.time() * 1000)}-{i}'

        default_board_data = {"columns": board_columns, "cards": [], "boardOptions": {}}

        cursor.execute(
            "INSERT INTO boards (owner_email, name, board_data, created_date, updated_date, category) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (email, board_name, json.dumps(default_board_data), now, now, "Personal")
        )
        board_id = cursor.fetchone()['id']
        
        cursor.execute("INSERT INTO collaborators (board_id, user_email, permission_level) VALUES (%s, %s, %s)", (board_id, email, 'editor'))
        
        conn.commit()
        return jsonify(success=True, message="Tablero creado", board_id=board_id), 201
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en POST /boards: {e}")
        return jsonify(success=False, message="Error interno del servidor al crear el tablero."), 500
    finally:
        if conn: conn.close()

@app.route('/boards/<int:board_id>/name', methods=['PATCH'])
def update_board_name(board_id):
    """Actualiza solo el nombre de un tablero."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    new_name = data.get('boardName', '').strip()

    if not email or not new_name:
        return jsonify(success=False, message="Email y nuevo nombre son requeridos"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verifica que el usuario tenga permisos de editor
        cursor.execute("SELECT permission_level FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        permission = cursor.fetchone()
        if not permission or permission['permission_level'] != 'editor':
            return jsonify(success=False, message="Permiso de editor requerido."), 403

        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "UPDATE boards SET name = %s, updated_date = %s WHERE id = %s",
            (new_name, now, board_id)
        )
        conn.commit()
        return jsonify(success=True, message="Nombre del tablero actualizado.")
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en PATCH /boards/{board_id}/name: {e}")
        return jsonify(success=False, message="Error interno del servidor al actualizar el nombre."), 500
    finally:
        if conn: conn.close()

@app.route('/notes', methods=['GET', 'POST'])
def handle_notes():
    """Maneja la obtención de todas las notas de un tablero y la creación de una nueva."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.method == 'GET':
            board_id = request.args.get('board_id')
            email = request.args.get('email')
            
            # Verificación de que el usuario tiene acceso (al menos como lector)
            cursor.execute("SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
            if not cursor.fetchone():
                return jsonify(success=False, message="Acceso denegado a las notas de este tablero."), 403

            cursor.execute("SELECT * FROM notes WHERE board_id = %s ORDER BY updated_date DESC", (board_id,))
            notes = [dict(row) for row in cursor.fetchall()]
            return jsonify(success=True, notes=notes)

        if request.method == 'POST':
            data = request.get_json()
            
            # ----- INICIO DE LA CORRECCIÓN CLAVE -----
            # Se verifica que el usuario tenga permiso de 'editor' antes de crear la nota.
            if not check_editor_permission(conn, data['board_id'], data['email']):
                return jsonify(success=False, message="Permiso de editor requerido para crear notas."), 403
            # ----- FIN DE LA CORRECCIÓN CLAVE -----
            
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO notes (board_id, user_email, content, color, created_date, updated_date) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (data['board_id'], data['email'], data['content'], data['color'], now, now)
            )
            new_note = dict(cursor.fetchone())
            conn.commit()
            socketio.emit('note_created', {'board_id': data['board_id'], 'note': new_note}, room=str(data['board_id']))
            return jsonify(success=True, note=new_note), 201

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en /notes: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500
    finally:
        if conn: conn.close()


@app.route('/admin/index.html')
def serve_admin_index():
    return render_template('index2.html')

@app.route('/admin/dashboard.html')
def serve_admin_dashboard():
    return render_template('dashboard.html')

@app.route('/admin/users.html')
def serve_admin_users():
    # Asumiendo que tienes un archivo users.html o lo crearás
    return render_template('users.html')

@app.route('/admin/assistants.html')
def serve_admin_assistants():
    return render_template('assistants.html')

@app.route('/admin/notifications.html')
def serve_admin_notifications():
    return render_template('notifications.html')

@app.route('/admin/database.html')
def serve_admin_database():
    return render_template('database.html')

@app.route('/admin/focux-view.html')
def serve_admin_focux_view():
    return render_template('focux-view.html')

@app.route('/admin/focux_message.html')
def serve_admin_focux_message():
    return render_template('focux_message.html')

@app.route('/admin/telegram_sender.html')
def serve_admin_telegram_sender():
    return render_template('telegram_sender.html')

@app.route('/admin/ia_boards.html')
def serve_admin_ia_boards():
    return render_template('ia_boards.html')

@app.route('/admin/settings.html')
def serve_admin_settings():
    return render_template('settings.html')


def get_user_details_from_db():
    """Obtiene detalles de todos los usuarios para el dashboard."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    u.email, 
                    u.first_name, 
                    u.last_name, 
                    u.last_login,
                    u.registration_date,
                    COUNT(b.id) as boards_count
                FROM users u
                LEFT JOIN boards b ON u.email = b.owner_email
                GROUP BY u.id
                ORDER BY u.registration_date DESC
            """)
            users = [dict(row) for row in cur.fetchall()]
            
            # Determinar estado
            now = datetime.now(timezone.utc)
            for user in users:
                user['name'] = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
                if not user['last_login']:
                    user['status'] = 'inactive'
                    user['days_since_login'] = -1
                else:
                    last_login_date = datetime.fromisoformat(user['last_login'])
                    days_inactive = (now - last_login_date).days
                    user['days_since_login'] = days_inactive
                    if days_inactive <= 7:
                        user['status'] = 'active'
                    else:
                        user['status'] = 'inactive'

            return users
    finally:
        conn.close()

# --- Rutas de API para el Dashboard ---

@app.route('/admin/dashboard', methods=['GET'])
def get_dashboard_data():
    """Endpoint principal para los datos del dashboard de admin."""
    try:
        all_users = get_user_details_from_db()
        
        # Resumen
        total_users = len(all_users)
        active_users_count = len([u for u in all_users if u['status'] == 'active'])
        
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM boards")
            total_boards = cur.fetchone()['total']
        conn.close()

        summary = {
            "total_users": total_users,
            "active_users": active_users_count,
            "total_boards": total_boards
        }
        
        # Actividad de usuarios (top 15 más recientes)
        user_activity = sorted(all_users, key=lambda u: u.get('last_login') or '1970-01-01', reverse=True)[:15]

        # Tableros recientes
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    b.name, 
                    b.owner_email,
                    b.created_date, 
                    (SELECT COUNT(*) FROM jsonb_to_recordset(b.board_data->'cards') as c(id text)) as cards_count
                FROM boards b 
                ORDER BY b.created_date DESC 
                LIMIT 10
            """)
            recent_boards_raw = [dict(row) for row in cur.fetchall()]
        conn.close()
        
        # Mapear email a nombre de propietario
        email_to_name = {u['email']: u['name'] for u in all_users}
        recent_boards = []
        for board in recent_boards_raw:
            board['owner'] = email_to_name.get(board['owner_email'], board['owner_email'])
            recent_boards.append(board)
            
        stats = {
            "summary": summary,
            "quick_stats": {"active_sessions": len(active_users)},
            "user_activity": user_activity,
            "recent_boards": recent_boards,
            "detailed_users": all_users,
            "detailed_boards": recent_boards_raw # para gráficas
        }
        
        return jsonify(success=True, stats=stats)
        
    except Exception as e:
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500


# --- Rutas para Focux View ---

@app.route('/admin/focux-view-data', methods=['GET'])
def get_focux_view_data():
    email = request.args.get('email')
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Obtener tableros
            cur.execute("""
                SELECT b.*, u.first_name, u.last_name 
                FROM boards b 
                JOIN users u ON b.owner_email = u.email
                WHERE b.id IN (SELECT board_id FROM collaborators WHERE user_email = %s)
            """, (email,))
            boards = [dict(row) for row in cur.fetchall()]
            
            processed_boards = []
            for board in boards:
                board['data'] = board.get('board_data', {})
                # Simplificar para no enviar datos muy pesados
                if 'cards' in board['data']:
                    board['data']['cards'] = board['data']['cards'][:50] # Limitar a 50 tarjetas
                processed_boards.append(board)

            # Obtener notas (si la tabla existe)
            try:
                cur.execute("SELECT * FROM notes WHERE board_id IN (SELECT id FROM boards WHERE owner_email = %s)", (email,))
                notes_raw = [dict(row) for row in cur.fetchall()]
                
                # Agrupar notas por tablero
                for board in processed_boards:
                    board['notes'] = [n for n in notes_raw if n['board_id'] == board['id']]

            except psycopg2.errors.UndefinedTable:
                print("Tabla 'notes' no encontrada, se omite.")


        return jsonify(success=True, boards=processed_boards)
    finally:
        conn.close()

# --- Rutas para Gestión de Asistentes ---


@app.route('/admin/assistants', methods=['GET'])
def admin_get_assistants():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM assistants ORDER BY name")
            assistants_raw = [dict(row) for row in cur.fetchall()]
            
            # Obtener a quién está compartido cada asistente
            for assistant in assistants_raw:
                cur.execute("SELECT user_email FROM assistant_sharing WHERE assistant_id = %s", (assistant['id'],))
                assistant['shared_with'] = [row['user_email'] for row in cur.fetchall()]
        return jsonify(success=True, assistants=assistants_raw)
    finally:
        conn.close()


@app.route('/admin/assistants', methods=['POST'])
def admin_save_assistants():
    assistants_data = request.get_json()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Sincronización: Eliminar asistentes que ya no están en la lista
            existing_ids = [a['id'] for a in assistants_data if not str(a.get('id','')).startswith('new-')]
            if existing_ids:
                cur.execute("DELETE FROM assistants WHERE id NOT IN %s", (tuple(existing_ids),))
            else:
                cur.execute("DELETE FROM assistants")

            for assistant in assistants_data:
                assistant_id = assistant.get('id')
                # Si es un asistente nuevo, genera un ID
                if not assistant_id or str(assistant_id).startswith('new-'):
                    assistant_id = f"asst_{os.urandom(8).hex()}"
                
                cur.execute("""
                    INSERT INTO assistants (id, name, description, avatar_url, prompt, knowledge_base, is_public)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        avatar_url = EXCLUDED.avatar_url,
                        prompt = EXCLUDED.prompt,
                        knowledge_base = EXCLUDED.knowledge_base,
                        is_public = EXCLUDED.is_public
                """, (
                    assistant_id,
                    assistant.get('name'),
                    assistant.get('description'),
                    assistant.get('avatar_url'),
                    assistant.get('prompt'),
                    assistant.get('knowledge_base'),
                    1 if assistant.get('is_public') else 0
                ))
                
                # Actualizar sharing
                cur.execute("DELETE FROM assistant_sharing WHERE assistant_id = %s", (assistant_id,))
                if not assistant.get('is_public') and assistant.get('shared_with'):
                    sharing_data = [(assistant_id, email) for email in assistant['shared_with']]
                    psycopg2.extras.execute_values(
                        cur,
                        "INSERT INTO assistant_sharing (assistant_id, user_email) VALUES %s",
                        sharing_data
                    )
            
            conn.commit()
            # Notificar a los clientes conectados de los cambios
            socketio.emit('assistants_updated')
        return jsonify(success=True, message="Asistentes guardados.")
    except Exception as e:
        conn.rollback()
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()



@app.route('/admin/assistants/<assistant_id>', methods=['DELETE'])
def delete_assistant_admin(assistant_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM assistants WHERE id = %s", (assistant_id,))
            conn.commit()
            socketio.emit('assistants_updated') # Notificar a los clientes
        return jsonify(success=True, message="Asistente eliminado.")
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()



@app.route('/admin/focux_messages', methods=['GET'])
def get_focux_messages_admin():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM focux_messages ORDER BY id DESC")
            messages = [dict(row) for row in cur.fetchall()]
        return jsonify(success=True, messages=messages)
    finally:
        conn.close()

@app.route('/admin/focux_messages', methods=['POST'])
def save_focux_messages_admin():
    messages = request.get_json()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Borrar todos los mensajes existentes para sincronizar
            cur.execute("DELETE FROM focux_messages")
            if messages:
                for msg in messages:
                    cur.execute("""
                        INSERT INTO focux_messages (id, title, content, color, image_url, button_text, button_url, is_active, start_date, end_date, target_info)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        msg.get('id') or f"msg_{os.urandom(8).hex()}",
                        msg.get('title'), msg.get('content'), msg.get('color'),
                        msg.get('image_url'), msg.get('button_text'), msg.get('button_url'),
                        1 if msg.get('is_active') else 0,
                        msg.get('start_date') or None, msg.get('end_date') or None,
                        msg.get('target_info')
                    ))
            conn.commit()
        return jsonify(success=True, message="Mensajes guardados.")
    except Exception as e:
        conn.rollback()
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()


@app.route('/admin/focux_messages/<message_id>', methods=['DELETE'])
def delete_focux_message_admin(message_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Ejecuta el comando para borrar el mensaje con el ID específico
            cur.execute("DELETE FROM focux_messages WHERE id = %s", (message_id,))
            conn.commit()
            # cur.rowcount nos dice si se eliminó alguna fila. Si es 0, el mensaje no se encontró.
            if cur.rowcount == 0:
                return jsonify(success=False, message="Mensaje no encontrado."), 404
        return jsonify(success=True, message="Mensaje eliminado.")
    except Exception as e:
        conn.rollback()
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        if conn: conn.close()

# --- Rutas para Generación con IA ---


@app.route('/chat/ask', methods=['POST'])
def ask_chat():
    """Procesa un mensaje de un usuario para un asistente de IA específico."""
    if not genai:
        return jsonify(success=False, message="El servicio de IA no está configurado."), 500

    data = request.get_json()
    assistant_id = data.get('assistant_id')
    message = data.get('message')
    history = data.get('history', [])

    if not all([assistant_id, message]):
        return jsonify(success=False, message="Faltan datos para la consulta."), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assistants WHERE id = %s", (assistant_id,))
        assistant = cursor.fetchone()
        if not assistant:
            return jsonify(success=False, message="Asistente no encontrado."), 404

        system_prompt = assistant['prompt'] or "Eres un asistente servicial."
        
        formatted_history = []
        for msg in history:
            role = 'user' if msg.get('sender') == 'user' else 'model'
            formatted_history.append({'role': role, 'parts': [msg.get('content', '')]})

        # CORRECCIÓN: Usar un modelo más moderno
        model = genai.GenerativeModel('gemini-2.5-flash', system_instruction=system_prompt)
        chat = model.start_chat(history=formatted_history)
        response = chat.send_message(message)

        return jsonify(success=True, reply=response.text.strip())

    except Exception as e:
        print(f"🚨 ERROR en POST /chat/ask: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error al contactar la IA: {str(e)}"), 500
    finally:
        if conn: conn.close()



@app.route('/admin/ai/generate-board', methods=['POST'])
def generate_ai_board():
    if not genai:
        return jsonify(success=False, message="La API de IA no está configurada en el servidor."), 503

    data = request.get_json()
    user_prompt = data.get('prompt')
    start_date_str = data.get('start_date')
    end_date_str = data.get('end_date')

    if not user_prompt:
        return jsonify(success=False, message="La descripción del tablero es requerida."), 400

    try:
        model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        model = genai.GenerativeModel(model_name)
        print(f"🤖 Iniciando generación de tablero (Parsing Mejorado). Modelo: {model_name}")

        template_prompt = f"""
        Actúa como un Project Manager experto y genera un plan de proyecto exhaustivo basado en la solicitud: "{user_prompt}"

        INSTRUCCIONES CRÍTICAS Y OBLIGATORIAS:
        1.  **VOLUMEN**: Genera un mínimo de 40 a 60 tarjetas en total.
        2.  **NOTAS**: Genera un mínimo de 5 notas de apoyo útiles y detalladas.
        3.  **DESCRIPCIÓN DE TARJETA**: Cada tarjeta debe tener "Contexto" y "Objetivos" detallados. **DEBE HABER DOS LÍNEAS EN BLANCO (un doble salto de párrafo) entre ellos.**
        4.  **CHECKLIST**: Cada tarjeta debe tener un checklist con 3 a 4 acciones detalladas. Es OBLIGATORIO usar el separador `---CHECKLIST---` antes de la lista.
        5.  **FORMATO EXACTO**: Usa los marcadores (BOARD_NAME_START, etc.) EXACTAMENTE como se muestra. No uses `[` `]` ni `**`. Cada tarjeta debe contener una única línea `COLUMN_TITLE::`.

        **ESTRUCTURA OBLIGATORIA:**
        1. Primero todas las columnas
        2. Después todas las tarjetas EN ORDEN SECUENCIAL LÓGICO
        3. Al final todas las notas

        **IMPORTANTE SOBRE SECUENCIA:**
        - Organiza las tarjetas por orden de ejecución temporal
        - Las primeras tarjetas deben ser preparación/planificación
        - Las siguientes deben ser acciones iniciales
        - Continúa con desarrollo/implementación
        - Termina con revisión/cierre
        - Dentro de cada columna, ordena las tarjetas por prioridad

        Usa el siguiente formato de texto plano:
        BOARD_NAME_START
        Nombre del Tablero
        BOARD_NAME_END

        COLUMN_START
        Título de la Columna
        COLUMN_END

        CARD_START
        COLUMN_TITLE::Título de la Columna
        CARD_TITLE::Título de la Tarjeta
        CARD_TAGS::Urgente, Importante
        CARD_DESCRIPTION::
Contexto: Párrafo detallado sobre la tarea.


Objetivos: Párrafo detallado sobre el resultado esperado.
        ---CHECKLIST---
        CHECKLIST_ITEM::Acción detallada 1.
        CHECKLIST_ITEM::Acción detallada 2.
        CHECKLIST_ITEM::Acción detallada 3.
        CARD_END
        
        NOTE_START
        NOTE_TITLE::Título de la Nota
        NOTE_CONTENT::Contenido detallado de la nota.
        NOTE_END
        """
        response = model.generate_content(template_prompt)
        raw_text = response.text
        
        final_board = { "board_name": "", "columns": [], "cards": [], "notes": [] }

        def clean_text(text):
            return text.strip().strip('[]').strip()

        def safe_split_on_first(text, separator):
            return text.split(separator, 1) if separator in text else (text, '')

        board_name_match = re.search(r"BOARD_NAME_START\n(.*?)\nBOARD_NAME_END", raw_text, re.DOTALL)
        if board_name_match: 
            final_board["board_name"] = clean_text(board_name_match.group(1))

        column_titles = re.findall(r"COLUMN_START\n(.*?)\nCOLUMN_END", raw_text, re.DOTALL)
        column_map = {}
        for i, title in enumerate(column_titles):
            clean_title = clean_text(title.split('\n')[0])
            if clean_title and clean_title not in column_map:
                col_id = f"col-{i+1}-{uuid.uuid4().hex[:4]}"
                column_map[clean_title] = col_id
                final_board["columns"].append({"id": col_id, "title": clean_title, "color": "bg-blue-200"})
        
        card_blocks = re.findall(r"CARD_START\n(.*?)\nCARD_END", raw_text, re.DOTALL)
        print(f"  -> Encontrados {len(card_blocks)} bloques de tarjetas")
        
        for i, block in enumerate(card_blocks):
            try:
                card_col_title_match = re.search(r"COLUMN_TITLE::(.*?)\n", block)
                card_title_match = re.search(r"CARD_TITLE::(.*?)\n", block)
                tags_match = re.search(r"CARD_TAGS::(.*?)\n", block)
                
                if not card_col_title_match:
                    print(f"⚠️ Tarjeta #{i+1} omitida: sin COLUMN_TITLE")
                    continue
                
                card_col_title = clean_text(card_col_title_match.group(1))

                if card_col_title not in column_map:
                    print(f"  -> Creando columna: '{card_col_title}'")
                    col_id = f"col-auto-{uuid.uuid4().hex[:4]}"
                    column_map[card_col_title] = col_id
                    final_board["columns"].append({"id": col_id, "title": card_col_title, "color": "bg-purple-200"})
                
                card = {
                    "id": str(uuid.uuid4()), "columnId": column_map[card_col_title],
                    "title": clean_text(card_title_match.group(1)) if card_title_match else f"Tarjeta {i+1}",
                    "description": "", "checklist": [],
                    "tags": [{'text': t.strip()} for t in clean_text(tags_match.group(1)).split(',') if t.strip()] if tags_match else [],
                    "order": i + 1, "sequence": f"Paso {i + 1}"
                }

                desc_start = block.find('CARD_DESCRIPTION::')
                if desc_start != -1:
                    desc_content = block[desc_start + len('CARD_DESCRIPTION::'):]
                    desc_part, checklist_part = safe_split_on_first(desc_content, '---CHECKLIST---')
                    
                    clean_desc = clean_text(desc_part)
                    if clean_desc:
                        paragraphs = [p.strip() for p in clean_desc.split('\n\n') if p.strip()]
                        html_desc = "".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs)
                        card['description'] = html_desc

                    if checklist_part.strip():
                        checklist_clean = checklist_part.split('CARD_END')[0].split('NOTE_START')[0]
                        checklist_items = []
                        for line in checklist_clean.split('\n'):
                            line = line.strip()
                            if line.startswith('CHECKLIST_ITEM::'):
                                item_text = clean_text(line.replace('CHECKLIST_ITEM::', ''))
                                if item_text and len(item_text) < 200:
                                    checklist_items.append({'id': str(uuid.uuid4()), 'text': item_text, 'completed': False})
                        card['checklist'] = checklist_items

                final_board["cards"].append(card)
                print(f"  -> Tarjeta procesada: '{card['title'][:30]}...' con {len(card['checklist'])} items")

            except Exception as card_error:
                print(f"⚠️ Error procesando tarjeta #{i+1}: {card_error}")
                continue
        
        note_blocks = re.findall(r"NOTE_START\n(.*?)\nNOTE_END", raw_text, re.DOTALL)
        print(f"  -> Encontradas {len(note_blocks)} notas")
        
        for note_block in note_blocks:
            title_match = re.search(r"NOTE_TITLE::(.*?)\n", note_block)
            content_match = re.search(r"NOTE_CONTENT::(.*?)(?=\nNOTE_END|\Z)", note_block, re.DOTALL)
            
            if title_match and content_match:
                final_board["notes"].append({"title": clean_text(title_match.group(1)), "content": clean_text(content_match.group(1))})

        if start_date_str and end_date_str and final_board["cards"]:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                total_seconds = (end_date - start_date).total_seconds()
                card_count = len(final_board["cards"])

                if total_seconds >= 0 and card_count > 0:
                    seconds_per_card = total_seconds / card_count
                    
                    current_start_time = start_date
                    for card in final_board["cards"]:
                        current_end_time = current_start_time + timedelta(seconds=seconds_per_card)
                        final_end_time = min(current_end_time, end_date)
                        
                        card['startDate'] = current_start_time.strftime('%Y-%m-%d')
                        card['endDate'] = final_end_time.strftime('%Y-%m-%d')

                        current_start_time = final_end_time
                    
                    print(f"🗓️ Fechas de inicio y fin asignadas a {card_count} tarjetas.")
            except (ValueError, TypeError):
                print("⚠️ Formato de fecha inválido o rango incorrecto. Las tarjetas se generarán sin fecha.")
        
        column_ids_with_cards = {card['columnId'] for card in final_board['cards']}
        final_board['columns'] = [col for col in final_board['columns'] if col['id'] in column_ids_with_cards]
        
        if not any(col['title'].lower().find('complet') != -1 for col in final_board['columns']):
            final_board["columns"].append({"id": "col-done", "title": "¡Completado! ✅", "color": "bg-green-200"})
        
        print(f"✅ Tablero generado: {len(final_board['columns'])} columnas, {len(final_board['cards'])} tarjetas, {len(final_board['notes'])} notas")
        
        return jsonify(success=True, board=final_board)

    except Exception as e:
        print(f"🚨 ERROR en generación de tablero IA: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error durante la generación: {str(e)[:200]}"), 500


@app.route('/admin/ai/assign-board', methods=['POST'])
def assign_ai_board():
    data = request.get_json()
    board_data = data.get('board_data')
    target_users = data.get('target_users', [])
    target_databases = data.get('target_databases', [])
    suggested_assistants = data.get('suggested_assistants', [])

    if not all([board_data, (target_users or target_databases)]):
        return jsonify(success=False, message="Faltan datos para asignar."), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            now = datetime.now(timezone.utc).isoformat()
            
            # 1. Determinar todos los emails destinatarios
            all_target_emails = set(target_users)
            if target_databases:
                cur.execute("SELECT email FROM users WHERE manager_id IN %s", (tuple(target_databases),))
                db_users = {row['email'] for row in cur.fetchall()}
                all_target_emails.update(db_users)
            
            final_emails = list(all_target_emails)
            if not final_emails:
                 return jsonify(success=False, message="No se encontraron usuarios válidos."), 404

            # 2. Guardar asistentes sugeridos y compartirlos con los usuarios finales
            if suggested_assistants:
                print(f"INFO: Guardando {len(suggested_assistants)} asistente(s) sugerido(s)...")
                for assistant_data in suggested_assistants:
                    assistant_id = f"asst_{os.urandom(8).hex()}"
                    cur.execute("""
                        INSERT INTO assistants (id, name, description, avatar_url, prompt, knowledge_base, is_public)
                        VALUES (%s, %s, %s, %s, %s, %s, 0)
                    """, (
                        assistant_id, assistant_data.get('name'), assistant_data.get('name'),
                        assistant_data.get('avatar_url'), assistant_data.get('prompt'),
                        assistant_data.get('knowledge_base')
                    ))
                    # Compartir el nuevo asistente con todos los usuarios destinatarios
                    sharing_data = [(assistant_id, email) for email in final_emails]
                    if sharing_data:
                        psycopg2.extras.execute_values(
                            cur, "INSERT INTO assistant_sharing (assistant_id, user_email) VALUES %s", sharing_data
                        )
                print("INFO: Asistentes guardados y compartidos.")

            # 3. Crear tablero y notas para cada usuario
            for email in final_emails:
                print(f"INFO: Procesando asignación para {email}...")
                # Crear el tablero principal
                cur.execute(
                    "INSERT INTO boards (owner_email, name, board_data, created_date, updated_date, category) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                    (email, board_data['board_name'], json.dumps(board_data), now, now, "Laboral")
                )
                board_id = cur.fetchone()['id']
                print(f"INFO: Tablero creado con ID {board_id} para {email}.")
                
                # Asignarse a sí mismo como colaborador
                cur.execute("INSERT INTO collaborators (board_id, user_email, permission_level) VALUES (%s, %s, %s)", (board_id, email, 'editor'))

                # Crear las notas de apoyo para este tablero específico
                notes_to_add = board_data.get('notes', [])
                if notes_to_add and isinstance(notes_to_add, list):
                    print(f"INFO: Guardando {len(notes_to_add)} nota(s) para el tablero {board_id}...")
                    for note in notes_to_add:
                        note_content = f"<h1>{note.get('title', 'Nota')}</h1><p>{note.get('content', '')}</p>"
                        cur.execute("""
                            INSERT INTO notes (board_id, user_email, content, color, created_date, updated_date)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (board_id, email, note_content, 'note-yellow', now, now))
                print(f"INFO: Asignación para {email} completada.")

            conn.commit()
            
            socketio.emit('assistants_updated')
            
        return jsonify(success=True, message=f"Tablero, notas y asistentes asignados a {len(final_emails)} usuarios.")
    except Exception as e:
        conn.rollback()
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()




@app.route('/telegram/stats', methods=['GET'])
def get_telegram_stats():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM users WHERE telegram_chat_id IS NOT NULL")
            connected_users = cur.fetchone()[0]
        return jsonify(success=True, stats={'total_users': total_users, 'connected_users': connected_users})
    finally:
        conn.close()
        
@app.route('/admin/telegram/connected-users-details', methods=['GET'])
def get_connected_users_details():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT email, first_name, last_name, manager_id FROM users WHERE telegram_chat_id IS NOT NULL")
            users = [dict(row) for row in cur.fetchall()]
        return jsonify(success=True, users=users)
    finally:
        conn.close()

@socketio.on('card_moved')
def handle_card_moved(data):
    """
    Retransmite el evento de una tarjeta movida a todos en la sala del tablero,
    excluyendo a quien originó el movimiento.
    """
    board_id = data.get('board_id')
    
    # Añadimos el email de quien envía para que su propio cliente pueda ignorar el evento
    if request.sid in active_users:
        data['email'] = active_users[request.sid].get('email')

    if board_id:
        # 'include_self=False' es clave para no enviarle el evento de vuelta a quien lo emitió
        emit('card_moved', data, room=str(board_id), include_self=False)
        print(f"SOCKET: Retransmitiendo 'card_moved' para el tablero {board_id}")




@socketio.on('card_created')
def handle_card_created(data):
    """
    Retransmite el evento de una tarjeta nueva a todos en la sala del tablero.
    Funciona tanto para tarjetas creadas desde cero como para duplicadas.
    """
    board_id = data.get('board_id')
    if request.sid in active_users:
        data['email'] = active_users[request.sid].get('email')

    if board_id:
        emit('card_created', data, room=str(board_id), include_self=False)
        print(f"SOCKET: Retransmitiendo 'card_created' para el tablero {board_id}")



# --- Rutas para el Historial de Notificaciones (notifications.html) ---



# --- Rutas para IA Boards (ia_boards.html) ---



@app.route('/admin/databases/details', methods=['GET'])
def get_database_details():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Obtiene el conteo de usuarios por manager_id
            cur.execute("SELECT manager_id, COUNT(*) as user_count FROM users WHERE manager_id IS NOT NULL GROUP BY manager_id")
            db_stats = {row['manager_id']: row['user_count'] for row in cur.fetchall()}
            
            # Obtiene las configuraciones de logo y fondo
            cur.execute("SELECT manager_id, logo_url, background_url FROM manager_settings")
            settings = {row['manager_id']: {'logo_url': row['logo_url'], 'background_url': row['background_url']} for row in cur.fetchall()}

        databases = []
        for db_name, user_count in db_stats.items():
             databases.append({
                "filename": db_name,
                "display_name": db_name,
                "size": f"{user_count} usuario(s)",
                "last_modified": None, # Puedes añadir esta lógica si necesitas registrar últimas modificaciones
                "logo_url": settings.get(db_name, {}).get('logo_url', ''),
                "background_url": settings.get(db_name, {}).get('background_url', '')
             })
        return jsonify(success=True, databases=databases)
    finally:
        conn.close()

@app.route('/admin/database/logo', methods=['POST'])
def set_db_logo():
    data = request.get_json()
    db_name = data.get('db_name')
    logo_url = data.get('logo_url')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO manager_settings (manager_id, logo_url) VALUES (%s, %s)
                ON CONFLICT (manager_id) DO UPDATE SET logo_url = EXCLUDED.logo_url
            """, (db_name, logo_url))
            conn.commit()
        return jsonify(success=True, message="Logo guardado.")
    except Exception as e:
        conn.rollback(); traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()

# --- Rutas para el Historial y Envío de Notificaciones (notifications.html) ---

@app.route('/admin/notifications', methods=['GET'])
def get_notifications_history():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM admin_notifications ORDER BY timestamp DESC LIMIT 100")
            notifications = [dict(row) for row in cur.fetchall()]
        return jsonify(success=True, notifications=notifications)
    finally:
        conn.close()

def send_telegram_message(chat_id, message):
    """Función auxiliar para enviar un mensaje a un chat de Telegram."""
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not bot_token:
        print("⚠️ Advertencia: TELEGRAM_BOT_TOKEN no está configurado.")
        return False
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'HTML'
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return response.json().get('ok', False)
    except requests.exceptions.RequestException as e:
        print(f"🚨 Error enviando a Telegram (Chat ID: {chat_id}): {e}")
        return False

@app.route('/admin/send-notification', methods=['POST'])
def send_notification_admin():
    data = request.get_json()
    title = data.get('title')
    message = data.get('message')
    target = data.get('target', {})
    
    # Prepara el mensaje para Telegram (negrita para el título)
    telegram_message = f"<b>{title}</b>\n\n{message}"
    
    conn = get_db_connection()
    sent_count = 0
    try:
        with conn.cursor() as cur:
            target_emails = []
            if target.get('mode') == 'all':
                cur.execute("SELECT email, telegram_chat_id FROM users WHERE telegram_chat_id IS NOT NULL")
            elif target.get('mode') == 'database':
                cur.execute("SELECT email, telegram_chat_id FROM users WHERE manager_id = %s AND telegram_chat_id IS NOT NULL", (target.get('value'),))
            elif target.get('mode') == 'users':
                user_emails = tuple(target.get('value', []))
                if not user_emails: return jsonify(success=True, message="No se seleccionaron usuarios.")
                cur.execute("SELECT email, telegram_chat_id FROM users WHERE email IN %s AND telegram_chat_id IS NOT NULL", (user_emails,))
            
            recipients = cur.fetchall()
            
            for user in recipients:
                if send_telegram_message(user['telegram_chat_id'], telegram_message):
                    sent_count += 1
            
            # Guardar en el historial
            cur.execute(
                "INSERT INTO admin_notifications (title, message, target_info, sent_by) VALUES (%s, %s, %s, %s)",
                (title, message, json.dumps(target), "admin")
            )
            conn.commit()
            
            # Notificar a usuarios online vía Socket.IO
            socketio.emit('new_notification', {'title': title, 'message': message, 'type': 'admin', 'timestamp': datetime.now(timezone.utc).isoformat()})
            
        return jsonify(success=True, message=f"Notificación enviada a {sent_count} usuarios de Telegram.", sent_count=sent_count)
    except Exception as e:
        conn.rollback()
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()

# --- Rutas para IA Boards (ia_boards.html) ---

@app.route('/admin/ai/assignment-data', methods=['GET'])
def get_assignment_data():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT manager_id FROM users WHERE manager_id IS NOT NULL")
            databases = [{"name": row['manager_id'], "filename": row['manager_id']} for row in cur.fetchall()]
            
            cur.execute("SELECT email, first_name, last_name FROM users")
            users = [dict(row) for row in cur.fetchall()]
            
        return jsonify(success=True, databases=databases, users=users)
    finally:
        conn.close()

@app.route('/admin/ai/list-saved-boards', methods=['GET'])
def list_saved_boards():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, created_at FROM ia_boards ORDER BY created_at DESC")
            boards = [dict(row) for row in cur.fetchall()]
        return jsonify(success=True, boards=boards)
    finally:
        conn.close()


@app.route('/admin/ai/generate-board-content', methods=['POST'])
def generate_board_content():
    """Genera solo la estructura del tablero (columnas y tarjetas)."""
    if not genai:
        return jsonify(success=False, message="La API de IA no está configurada."), 503

    data = request.get_json()
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify(success=False, message="La descripción del tablero es requerida."), 400

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        # --- PROMPT MEJORADO: Instrucciones más estrictas para la IA ---
        template_prompt = f"""
        Actúa como un Project Manager experto y genera un plan de proyecto basado en: "{user_prompt}"

        INSTRUCCIONES CRÍTICAS DE FORMATO (OBLIGATORIO):
        1.  Usa los marcadores (BOARD_NAME_START, etc.) EXACTAMENTE como se indica, sin texto adicional antes o después.
        2.  Genera entre 4 y 6 columnas.
        3.  Genera un total de 40 a 60 tarjetas, distribuidas lógicamente entre las columnas.
        4.  Cada tarjeta DEBE tener `COLUMN_TITLE::`, `CARD_TITLE::`, y `CARD_DESCRIPTION::`.
        5.  La descripción DEBE contener "Contexto:" y "Objetivos:", separados por DOS saltos de línea.
        6.  Cada tarjeta DEBE incluir un checklist precedido por `---CHECKLIST---`.
        7.  Tu respuesta debe contener ÚNICAMENTE el texto con este formato. No agregues introducciones, resúmenes ni la palabra 'json'.

        ESTRUCTURA DE TEXTO PLANO:
        BOARD_NAME_START
        Nombre del Tablero
        BOARD_NAME_END

        COLUMN_START
        Título de la Columna
        COLUMN_END

        CARD_START
        COLUMN_TITLE::Título de la Columna a la que pertenece
        CARD_TITLE::Título de la Tarjeta
        CARD_TAGS::Tag1, Tag2
        CARD_DESCRIPTION::
Contexto: Párrafo detallado sobre la tarea.


Objetivos: Párrafo detallado sobre el resultado esperado.
        ---CHECKLIST---
        CHECKLIST_ITEM::Acción detallada 1.
        CHECKLIST_ITEM::Acción detallada 2.
        CARD_END
        """
        response = model.generate_content(template_prompt)
        raw_text = response.text
        
        final_board = { "board_name": "", "columns": [], "cards": [] }
        def clean_text(text): return text.strip() if text else ''

        # --- PARSEO MEJORADO: Más flexible con espacios y saltos de línea ---
        board_name_match = re.search(r"BOARD_NAME_START\s*(.*?)\s*BOARD_NAME_END", raw_text, re.DOTALL)
        if board_name_match: final_board["board_name"] = clean_text(board_name_match.group(1))

        # Usamos \s* para permitir espacios o saltos de línea opcionales alrededor de los marcadores
        column_titles = re.findall(r"COLUMN_START\s*(.*?)\s*COLUMN_END", raw_text, re.DOTALL)
        column_map = {}
        for i, title in enumerate(column_titles):
            clean_title = clean_text(title)
            if clean_title and clean_title not in column_map:
                col_id = f"col-{i+1}-{uuid.uuid4().hex[:4]}"
                column_map[clean_title] = col_id
                final_board["columns"].append({"id": col_id, "title": clean_title, "color": "bg-blue-200"})
        
        card_blocks = re.findall(r"CARD_START\s*(.*?)\s*CARD_END", raw_text, re.DOTALL)
        for i, block in enumerate(card_blocks):
            try:
                # Usamos (?:\n|\Z) para que coincida con un salto de línea o el final del texto
                card_col_title_match = re.search(r"COLUMN_TITLE::(.*?)(?:\n|\Z)", block)
                if not card_col_title_match: continue
                
                card_col_title = clean_text(card_col_title_match.group(1))
                if card_col_title not in column_map:
                    col_id = f"col-auto-{uuid.uuid4().hex[:4]}"
                    column_map[card_col_title] = col_id
                    final_board["columns"].append({"id": col_id, "title": card_col_title, "color": "bg-purple-200"})
                
                card_title_match = re.search(r"CARD_TITLE::(.*?)(?:\n|\Z)", block)
                tags_match = re.search(r"CARD_TAGS::(.*?)(?:\n|\Z)", block)
                
                card = {
                    "id": str(uuid.uuid4()), "columnId": column_map[card_col_title],
                    "title": clean_text(card_title_match.group(1)) if card_title_match else f"Tarjeta Sin Título {i+1}",
                    "description": "", "checklist": [],
                    "tags": [{'text': t.strip()} for t in clean_text(tags_match.group(1)).split(',') if t.strip()] if tags_match else []
                }

                desc_start = block.find('CARD_DESCRIPTION::')
                if desc_start != -1:
                    desc_content = block[desc_start + len('CARD_DESCRIPTION::'):]
                    desc_part, checklist_part = (desc_content.split('---CHECKLIST---', 1) + [''])[:2]
                    
                    card['description'] = clean_text(desc_part)
                    if checklist_part:
                        checklist_items_raw = re.findall(r"CHECKLIST_ITEM::(.*?)(?:\n|\Z)", checklist_part)
                        card['checklist'] = [{'id': str(uuid.uuid4()), 'text': clean_text(item), 'completed': False} for item in checklist_items_raw]

                final_board["cards"].append(card)
            except Exception as e:
                print(f"Error procesando una tarjeta individual: {e}")
                continue
        
        # Añadir columna 'Completado' si no existe
        if not any(col['title'].lower().startswith('completado') for col in final_board['columns']):
            final_board["columns"].append({"id": "col-done", "title": "¡Completado! ✅", "color": "bg-green-200"})
            
        return jsonify(success=True, board=final_board)
    except Exception as e:
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500




@app.route('/admin/ai/regenerate-notes', methods=['POST'])
def regenerate_notes_ai():
    """Genera solo notas de apoyo basadas en el prompt del proyecto."""
    if not genai: return jsonify(success=False, message="IA no disponible."), 503
    
    data = request.get_json()
    prompt = data.get('prompt')
    if not prompt: return jsonify(success=False, message="El prompt es requerido."), 400

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        template_prompt = f"""
        Actúa como un asesor experto. Basado en el objetivo de proyecto "{prompt}", genera 5 notas de apoyo MUY útiles y detalladas.

        INSTRUCCIONES DE FORMATO (OBLIGATORIO):
        - Usa EXACTAMENTE el siguiente formato para cada nota.
        - No incluyas texto explicativo antes, entre o después de las notas.

        NOTE_START
        NOTE_TITLE::Título conciso de la Nota
        NOTE_CONTENT::Contenido detallado de la nota. Puede incluir varios párrafos.
        NOTE_END
        """
        response = model.generate_content(template_prompt)
        raw_text = response.text
        
        notes = []
        note_blocks = re.findall(r"NOTE_START\n(.*?)\nNOTE_END", raw_text, re.DOTALL)
        for block in note_blocks:
            title_match = re.search(r"NOTE_TITLE::(.*?)\n", block)
            content_match = re.search(r"NOTE_CONTENT::(.*?)(?=\Z)", block, re.DOTALL)
            if title_match and content_match:
                notes.append({"title": title_match.group(1).strip(), "content": content_match.group(1).strip()})
        
        return jsonify(success=True, notes=notes)
    except Exception as e:
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500

# La ruta /admin/ai/suggest-assistants que ya tienes es correcta, no necesitas cambiarla.
# Asegúrate de que exista y sea similar a esta:
@app.route('/admin/ai/suggest-assistants', methods=['POST'])
def suggest_assistants_ai():
    if not genai: return jsonify(success=False, message="IA no disponible."), 503
    
    data = request.get_json()
    prompt = data.get('prompt')
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        system_prompt = """
        Eres un experto en diseño de equipos y roles de IA. Basado en la descripción de un proyecto,
        genera 3 perfiles de asistentes de IA que serían útiles.
        Responde ÚNICAMENTE con un array JSON válido con la siguiente estructura:
        [
          {"profile": "Nombre del Perfil (ej. Analista de Datos IA)", "prompt": "Prompt detallado para el asistente (ej. Eres un analista...)", "knowledge_base": "Sugerencia de conocimiento (ej. Documentación de Python, KPIs de marketing)"},
          ...
        ]
        No incluyas texto explicativo antes o después del JSON.
        """
        response = model.generate_content([system_prompt, f"Proyecto: '{prompt}'"])
        # Limpieza robusta del JSON
        json_string = response.text.strip()
        match = re.search(r'\[.*\]', json_string, re.DOTALL)
        if match:
            json_string = match.group(0)
        else:
            # Si no encuentra un array, intenta limpiar de otra forma
            json_string = json_string.replace('```json', '').replace('```', '').strip()
            
        suggestions = json.loads(json_string)
        return jsonify(success=True, assistants=suggestions)
    except Exception as e:
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500



@app.route('/admin/ai/save-suggested-assistants', methods=['POST'])
def save_suggested_assistants():
    data = request.get_json()
    assistants = data.get('assistants', [])
    saved_count = 0
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            for assistant in assistants:
                assistant_id = f"asst_{os.urandom(8).hex()}"
                cur.execute("""
                    INSERT INTO assistants (id, name, description, avatar_url, prompt, knowledge_base, is_public)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,(
                    assistant_id, assistant.get('name'), assistant.get('description'),
                    assistant.get('avatar_url'), assistant.get('prompt'),
                    assistant.get('knowledge_base'), 0 # Por defecto no son públicos
                ))
                saved_count += 1
            conn.commit()
        socketio.emit('assistants_updated')
        return jsonify(success=True, message=f"{saved_count} asistentes guardados.", saved_count=saved_count)
    except Exception as e:
        conn.rollback()
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500
    finally:
        conn.close()


@app.route('/ai/writing-suggestions', methods=['POST'])
def get_ai_suggestions():
    if not genai:
        return jsonify(success=False, message="El servicio de IA no está configurado en el servidor."), 500

    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify(success=False, message="No se proporcionó texto."), 400

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        # --- PROMPT MEJORADO Y MÁS ESTRICTO ---
        prompt = f"""
        Eres un asistente de escritura experto. Reescribe el siguiente texto de 3 maneras diferentes, variando el tono (por ejemplo: uno más profesional, uno más conciso, uno más casual).
        IMPORTANTE: Tu única respuesta debe ser las 3 sugerencias de texto, separadas exactamente por el delimitador '|||'.
        No incluyas números, viñetas, comillas, la palabra JSON, introducciones, conclusiones ni explicaciones.

        Texto original: "{text}"
        """
        response = model.generate_content(prompt)
        
        # --- CÓDIGO DE PROCESAMIENTO CORREGIDO ---
        # Limpiamos y dividimos la respuesta usando el delimitador para crear una lista real
        clean_text = response.text.strip().replace('"', '')
        suggestions = [s.strip() for s in clean_text.split('|||')]
        
        return jsonify(success=True, suggestions=suggestions)
        
    except Exception as e:
        print(f"🚨 ERROR en /ai/writing-suggestions: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error al contactar la IA: {str(e)}"), 500


@app.route('/ai/enhance-text', methods=['POST'])
def enhance_text_with_ai():
    if not genai:
        return jsonify(success=False, message="El servicio de IA no está configurado en el servidor."), 500

    data = request.get_json()
    text = data.get('text', '')
    mode = data.get('mode', 'improve')

    if not text:
        return jsonify(success=False, message="No se proporcionó texto."), 400

    try:
        model = genai.GenerativeModel('gemini-2.5-flash') 
        
        # --- PROMPTS MEJORADOS Y MÁS RESTRICTIVOS ---
        prompts = {
            'improve': (
                "Reformula el siguiente texto para que sea más claro, conciso y profesional. "
                "Tu única respuesta debe ser el texto mejorado. No añadas introducciones, explicaciones ni markdown. "
                "Texto a reformular:\n\n"
                f"'{text}'"
            ),
            'fix': (
                "Tu única tarea es corregir la ortografía y puntuación (tildes, comas, puntos, mayúsculas) del siguiente texto. "
                "NO cambies ninguna palabra. NO reformules frases. NO alteres el significado. "
                "Actúa como un corrector de pruebas, no como un escritor. "
                "Devuelve exclusivamente el texto corregido, sin introducciones, explicaciones ni markdown. "
                "Texto a corregir:\n\n"
                f"'{text}'"
            )
        }
        
        prompt_text = prompts.get(mode, prompts['improve'])
        
        response = model.generate_content(prompt_text)
        
        enhanced_text = response.text.strip()
        if enhanced_text.startswith('"') and enhanced_text.endswith('"'):
            enhanced_text = enhanced_text[1:-1]
            
        return jsonify(success=True, enhancedText=enhanced_text)

    except Exception as e:
        print(f"🚨 ERROR en /ai/enhance-text: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error al contactar la IA: {str(e)}"), 500



@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
def handle_single_note(note_id):
    """Maneja la actualización y eliminación de una nota específica."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Primero, obtener el board_id de la nota para la validación
        cursor.execute("SELECT board_id FROM notes WHERE id = %s", (note_id,))
        note = cursor.fetchone()
        if not note:
            return jsonify(success=False, message="Nota no encontrada"), 404
        board_id = note['board_id']

        if request.method == 'PUT':
            data = request.get_json()
            # AÑADIR ESTA VERIFICACIÓN
            if not check_editor_permission(conn, board_id, data['email']):
                return jsonify(success=False, message="Permiso de editor requerido."), 403
            
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "UPDATE notes SET content = %s, color = %s, updated_date = %s WHERE id = %s RETURNING *",
                (data['content'], data['color'], now, note_id)
            )
            updated_note = dict(cursor.fetchone())
            conn.commit()
            socketio.emit('note_updated', {'board_id': updated_note['board_id'], 'note': updated_note}, room=str(updated_note['board_id']))
            return jsonify(success=True, note=updated_note)

        if request.method == 'DELETE':
            email = request.args.get('email')
            # AÑADIR ESTA VERIFICACIÓN
            if not check_editor_permission(conn, board_id, email):
                return jsonify(success=False, message="Permiso de editor requerido."), 403

            cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
            conn.commit()
            socketio.emit('note_deleted', {'board_id': board_id, 'note_id': note_id}, room=str(board_id))
            return jsonify(success=True, message="Nota eliminada")
            
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en /notes/{note_id}: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500
    finally:
        if conn: conn.close()


@app.route('/boards/<int:board_id>/cards/<card_id>', methods=['DELETE'])
def delete_card(board_id, card_id):
    """
    Elimina una tarjeta específica de un tablero y notifica a todos los colaboradores.
    """
    email = request.args.get('email')
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Verificar que el usuario tenga permisos para editar
        if not check_editor_permission(conn, board_id, email):
            return jsonify(success=False, message="Permiso de editor requerido."), 403

        # 2. Obtener los datos actuales del tablero
        cursor.execute("SELECT board_data FROM boards WHERE id = %s", (board_id,))
        board = cursor.fetchone()
        if not board or not board['board_data']:
            return jsonify(success=False, message="Tablero no encontrado."), 404

        board_data = board['board_data']
        
        # 3. Filtrar la tarjeta para eliminarla de la lista
        initial_card_count = len(board_data.get('cards', []))
        board_data['cards'] = [card for card in board_data.get('cards', []) if card.get('id') != card_id]
        
        # Si no se encontró la tarjeta, no es un error crítico, pero lo registramos
        if len(board_data.get('cards', [])) == initial_card_count:
             print(f"ADVERTENCIA: No se encontró la tarjeta {card_id} para eliminar en el tablero {board_id}.")

        # 4. Actualizar la base de datos con el nuevo estado del tablero
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "UPDATE boards SET board_data = %s, updated_date = %s WHERE id = %s",
            (json.dumps(board_data), now, board_id)
        )
        conn.commit()
        
        # 5. [LA CORRECCIÓN CLAVE] Notificar a todos los clientes en la sala del tablero
        #    que esta tarjeta específica debe ser eliminada.
        socketio.emit('card_deleted', {'board_id': board_id, 'card_id': card_id}, room=str(board_id))
        
        return jsonify(success=True, message="Tarjeta eliminada")
        
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en DELETE /boards/{board_id}/cards/{card_id}: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500
    finally:
        if conn: conn.close()

@app.route('/boards/<int:board_id>', methods=['DELETE'])
def delete_board(board_id):
    """Elimina un tablero. Solo el propietario puede hacerlo."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT owner_email FROM boards WHERE id = %s", (board_id,))
        board = cursor.fetchone()

        if not board:
            return jsonify(success=False, message="Tablero no encontrado."), 404
        
        if board['owner_email'] != email:
            return jsonify(success=False, message="Solo el propietario puede eliminar el tablero."), 403

        cursor.execute("DELETE FROM boards WHERE id = %s", (board_id,))
        conn.commit()
        
        return jsonify(success=True, message="Tablero eliminado")
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en DELETE /boards/{board_id}: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500
    finally:
        if conn: conn.close()



@socketio.on('columns_reordered')
def handle_columns_reordered(data):
    """ Retransmite el nuevo orden de las columnas a los demás en el tablero. """
    board_id = data.get('board_id')
    if board_id:
        # Reenvía el evento a todos en la sala, excepto al remitente original.
        emit('columns_reordered', data, room=str(board_id), include_self=False)
        print(f"SOCKET: Retransmitiendo 'columns_reordered' para el tablero {board_id}")

@socketio.on('column_created')
def handle_column_created(data):
    """ Retransmite la información de una nueva columna a los demás. """
    board_id = data.get('board_id')
    if board_id:
        emit('column_created', data, room=str(board_id), include_self=False)
        print(f"SOCKET: Retransmitiendo 'column_created' para el tablero {board_id}")

@socketio.on('column_deleted')
def handle_column_deleted(data):
    """ Retransmite el ID de una columna eliminada a los demás. """
    board_id = data.get('board_id')
    if board_id:
        emit('column_deleted', data, room=str(board_id), include_self=False)
        print(f"SOCKET: Retransmitiendo 'column_deleted' para el tablero {board_id}")


@socketio.on('column_updated')
def handle_column_updated(data):
    """ Retransmite los datos de una columna actualizada a los demás. """
    board_id = data.get('board_id')
    if board_id:
        emit('column_updated', data, room=str(board_id), include_self=False)
        print(f"SOCKET: Retransmitiendo 'column_updated' para el tablero {board_id}")


@app.route('/notifications/pending', methods=['GET'])
def get_pending_notifications():
    """Obtiene notificaciones no leídas para un usuario."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400
    
    # Esta es una función básica. A futuro puedes mejorarla para que
    # realmente consulte notificaciones desde la base de datos.
    # Por ahora, evita el error 404.
    return jsonify(success=True, notifications=[])





@app.route('/boards/<int:board_id>', methods=['GET'])
def get_single_board(board_id):
    """Obtiene los datos de un tablero específico, incluyendo nombres de colaboradores."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Verificar si el usuario tiene acceso al tablero
        cursor.execute("SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        if not cursor.fetchone():
            return jsonify(success=False, message="Acceso denegado a este tablero."), 403

        # --- INICIO DE LA CORRECCIÓN CLAVE ---
        # Se reemplaza la consulta simple con una que une las tablas para obtener
        # la información completa y consistente de los colaboradores.
        query = """
            SELECT
                b.*,
                (
                    SELECT JSON_AGG(json_build_object(
                        'user_email', c.user_email, 
                        'permission_level', c.permission_level,
                        'first_name', u.first_name,
                        'last_name', u.last_name
                    ))
                    FROM collaborators c
                    JOIN users u ON c.user_email = u.email
                    WHERE c.board_id = b.id
                ) as shared_with
            FROM boards b WHERE b.id = %s
        """
        cursor.execute(query, (board_id,))
        board_info = cursor.fetchone()
        # --- FIN DE LA CORRECCIÓN CLAVE ---

        if not board_info:
            return jsonify(success=False, message="Tablero no encontrado."), 404
        
        board_to_send = dict(board_info)
        
        # Formateo final para el frontend
        board_to_send['shared_with'] = board_to_send.get('shared_with') or []
        board_to_send['data'] = board_to_send.get('board_data') or {}
        if 'board_data' in board_to_send:
            del board_to_send['board_data']
        
        return jsonify(success=True, board=board_to_send)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()


@app.route('/boards/<int:board_id>', methods=['PUT'])
def update_board(board_id):
    """Actualiza los datos de un tablero y notifica en tiempo real a los colaboradores."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    board_data = data.get('boardData')
    
    if not email or board_data is None:
        return jsonify(success=False, message="Email y boardData son requeridos"), 400

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
        
        # --- INICIO DE LA CORRECCIÓN CLAVE ---
        # Después de guardar, enviamos una notificación a todos en la "sala" del tablero.
        # Incluimos el email de quien hizo el cambio para que el frontend pueda
        # ignorar la actualización si la hizo el mismo usuario, evitando parpadeos.
        socketio.emit('board_was_updated', {
            'board_id': board_id, 
            'boardData': board_data,
            'email': email
        }, room=str(board_id))
        # --- FIN DE LA CORRECCIÓN CLAVE ---
        
        return jsonify(success=True, message="Tablero actualizado")

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en PUT /boards/{board_id}: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error al guardar el tablero."), 500
    finally:
        if conn: conn.close()



@socketio.on('global_chat_delete_conversation')
def handle_delete_conversation(data):
    """Elimina permanentemente una conversación y todos sus mensajes."""
    conv_id = data.get('conv_id')
    user_email = data.get('user_email')
    if not all([conv_id, user_email]): return

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificamos que el usuario sea participante para seguridad
        cursor.execute(
            "SELECT 1 FROM conversations WHERE id = %s AND participants_json::jsonb ? %s",
            (conv_id, user_email)
        )
        if cursor.fetchone():
            # ON DELETE CASCADE se encargará de los mensajes en direct_messages
            cursor.execute("DELETE FROM conversations WHERE id = %s", (conv_id,))
            conn.commit()
            print(f"SOCKET: Usuario {user_email} eliminó la conversación {conv_id}")
            
            # Notifica al cliente que la eliminación fue exitosa para que refresque su lista
            emit('conversation_deleted', {'conv_id': conv_id})
            
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en 'global_chat_delete_conversation': {e}")
    finally:
        if conn: conn.close()


@socketio.on('global_chat_clear_conversation')
def handle_clear_conversation(data):
    """Elimina todos los mensajes de una conversación, pero la mantiene en la lista."""
    conv_id = data.get('conv_id')
    user_email = data.get('user_email')
    if not all([conv_id, user_email]): return

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verificamos que el usuario sea participante
        cursor.execute(
            "SELECT 1 FROM conversations WHERE id = %s AND participants_json::jsonb ? %s",
            (conv_id, user_email)
        )
        if cursor.fetchone():
            cursor.execute("DELETE FROM direct_messages WHERE conv_id = %s", (conv_id,))
            
            # Actualizamos el timestamp para que no aparezca con mensaje antiguo
            cursor.execute("UPDATE conversations SET last_ts = %s WHERE id = %s", (datetime.now(timezone.utc).isoformat(), conv_id))
            
            conn.commit()
            print(f"SOCKET: Usuario {user_email} vació la conversación {conv_id}")

            # Notifica al cliente para que actualice la vista
            emit('conversation_cleared', {'conv_id': conv_id})

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en 'global_chat_clear_conversation': {e}")
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
    
    # --- LÍNEA AÑADIDA ---
    print("🔄 Ejecutando migraciones de base de datos...")
    migrate_database()
    # ---------------------

except Exception as e:
    print(f"🚨 ERROR CRÍTICO DURANTE LA INICIALIZACIÓN: {e}")

if __name__ == '__main__':
    print("🚀 Iniciando servidor de desarrollo local...")
    socketio.run(app, host='0.0.0.0', port=8080)