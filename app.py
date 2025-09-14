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



@app.route('/boards/<int:board_id>/share', methods=['POST'])
def share_board(board_id):
    """Invita a un nuevo usuario a colaborar en un tablero."""
    data = request.get_json()
    sharer_email = data.get('sharer_email')
    recipient_email = data.get('recipient_email', '').lower().strip()
    permission_level = data.get('permission_level', 'viewer')

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
            return jsonify(success=False, message=f"El usuario '{recipient_email}' no fue encontrado."), 404

        cursor.execute("""
            INSERT INTO collaborators (board_id, user_email, permission_level)
            VALUES (%s, %s, %s)
            ON CONFLICT (board_id, user_email) DO UPDATE SET permission_level = EXCLUDED.permission_level
        """, (board_id, recipient_email, permission_level))
        
        conn.commit()
        
        # --- CORRECCIÓN CLAVE ---
        # Después de guardar, obtenemos y devolvemos toda la info actualizada del tablero.
        updated_board_info = find_board_and_owner_db(board_id)
        return jsonify(success=True, message="Tablero compartido.", board=updated_board_info)

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en POST /boards/{board_id}/share: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()

@app.route('/boards/<int:board_id>/collaborators/update', methods=['PUT'])
def update_collaborator_permission(board_id):
    """Actualiza el nivel de permiso de un colaborador."""
    data = request.get_json()
    owner_email = data.get('owner_email')
    collaborator_email = data.get('collaborator_email')
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
        
        # --- CORRECCIÓN CLAVE ---
        updated_board_info = find_board_and_owner_db(board_id)
        return jsonify(success=True, message="Permiso actualizado.", board=updated_board_info)

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en PUT .../collaborators/update: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500
    finally:
        if conn: conn.close()

@app.route('/boards/<int:board_id>/share', methods=['DELETE'])
def remove_collaborator(board_id):
    """Elimina a un colaborador de un tablero."""
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

        # --- CORRECCIÓN CLAVE ---
        updated_board_info = find_board_and_owner_db(board_id)
        return jsonify(success=True, message="Colaborador eliminado.", board=updated_board_info)

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en DELETE /boards/{board_id}/share: {e}")
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


@app.route('/boards', methods=['POST'])
def create_board():
    """Crea un nuevo tablero para un usuario, aceptando una plantilla de columnas opcional."""
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
        now = datetime.now(timezone.utc).isoformat()

        # --- INICIO DE LA CORRECCIÓN ---
        # Si el frontend envía una plantilla de columnas, la usamos.
        # Si no, usamos la plantilla por defecto.
        board_columns = template_columns if template_columns and isinstance(template_columns, list) else [
            {"id": "col-1", "title": "Por hacer", "color": "bg-red-200"},
            {"id": "col-2", "title": "En proceso", "color": "bg-yellow-200"},
            {"id": "col-3", "title": "Hecho", "color": "bg-green-200"}
        ]
        # Aseguramos que cada columna tenga un ID único
        for i, col in enumerate(board_columns):
            if 'id' not in col:
                col['id'] = f'col-{Date.now()}-{i}'
        # --- FIN DE LA CORRECCIÓN ---

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
        traceback.print_exc()
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
            cursor.execute("SELECT * FROM notes WHERE board_id = %s ORDER BY updated_date DESC", (board_id,))
            notes = [dict(row) for row in cursor.fetchall()]
            return jsonify(success=True, notes=notes)

        if request.method == 'POST':
            data = request.get_json()
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


@app.route('/ai/writing-suggestions', methods=['POST'])
def get_ai_suggestions():
    if not genai:
        return jsonify(success=False, message="El servicio de IA no está configurado en el servidor."), 500

    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify(success=False, message="No se proporcionó texto."), 400

    try:
        model = genai.GenerativeModel('gemini-2.0-flash')
        
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
        model = genai.GenerativeModel('gemini-2.0-flash') 
        
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

        if request.method == 'PUT':
            data = request.get_json()
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
            # Primero obtenemos el board_id para notificar a la sala correcta
            cursor.execute("SELECT board_id FROM notes WHERE id = %s", (note_id,))
            note = cursor.fetchone()
            if note:
                board_id = note['board_id']
                cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
                conn.commit()
                socketio.emit('note_deleted', {'board_id': board_id, 'note_id': note_id}, room=str(board_id))
                return jsonify(success=True, message="Nota eliminada")
            return jsonify(success=False, message="Nota no encontrada"), 404
            
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en /notes/{note_id}: {e}")
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
    """Obtiene los datos de un tablero específico y verifica permisos."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Verificar si el usuario es colaborador del tablero solicitado
        cursor.execute("SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        if not cursor.fetchone():
            conn.close()
            return jsonify(success=False, message="Acceso denegado a este tablero."), 403

        # 2. Si tiene permiso, obtener los datos completos del tablero
        cursor.execute("SELECT * FROM boards WHERE id = %s", (board_id,))
        board_info = cursor.fetchone()
        if not board_info:
            conn.close()
            return jsonify(success=False, message="Tablero no encontrado."), 404
        
        board_to_send = dict(board_info)
        
        # --- CORRECCIÓN CLAVE ---
        # PostgreSQL ya devuelve un diccionario, no necesitamos json.loads()
        board_to_send['data'] = board_to_send.get('board_data') or {}
        if 'board_data' in board_to_send:
            del board_to_send['board_data']
        # --- FIN DE LA CORRECCIÓN ---

        # 3. Obtener la lista de todos los colaboradores de ese tablero
        cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id,))
        board_to_send['shared_with'] = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        return jsonify(success=True, board=board_to_send)
        
    except Exception as e:
        print(f"🚨 ERROR en GET /boards/{board_id}: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al obtener el tablero."), 500
        
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