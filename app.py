# ############################################################################
# # SECCIÓN 1: IMPORTACIONES Y CONFIGURACIÓN INICIAL                          #
# ############################################################################



import os
import json
import threading
import time
import html
import uuid
import traceback
import shutil 
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from urllib.parse import quote
import requests
import fitz  # PyMuPDF
import io
from dotenv import load_dotenv
# Importaciones de Flask y extensiones

from flask import Flask, request, jsonify, render_template_string, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, emit
import cloudinary
import cloudinary.uploader
import cloudinary.utils
import re
import random
import psycopg2
import psycopg2.extras


# Importaciones de IA (si se usan)
try:
    import google.generativeai as genai
except ImportError:
    genai = None

# ############################################################################
# # SECCIÓN 2: CONFIGURACIÓN DE LA APLICACIÓN Y LA BASE DE DATOS             #
# ############################################################################

# Configuración de la aplicación Flask
app = Flask(__name__)


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

CORS(app, origins=[
    'https://focux.netlify.app',
    'https://focuxadmin.netlify.app',
    'https://focux-app.onrender.com', # <-- AÑADE ESTA LÍNEA
    'http://localhost:3000', 
    '*'
])


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")






socketio = SocketIO(app, cors_allowed_origins="*")

# --- INICIO DE CORRECCIÓN: Silenciar logs de requests HTTP ---
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
# --- FIN DE CORRECCIÓN ---

DATABASE_FILE = "focux_data.db"
db_lock = threading.Lock()

PEXELS_API_KEY = os.getenv("PEXELS_API_KEY")
DEFAULT_AVATAR_URL = "https://i.ibb.co/ZR8zNXGn/imagen-2025-08-17-163425695.png" # <-- AÑADE ESTA LÍNEA
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if genai and GEMINI_API_KEY and GEMINI_API_KEY != "TU_API_KEY_AQUÍ":
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"🚨 ERROR al configurar la API de Gemini: {e}")
        genai = None 
else:
    genai = None

active_sids_by_room = defaultdict(set)
sid_to_room_map = {}
sid_to_user_map = {}
user_to_sids = defaultdict(set)
meeting_rooms = {}


# ############################################################################
# # SECCIÓN 3: MANEJO DE LA BASE DE DATOS (CONEXIÓN Y ESQUEMA)               #
# ############################################################################

def get_db_connection():
    """Conecta a la base de datos PostgreSQL en la nube."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        # cursor_factory hace que los resultados se devuelvan como diccionarios
        conn.cursor_factory = psycopg2.extras.DictCursor
        return conn
    except psycopg2.OperationalError as e:
        print(f"🚨 ERROR CRÍTICO: No se pudo conectar a la base de datos PostgreSQL: {e}")
        raise

# ############################################################################
# # SECCIÓN 4: MIDDLEWARE Y RUTAS DE UTILIDAD (HEALTH, OPTIONS)              #
# ############################################################################



# --- INICIO DE LA CORRECCIÓN: Middleware para CORS y Private Network Access ---
@app.after_request
def after_request_func(response):
    """
    Añade las cabeceras CORS necesarias después de cada petición,
    incluyendo la cabecera 'Access-Control-Allow-Private-Network' para
    solucionar el error de acceso a red privada desde sitios públicos (Netlify/Ngrok).
    """
    origin = request.headers.get('Origin')
    allowed_origins = [
        'https://focux.netlify.app',
        'https://b10s9f1sip9b.share.zrok.io',
        'https://unique-tapioca-0f3c64.netlify.app',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5500'
    ]
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,ngrok-skip-browser-warning')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,PATCH,OPTIONS')
    
    # Esta es la cabecera clave que soluciona el error
    response.headers.add('Access-Control-Allow-Private-Network', 'true')
    
    return response
# --- FIN DE LA CORRECCIÓN ---




# --- CONFIGURACIÓN DE CLOUDINARY ---
# Reemplaza los valores con tus credenciales.
cloudinary.config( 
  cloud_name = "dcmqx8kl3", 
  api_key = "658816486722381", 
  api_secret = "v2EB2bcJ_JsB0BV0FYOMK5eLptM" # <-- PEGA TU API SECRET AQUÍ
)

# --- BASE DE DATOS EN MEMORIA (PARA SIMPLICIDAD) ---
# En una aplicación real, esto estaría en una base de datos como PostgreSQL o MongoDB.
db_documents = {}
doc_id_counter = 1

def generate_thumbnail_link(file_id):
    """Genera un enlace público temporal a la miniatura del archivo."""
    try:
        file_metadata = drive_service.files().get(
            fileId=file_id, fields='thumbnailLink').execute()
        return file_metadata.get('thumbnailLink')
    except Exception as e:
        print(f"Error generando thumbnail: {e}")
        return DEFAULT_BLANK_COVER

@app.route('/documents', methods=['POST'])
def upload_document():
    if 'pdf_file' not in request.files:
        return jsonify(success=False, message="No se encontró el archivo PDF"), 400

    file_to_upload = request.files['pdf_file']
    title = request.form.get('title', 'Sin Título')
    version = request.form.get('version', '1.0')
    user_email = request.form.get('email')
    board_id = request.form.get('board_id')
    
    # --- INICIO DE LA CORRECCIÓN ---
    password = request.form.get('password')
    thumbnail_url = request.form.get('thumbnail_url')
    # --- FIN DE LA CORRECCIÓN ---

    if not all([user_email, board_id]):
        return jsonify(success=False, message="Email del usuario y ID del tablero son requeridos"), 400

    try:
        # 1. Subir el archivo a Cloudinary
        print(f"Subiendo '{title}' a Cloudinary...")
        upload_result = cloudinary.uploader.upload(
            file_to_upload,
            resource_type="raw",
            public_id=f"focux_documents/{title}_{uuid.uuid4().hex[:8]}",
            format="pdf"
        )
        
        cloudinary_url = upload_result.get('secure_url')
        cloudinary_public_id = upload_result.get('public_id')
        
        if not cloudinary_url or not cloudinary_public_id:
            raise Exception("La subida a Cloudinary no devolvió una URL o un public_id.")

        print(f"Subida exitosa. URL: {cloudinary_url}, Public ID: {cloudinary_public_id}")

        # 2. Guardar la información en la base de datos
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            # --- INICIO DE LA CORRECCIÓN ---
            # Si no se provee una portada, se usa la de por defecto.
            final_thumbnail = thumbnail_url or 'https://i.ibb.co/kVPCQPZf/imagen-2025-08-19-012405491.png'
            page_count = 0 

            # Se actualiza la consulta INSERT para guardar la contraseña y la portada.
            cursor.execute("""
                INSERT INTO documents (board_id, user_email, title, version, google_drive_file_id, cloudinary_public_id, thumbnail_url, password, page_count, created_date, updated_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (board_id, user_email, title, version, cloudinary_url, cloudinary_public_id, final_thumbnail, password if password else None, page_count, now, now))
            # --- FIN DE LA CORRECCIÓN ---
            
            # Nueva forma de insertar y obtener el ID
            cursor.execute("""
                INSERT INTO documents (board_id, user_email, title, ...)
                VALUES (%s, %s, %s, ...)
                RETURNING id; 
            """, (board_id, user_email, title, ...))
            doc_db_id = cursor.fetchone()['id']
            
            conn.commit()
            
            cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_db_id,))
            new_doc_from_db = dict(cursor.fetchone())
            conn.close()

        return jsonify(success=True, document=new_doc_from_db)

    except Exception as e:
        print(f"🚨 ERROR en /documents POST (Cloudinary): {e}")
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500






@app.route('/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 1. Obtener el ID de Google Drive antes de borrar
            cursor.execute("SELECT google_drive_file_id FROM documents WHERE id = %s", (doc_id,))
            doc_row = cursor.fetchone()
            
            if not doc_row:
                conn.close()
                return jsonify(success=False, message="Documento no encontrado en la base de datos"), 404
            
            google_drive_file_id = doc_row['google_drive_file_id']
            
            # 2. Eliminar de la base de datos SQLite
            cursor.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
            conn.commit()
            conn.close()

        # 3. Eliminar de Google Drive (fuera del bloqueo de la BD)
        if google_drive_file_id:
            try:
                drive_service.files().delete(fileId=google_drive_file_id).execute()
            except Exception as drive_error:
                # Si falla en Drive, no es crítico, ya se borró de la UI. Se registra el error.
                print(f"🔔 AVISO: No se pudo eliminar el archivo de Drive {google_drive_file_id}. Error: {drive_error}")
        
        return jsonify(success=True, message="Documento eliminado correctamente")
        
    except Exception as e:
        print(f"🚨 ERROR en /documents DELETE: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al eliminar."), 500

@app.route('/documents/<int:doc_id>/cover', methods=['PATCH'])
def update_cover(doc_id):
    data = request.get_json()
    new_url = data.get('url', DEFAULT_BLANK_COVER)
    
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("UPDATE documents SET thumbnail_url = %s WHERE id = %s", (new_url, doc_id))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Documento no encontrado"), 404

            conn.commit()
            
            cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
            updated_doc = dict(cursor.fetchone())
            conn.close()
            
        return jsonify(success=True, document=updated_doc)
    except Exception as e:
        print(f"🚨 ERROR en /documents PATCH: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al actualizar."), 500



@app.route('/admin/focux-view-data', methods=['GET'])
def get_focux_view_data():
    """
    Recopila y devuelve todos los tableros, tarjetas y notas
    asociados a un email de usuario específico a través de todas las bases de datos.
    """
    user_email = request.args.get('email', '').lower().strip()
    if not user_email:
        return jsonify(success=False, message="El email del usuario es requerido."), 400

    try:
        # 1. Obtener la lista de todas las bases de datos existentes
        init_master_db()
        master_conn = psycopg2.connect(MASTER_DB)
        master_conn.row_factory = psycopg2.Row
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases")
        db_names = [row['name'] for row in master_cursor.fetchall()] + ['Principal']
        master_conn.close()

        user_boards = []

        # 2. Iterar sobre cada base de datos para encontrar los tableros del usuario
        for db_name in set(db_names):
            conn = get_db_connection_for_manager(db_name)
            if not conn:
                continue

            cursor = conn.cursor()
            
            # Buscar todos los tableros donde el usuario es colaborador en esta DB
            cursor.execute("""
                SELECT b.id, b.owner_email, b.name, b.board_data, b.created_date, b.updated_date, b.category
                FROM boards b
                JOIN collaborators c ON b.id = c.board_id
                WHERE c.user_email = %s
            """, (user_email,))
            
            boards_in_db = [dict(row) for row in cursor.fetchall()]
            
            for board in boards_in_db:
                board_data = {}
                try:
                    board_data = json.loads(board['board_data'])
                except:
                    pass

                # Extraer notas del usuario para este tablero
                cursor.execute("SELECT * FROM notes WHERE board_id = %s AND user_email = %s", (board['id'], user_email))
                notes_for_board = [dict(row) for row in cursor.fetchall()]

                user_boards.append({
                    "id": board['id'],
                    "name": board['name'],
                    "category": board['category'],
                    "created_date": board['created_date'],
                    "updated_date": board['updated_date'],
                    "source_db": db_name,
                    "data": {
                        "cards": board_data.get('cards', [])
                    },
                    "notes": notes_for_board # Añadir las notas al tablero correspondiente
                })

            conn.close()

        return jsonify(success=True, boards=user_boards)

    except Exception as e:
        print(f"🚨 ERROR en /admin/focux-view-data: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al recopilar datos."), 500


@app.route('/', methods=['GET'])
def serve_index():
    """Sirve la página de login principal desde la carpeta de plantillas."""
    return render_template('Index.html')

@app.route('/Tablero.html', methods=['GET'])
def serve_tablero():
    """Sirve la página del tablero principal."""
    return render_template('Tablero.html')



@app.route('/health', methods=['GET'])
def health_check():
    return jsonify(success=True, message="Servidor Focux SQL funcionando correctamente", timestamp=datetime.now().isoformat())


# --- SECCIÓN DE ADMINISTRACIÓN ---

# --- Sub-sección: Funciones Auxiliares para Gestión de Múltiples Bases de Datos ---

DB_FOLDER = "databases"
MASTER_DB = os.path.join(DB_FOLDER, "master_control.db")


@app.route('/admin/dashboard', methods=['GET'])
def get_dashboard_stats():
    """
    Recopila y devuelve estadísticas agregadas de TODAS las bases de datos FÍSICAMENTE EXISTENTES.
    """
    try:
        # --- INICIO DE CORRECCIÓN: LÓGICA PARA LEER ÚNICAMENTE BASES DE DATOS VÁLIDAS ---
        
        # 1. Obtener la lista de todas las bases de datos registradas en la DB maestra
        init_master_db()
        master_conn = psycopg2.connect(MASTER_DB)
        master_conn.row_factory = psycopg2.Row
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases")
        # Se añade la base de datos 'Principal' a la lista para ser procesada
        db_names = [row['name'] for row in master_cursor.fetchall()] + ['Principal']
        master_conn.close()

        all_users = []
        all_boards = []

        # 2. Iterar sobre cada nombre de base de datos para extraer sus datos
        for db_name in set(db_names): # Usar set para evitar duplicados
            conn = get_db_connection_for_manager(db_name)
            # ¡VERIFICACIÓN CLAVE! Si la conexión es None (porque el archivo .db no existe), la saltamos.
            if not conn:
                print(f"🔔 Aviso: La base de datos '{db_name}' está registrada pero no se encontró el archivo. Omitiendo.")
                continue

            cursor = conn.cursor()
            
            # Extraer usuarios de esta base de datos
            cursor.execute("SELECT first_name, last_name, email, registration_date, manager_id, access_expires_on, last_login, (SELECT COUNT(b.id) FROM boards b WHERE b.owner_email = u.email) as boards_count FROM users u")
            users_in_db = [dict(row) for row in cursor.fetchall()]
            all_users.extend(users_in_db)
            
            # Extraer tableros de esta base de datos
            cursor.execute("SELECT id, name, owner_email, created_date, updated_date, board_data FROM boards")
            boards_in_db = [dict(row) for row in cursor.fetchall()]
            all_boards.extend(boards_in_db)
            
            conn.close()

        # 3. Procesar los datos agregados de todas las bases de datos válidas
        summary = {
            "total_users": len(all_users),
            "active_users": len([u for u in all_users if u['last_login'] and (datetime.now(timezone.utc) - datetime.fromisoformat(u['last_login'])).days <= 30]),
            "total_boards": len(all_boards)
        }
        
        quick_stats = {"active_sessions": len(set(sid_to_user_map.values()))}

        # Procesar actividad de usuario
        user_activity, now, online_emails = [], datetime.now(timezone.utc), set(sid_to_user_map.values())
        for user in all_users:
            user_dict = dict(user)
            user_dict['name'] = f"{user['first_name']} {user['last_name']}".strip()
            user_dict['source_db'] = user['manager_id']
            days_since_login, status = 'Nunca', 'inactive'
            if user['last_login']:
                days_since_login = (now - datetime.fromisoformat(user['last_login'])).days
                if user['email'] in online_emails: status = 'online'
                elif days_since_login <= 30: status = 'active'
            user_dict['days_since_login'], user_dict['status'] = days_since_login, status
            user_activity.append(user_dict)
        
        user_activity.sort(key=lambda x: x.get('last_login') or '1970-01-01', reverse=True)

        # Procesar tableros recientes
        all_boards.sort(key=lambda x: x.get('created_date') or '1970-01-01', reverse=True)
        recent_boards = []
        for board in all_boards[:10]:
            board_dict = dict(board)
            try: board_dict['cards_count'] = len(json.loads(board['board_data']).get('cards', []))
            except: board_dict['cards_count'] = 0
            del board_dict['board_data']
            board_dict['owner'] = board_dict['owner_email']
            recent_boards.append(board_dict)

        # Preparar datos detallados
        detailed_users = user_activity
        detailed_boards = []
        for board in all_boards:
            board_dict = dict(board)
            try: board_dict['cards_count'] = len(json.loads(board_dict['board_data']).get('cards', []))
            except: board_dict['cards_count'] = 0
            # Simular shared_count 
            board_dict['shared_count'] = 0 
            del board_dict['board_data']
            detailed_boards.append(board_dict)

        stats = {
            "summary": summary, "quick_stats": quick_stats, "user_activity": user_activity,
            "recent_boards": recent_boards, "detailed_users": detailed_users, "detailed_boards": detailed_boards
        }
        return jsonify(success=True, stats=stats)
        # --- FIN DE CORRECCIÓN ---
    except Exception as e:
        print(f"🚨 ERROR en /admin/dashboard: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al generar estadísticas."), 500

@app.route('/admin/focux_messages', methods=['GET'])
def get_focux_messages_admin():
    """Obtiene todos los mensajes de Focux para el panel de admin."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM focux_messages ORDER BY is_active DESC, title ASC")
        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, messages=messages)
    except Exception as e:
        print(f"🚨 ERROR en GET /admin/focux_messages: {e}")
        return jsonify(success=False, message="Error al obtener mensajes."), 500



@app.route('/admin/focux_messages/create', methods=['POST'])
def create_focux_message():
    """Crea un único mensaje nuevo de Focux."""
    msg_data = request.get_json()
    new_id = str(uuid.uuid4())
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO focux_messages 
            (id, title, content, color, image_url, button_text, button_url, is_active, start_date, end_date, target_info)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            new_id, msg_data.get('title'), msg_data.get('content'), msg_data.get('color'), msg_data.get('image_url'),
            msg_data.get('button_text'), msg_data.get('button_url'), 1 if msg_data.get('is_active') else 0,
            msg_data.get('start_date') if msg_data.get('start_date') else None,
            msg_data.get('end_date') if msg_data.get('end_date') else None,
            msg_data.get('target_info')
        ))
        conn.commit()
        conn.close()
        return jsonify(success=True, message="Mensaje creado.", new_id=new_id)
    except Exception as e:
        print(f"🚨 ERROR en POST /admin/focux_messages/create: {e}")
        return jsonify(success=False, message="Error interno al crear el mensaje."), 500





@app.route('/admin/focux_messages/update/<message_id>', methods=['PUT'])
def update_focux_message(message_id):
    """Actualiza un único mensaje de Focux existente."""
    msg_data = request.get_json()
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE focux_messages SET
                title=%s, content=%s, color=%s, image_url=%s, button_text=%s, button_url=%s, 
                is_active=%s, start_date=%s, end_date=%s, target_info=%s
                WHERE id=%s
            """, (
                msg_data.get('title'), msg_data.get('content'), msg_data.get('color'), msg_data.get('image_url'),
                msg_data.get('button_text'), msg_data.get('button_url'), 1 if msg_data.get('is_active') else 0,
                msg_data.get('start_date') if msg_data.get('start_date') else None,
                msg_data.get('end_date') if msg_data.get('end_date') else None,
                msg_data.get('target_info'), message_id
            ))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Mensaje no encontrado para actualizar."), 404
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Mensaje actualizado.")
    except Exception as e:
        print(f"🚨 ERROR en PUT /admin/focux_messages/update/{message_id}: {e}")
        return jsonify(success=False, message="Error interno al actualizar el mensaje."), 500

@app.route('/admin/focux_messages/<message_id>', methods=['DELETE'])
def delete_focux_message(message_id):
    """Elimina un mensaje de Focux específico."""
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM focux_messages WHERE id = %s", (message_id,))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Mensaje no encontrado."), 404
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Mensaje eliminado.")
    except Exception as e:
        print(f"🚨 ERROR en DELETE /admin/focux_messages/{message_id}: {e}")
        return jsonify(success=False, message="Error interno al eliminar el mensaje."), 500

@app.route('/admin/focux_messages', methods=['POST'])
def save_focux_messages():
    """
    Guarda el estado completo de la lista de mensajes de Focux.
    Este método es atómico: borra todos los mensajes existentes e inserta la nueva lista.
    """
    messages_data = request.get_json()
    if not isinstance(messages_data, list):
        return jsonify(success=False, message="Se esperaba una lista de mensajes"), 400

    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()

            # 1. Borrar todos los mensajes existentes para empezar desde cero.
            cursor.execute("DELETE FROM focux_messages")

            # 2. Iterar sobre la nueva lista y insertar cada mensaje.
            for msg in messages_data:
                # Generar un nuevo ID único para cada mensaje para evitar conflictos.
                new_id = str(uuid.uuid4())
                
                cursor.execute("""
                    INSERT INTO focux_messages 
                    (id, title, content, color, image_url, button_text, button_url, is_active, start_date, end_date, target_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    new_id,
                    msg.get('title'), msg.get('content'), msg.get('color'), msg.get('image_url'),
                    msg.get('button_text'), msg.get('button_url'), 1 if msg.get('is_active') else 0,
                    msg.get('start_date') if msg.get('start_date') else None,
                    msg.get('end_date') if msg.get('end_date') else None,
                    msg.get('target_info')
                ))
            
            conn.commit()
            conn.close()

        return jsonify(success=True, message="Mensajes guardados y sincronizados correctamente.")
        
    except Exception as e:
        print(f"🚨 ERROR en POST /admin/focux_messages: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno al guardar mensajes."), 500



@app.route('/focux_messages', methods=['GET'])
def get_active_focux_messages():
    """
    Obtiene los mensajes de Focux activos y relevantes para el usuario que hace la petición.
    """
    user_email = request.args.get('email', '').lower().strip()
    manager_id = request.args.get('manager_id', '').strip()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Obtener todos los mensajes activos y dentro del rango de fechas
        now_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        cursor.execute("""
            SELECT * FROM focux_messages 
            WHERE is_active = 1 
            AND (start_date IS NULL OR start_date <= %s)
            AND (end_date IS NULL OR end_date >= %s)
        """, (now_date, now_date))




        
        potential_messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        # Filtrar por destinatario en el lado del servidor
        visible_messages = []
        for msg in potential_messages:
            is_visible = False
            try:
                target = json.loads(msg['target_info'] or '{}')
                mode = target.get('mode', 'all')
                values = target.get('values', [])
                
                if mode == 'all':
                    is_visible = True
                elif mode == 'databases' and manager_id in values:
                    is_visible = True
                elif mode == 'users' and user_email in values:
                    is_visible = True
            except:
                is_visible = True # Si el JSON es inválido, mostrar por defecto

            if is_visible:
                visible_messages.append(msg)

        return jsonify(success=True, messages=visible_messages)
    except Exception as e:
        print(f"🚨 ERROR en GET /focux_messages: {e}")
        return jsonify(success=False, messages=[])


# ============================================================================
# INICIO: Bloque MEJORADO para Recordatorios de Telegram
# ============================================================================



def schedule_telegram_reminder(user_email, card_data):
    """Guarda un recordatorio detallado en la base de datos para ser enviado 10 minutos antes."""
    try:
        start_date = card_data.get('startDate') 
        start_time = card_data.get('start_time')
        
        if not start_date or not start_time:
            print(f"🔔 No se programó recordatorio para '{card_data.get('card_title')}' porque no tiene fecha/hora de inicio.")
            return False, "No se proporcionó fecha/hora de inicio."

        event_time_str = f"{start_date}T{start_time}"
        event_time = datetime.fromisoformat(event_time_str)
        notification_time = event_time - timedelta(minutes=10)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT chat_id FROM telegram_connections WHERE user_email = %s AND is_active = 1",
            (user_email,)
        )
        connection = cursor.fetchone()
        
        if not connection:
            conn.close()
            return False, "Usuario no conectado a Telegram."

        chat_id = connection['chat_id']
        
        with db_lock:
            cursor.execute("""
                INSERT INTO scheduled_reminders 
                (user_email, telegram_chat_id, notification_time, card_title, board_name, card_column, card_description, card_tags, sent)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_email, chat_id, notification_time.isoformat(),
                card_data.get('card_title'), card_data.get('board_name'),
                card_data.get('card_column'), card_data.get('card_description'),
                card_data.get('card_tags'), 0
            ))
            conn.commit()
        
        conn.close()
        return True, "Recordatorio programado."
        
    except Exception as e:
        print(f"🚨 ERROR al programar recordatorio detallado: {e}")
        traceback.print_exc()
        return False, str(e)

@app.route('/schedule-reminder', methods=['POST'])
def schedule_reminder_endpoint():
    """Endpoint para que el frontend solicite un recordatorio."""
    data = request.get_json()
    user_email = data.get('user_email')
    card_data = data.get('card_data')

    if not user_email or not card_data:
        return jsonify(success=False, message="Faltan datos para programar el recordatorio."), 400

    success, message = schedule_telegram_reminder(user_email, card_data)
    
    if success:
        return jsonify(success=True, message=message)
    else:
        return jsonify(success=False, message=message), 500

def check_and_send_reminders():
    """Función que se ejecuta en segundo plano para enviar recordatorios detallados."""
    while True:
        try:
            now_utc = datetime.now(timezone.utc)
            
            with db_lock:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM scheduled_reminders WHERE notification_time <= %s AND sent = 0",
                    (now_utc.isoformat(),)
                )
                reminders_to_send = [dict(row) for row in cursor.fetchall()]
            
            if reminders_to_send:
                print(f"📬 Encontrados {len(reminders_to_send)} recordatorios para enviar...")

            for reminder in reminders_to_send:
                try:
                    # Construir el mensaje detallado
                    start_time_obj = datetime.fromisoformat(reminder['notification_time']) + timedelta(minutes=10)
                    message = (
                        f"🔔 <b>Recordatorio Focux (inicia en 10 min)</b>\n\n"
                        f"📌 <b>Tarea:</b> {html.escape(reminder['card_title'])}\n"
                        f"🗓️ <b>Inicia:</b> {start_time_obj.strftime('%H:%M')}\n\n"
                        f"🗂️ <b>Tablero:</b> {html.escape(reminder.get('board_name', 'N/A'))}\n"
                        f"📊 <b>Columna:</b> {html.escape(reminder.get('card_column', 'N/A'))}\n\n"
                    )
                    
                    description = reminder.get('card_description')
                    if description and description.strip():
                        # Acortar descripción si es muy larga
                        short_desc = (description[:150] + '...') if len(description) > 150 else description
                        message += f"📝 <i>{html.escape(short_desc)}</i>\n\n"

                    tags = reminder.get('card_tags')
                    if tags and tags.strip():
                        message += f"🏷️ <b>Etiquetas:</b> {html.escape(tags)}"

                    # Enviar el mensaje
                    result = send_telegram_message(reminder['telegram_chat_id'], message.strip())
                    
                    if result.get('success'):
                        print(f"✅ Notificación detallada enviada a {reminder['user_email']} para '{reminder['card_title']}'")
                        with db_lock:
                            cursor.execute("UPDATE scheduled_reminders SET sent = 1 WHERE id = %s", (reminder['id'],))
                            conn.commit()
                    else:
                        print(f"❌ Fallo al enviar notificación para '{reminder['card_title']}': {result.get('error')}")
                
                except Exception as send_error:
                    print(f"🚨 Error crítico al procesar el envío del recordatorio ID {reminder['id']}: {send_error}")

            if 'conn' in locals() and conn:
                conn.close()

        except Exception as e:
            print(f"🚨 ERROR en el ciclo de revisión de recordatorios: {e}")
            traceback.print_exc()
        
        time.sleep(60)

# Iniciar el hilo del revisor de recordatorios
reminder_thread = threading.Thread(target=check_and_send_reminders, daemon=True)
if not reminder_thread.is_alive():
    reminder_thread.start()


@app.route('/admin/focux-view/delete-board', methods=['DELETE'])
def focux_view_delete_board():
    """Elimina un tablero específico desde Focux View."""
    data = request.get_json()
    board_id, source_db = data.get('boardId'), data.get('sourceDb')
    if not all([board_id, source_db]):
        return jsonify(success=False, message="ID del tablero y base de datos son requeridos."), 400
    
    conn = get_db_connection_for_manager(source_db)
    if not conn:
        return jsonify(success=False, message=f"No se pudo conectar a la base de datos '{source_db}'."), 404
        
    try:
        with db_lock:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("DELETE FROM boards WHERE id = %s", (board_id,))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Tablero no encontrado en la base de datos especificada."), 404
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Tablero y todos sus datos asociados han sido eliminados.")
    except Exception as e:
        if conn: conn.close()
        print(f"🚨 ERROR en /delete-board: {e}")
        return jsonify(success=False, message="Error interno del servidor al eliminar el tablero."), 500

@app.route('/admin/focux-view/delete-card', methods=['DELETE'])
def focux_view_delete_card():
    """Elimina una tarjeta específica de un tablero desde Focux View."""
    data = request.get_json()
    card_id, board_id, source_db = data.get('cardId'), data.get('boardId'), data.get('sourceDb')
    if not all([card_id, board_id, source_db]):
        return jsonify(success=False, message="ID de tarjeta, ID de tablero y base de datos son requeridos."), 400

    conn = get_db_connection_for_manager(source_db)
    if not conn:
        return jsonify(success=False, message=f"No se pudo conectar a la base de datos '{source_db}'."), 404
        
    try:
        with db_lock:
            cursor = conn.cursor()
            cursor.execute("SELECT board_data FROM boards WHERE id = %s", (board_id,))
            board_row = cursor.fetchone()
            if not board_row:
                conn.close()
                return jsonify(success=False, message="El tablero contenedor no fue encontrado."), 404
            
            board_data = json.loads(board_row['board_data'])
            initial_card_count = len(board_data.get('cards', []))
            board_data['cards'] = [card for card in board_data.get('cards', []) if card.get('id') != card_id]
            
            if len(board_data['cards']) == initial_card_count:
                conn.close()
                return jsonify(success=False, message="Tarjeta no encontrada dentro del tablero."), 404

            cursor.execute("UPDATE boards SET board_data = %s WHERE id = %s", (json.dumps(board_data), board_id))
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Tarjeta eliminada exitosamente.")
    except Exception as e:
        if conn: conn.close()
        print(f"🚨 ERROR en /delete-card: {e}")
        return jsonify(success=False, message="Error interno del servidor al eliminar la tarjeta."), 500

@app.route('/admin/focux-view/delete-note', methods=['DELETE'])
def focux_view_delete_note():
    """Elimina una nota específica desde Focux View."""
    data = request.get_json()
    note_id, source_db = data.get('noteId'), data.get('sourceDb')
    if not all([note_id, source_db]):
        return jsonify(success=False, message="ID de la nota y base de datos son requeridos."), 400

    conn = get_db_connection_for_manager(source_db)
    if not conn:
        return jsonify(success=False, message=f"No se pudo conectar a la base de datos '{source_db}'."), 404
    
    try:
        with db_lock:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Nota no encontrada en la base de datos especificada."), 404
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Nota eliminada exitosamente.")
    except Exception as e:
        if conn: conn.close()
        print(f"🚨 ERROR en /delete-note: {e}")
        return jsonify(success=False, message="Error interno del servidor al eliminar la nota."), 500


@app.route('/admin/databases/details', methods=['GET'])
def get_all_databases_details():
    """Obtiene una lista de todas las bases de datos con sus detalles (tamaño, modificación y fondo)."""
    try:
        init_master_db()
        conn = psycopg2.connect(MASTER_DB)
        conn.row_factory = psycopg2.Row
        cursor = conn.cursor()
        
        # --- INICIO DE LA MODIFICACIÓN ---
        cursor.execute("""
            SELECT m.name, s.background_url, s.logo_url
            FROM managed_databases m
            LEFT JOIN database_settings s ON m.name = s.name
            ORDER BY m.name ASC
        """)
        # --- FIN DE LA MODIFICACIÓN ---
        db_rows = cursor.fetchall()

        conn.close()
        databases_details = []

        for row in db_rows:
            db_name = row['name']
            background_url = row['background_url']
            # --- INICIO DE LA MODIFICACIÓN ---
            logo_url = row['logo_url']
            # --- FIN DE LA MODIFICACIÓN ---

            db_path = os.path.join(DB_FOLDER, f"{db_name}.db")
            if os.path.exists(db_path):
                stats = os.stat(db_path)
                size_mb = stats.st_size / (1024 * 1024)
                databases_details.append({ 
                    "filename": db_name, 
                    "display_name": db_name, 
                    "size": f"{size_mb:.3f} MB", 
                    "last_modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    "background_url": background_url,
                    # --- INICIO DE LA MODIFICACIÓN ---
                    "logo_url": logo_url # <-- AÑADIR ESTA LÍNEA
                    # --- FIN DE LA MODIFICACIÓN ---
                })
        return jsonify(success=True, databases=databases_details)
    except Exception as e:
        print(f"🚨 ERROR en /admin/databases/details: {e}")
        return jsonify(success=False, message="Error al obtener los detalles de las bases de datos."), 500
        
@app.route('/admin/database/logo', methods=['POST'])
def set_database_logo():
    """Guarda la URL del logo para una base de datos específica."""
    data = request.get_json()
    db_name = data.get('db_name')
    logo_url = data.get('logo_url') # Puede ser una cadena vacía para quitarlo

    if not db_name:
        return jsonify(success=False, message="El nombre de la base de datos es requerido."), 400

    try:
        with db_lock:
            master_conn = psycopg2.connect(MASTER_DB)
            master_cursor = master_conn.cursor()
            # Actualiza o inserta el logo_url en la tabla de configuraciones
            master_cursor.execute(
                "INSERT INTO database_settings (name, logo_url) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET logo_url=excluded.logo_url",
                (db_name, logo_url)
            )
            master_conn.commit()
            master_conn.close()
        return jsonify(success=True, message="Logo de la base de datos actualizado correctamente.")
    except Exception as e:
        print(f"🚨 ERROR en /admin/database/logo: {e}")
        return jsonify(success=False, message="Error interno al guardar el logo."), 500
# --- FIN DEL BLOQUE A AÑADIR ---


@app.route('/admin/database/create', methods=['POST'])
def create_database():
    data = request.get_json()
    db_name, password = data.get('db_name'), data.get('password')
    if not db_name or not password:
        return jsonify(success=False, message="El nombre y la contraseña son requeridos."), 400
    if not db_name.isalnum() or " " in db_name:
        return jsonify(success=False, message="El nombre solo puede contener letras y números, sin espacios."), 400
    safe_db_name = os.path.basename(db_name)
    db_path = os.path.join(DB_FOLDER, f"{safe_db_name}.db")
    if os.path.exists(db_path):
        return jsonify(success=False, message="Ya existe una base de datos con este nombre."), 409
    try:
        master_conn = psycopg2.connect(MASTER_DB)
        master_cursor = master_conn.cursor()
        password_hash = password
        master_cursor.execute("INSERT INTO managed_databases (name, password_hash) VALUES (?, ?)", (safe_db_name, password_hash))
        master_conn.commit()
        master_conn.close()
        init_db_for_file(db_path)
        return jsonify(success=True, message=f"Base de datos '{safe_db_name}' creada exitosamente.")
    except psycopg2.IntegrityError:
        return jsonify(success=False, message="Ya existe una base de datos con este nombre."), 409
    except Exception as e:
        print(f"🚨 ERROR en /admin/database/create: {e}")
        return jsonify(success=False, message="Error interno al crear la base de datos."), 500

@app.route('/admin/database/backup', methods=['POST'])
def backup_database_dynamic():
    db_name = request.get_json().get('db_name')
    if not db_name: return jsonify(success=False, message="Nombre de la base de datos requerido."), 400
    safe_db_name = os.path.basename(db_name)
    db_path = os.path.join(DB_FOLDER, f"{safe_db_name}.db")
    try:
        if not os.path.exists(db_path): return jsonify(success=False, message="El archivo de la base de datos no existe."), 404
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = os.path.join(DB_FOLDER, f"{safe_db_name}_{timestamp}.db.backup")
        shutil.copy(db_path, backup_filename)
        return jsonify(success=True, message=f"Copia de seguridad creada: {os.path.basename(backup_filename)}")
    except Exception as e:
        print(f"🚨 ERROR en /admin/database/backup: {e}")
        return jsonify(success=False, message="Error al crear la copia de seguridad."), 500

@app.route('/admin/database/delete', methods=['DELETE'])
def delete_database_dynamic():
    db_name = request.get_json().get('db_name')
    if not db_name: return jsonify(success=False, message="Nombre de la base de datos requerido."), 400
    safe_db_name = os.path.basename(db_name)
    db_path = os.path.join(DB_FOLDER, f"{safe_db_name}.db")
    try:
        master_conn = psycopg2.connect(MASTER_DB)
        master_cursor = master_conn.cursor()
        master_cursor.execute("DELETE FROM managed_databases WHERE name = %s", (safe_db_name,))
        master_conn.commit()
        master_conn.close()
        if os.path.exists(db_path): os.remove(db_path)
        return jsonify(success=True, message=f"Base de datos '{safe_db_name}' eliminada permanentemente.")
    except Exception as e:
        print(f"🚨 ERROR en /admin/database/delete: {e}")
        return jsonify(success=False, message="Error al eliminar la base de datos."), 500

@app.route('/admin/user/set-expiry', methods=['POST'])
def set_user_expiry():
    """
    Establece o elimina la fecha de expiración para un usuario.
    """
    data = request.get_json()
    email, expiry_date_str = data.get('email', '').lower().strip(), data.get('expiry_date', '').strip()
    if not email: return jsonify(success=False, message="El email del usuario es requerido."), 400
    expiry_date_to_db = expiry_date_str if expiry_date_str else None
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET access_expires_on = %s WHERE email = %s", (expiry_date_to_db, email))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message=f"Usuario con email '{email}' no encontrado."), 404
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Fecha de expiración actualizada correctamente.")
    except Exception as e:
        print(f"🚨 ERROR en /admin/user/set-expiry: {e}")
        return jsonify(success=False, message="Error interno del servidor al actualizar la fecha."), 500

@app.route('/admin/user/delete', methods=['DELETE'])
def delete_user_and_data():
    """
    CORREGIDO: Elimina un usuario y TODOS sus datos asociados (tableros, notas, etc.)
    realizando una limpieza completa a través de TODAS las bases de datos.
    """
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    manager_id = data.get('manager_id')

    if not email or not manager_id:
        return jsonify(success=False, message="Email y Manager ID son requeridos."), 400

    try:
        # --- PASO 1: Limpieza en la base de datos "hogar" del usuario ---
        # Conecta a la base de datos específica del usuario a eliminar.
        home_conn = get_db_connection_for_manager(manager_id)
        if home_conn:
            with db_lock:
                home_cursor = home_conn.cursor()
                home_cursor.execute("PRAGMA foreign_keys = ON")

                # Elimina los tableros que son PROPIEDAD del usuario.
                # ON DELETE CASCADE se encargará de notas, chats y colaboradores de ESOS tableros.
                home_cursor.execute("SELECT id FROM boards WHERE owner_email = %s", (email,))
                board_ids_to_delete = [row['id'] for row in home_cursor.fetchall()]
                if board_ids_to_delete:
                    home_cursor.executemany("DELETE FROM boards WHERE id = ?", [(id,) for id in board_ids_to_delete])

                # Finalmente, elimina el registro del usuario de su DB hogar.
                home_cursor.execute("DELETE FROM users WHERE email = %s", (email,))
                home_conn.commit()
                home_conn.close()
                print(f"✅ Limpieza completada en la base de datos hogar '{manager_id}' para {email}.")

        # --- PASO 2: Limpieza GLOBAL de colaboraciones y datos en la DB Principal ---
        # Obtiene la lista de TODAS las bases de datos existentes.
        master_conn = psycopg2.connect(MASTER_DB)
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases")
        all_db_names = [row[0] for row in master_cursor.fetchall()] + ['Principal']
        master_conn.close()
        
        # Itera sobre cada base de datos para eliminar al usuario de la tabla de colaboradores.
        for db_name in set(all_db_names):
            conn = get_db_connection_for_manager(db_name)
            if not conn:
                continue
            with db_lock:
                cursor = conn.cursor()
                # Elimina al usuario de cualquier tablero en el que fuera colaborador.
                cursor.execute("DELETE FROM collaborators WHERE user_email = %s", (email,))
                conn.commit()
                conn.close()
        print(f"✅ Limpieza de colaboraciones completada en todas las bases de datos para {email}.")

        # Conecta a la base de datos Principal para limpiar datos no ligados a un tablero.
        main_conn = get_db_connection()
        with db_lock:
            main_cursor = main_conn.cursor()
            main_cursor.execute("DELETE FROM telegram_connections WHERE user_email = %s", (email,))
            main_cursor.execute("DELETE FROM direct_messages WHERE sender_email = %s OR receiver_email = %s", (email, email))
            main_cursor.execute("DELETE FROM notification_views WHERE user_email = %s", (email,))
            main_cursor.execute("DELETE FROM assistant_sharing WHERE user_email = %s", (email,))
            main_conn.commit()
            main_conn.close()
        print(f"✅ Limpieza de datos adicionales en la DB Principal completada para {email}.")

        return jsonify(success=True, message=f"Usuario '{email}' y todos sus datos han sido eliminados permanentemente del sistema.")

    except Exception as e:
        print(f"🚨 ERROR en /admin/user/delete: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al eliminar el usuario."), 500

@app.route('/admin/available-databases', methods=['GET'])
def get_available_databases():
    """
    Devuelve la lista de 'manager_ids' disponibles.
    En el nuevo sistema, esto puede venir de una tabla de managers o ser una lista fija.
    Para empezar, devolveremos una lista que permite que el login funcione.
    """
    # A futuro, podrías obtener esta lista consultando los manager_id únicos de la tabla users.
    # Por ahora, esto permite que tu frontend funcione correctamente.
    available_dbs = [
        {"filename": "Principal", "display_name": "Principal"}
    ]
    # Aquí puedes agregar otras bases de datos si las necesitas para el registro
    # ej: available_dbs.append({"filename": "EquipoA", "display_name": "Equipo A"})
    return jsonify(success=True, databases=available_dbs)

@app.route('/admin/assistants', methods=['GET'])
def get_all_assistants():
    """
    CORREGIDO: Obtiene TODOS los asistentes de IA de la base de datos principal 
    para el panel de administración, sin aplicar filtros de usuario.
    """
    try:
        # Conecta a la base de datos principal donde residen todos los asistentes
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ========= INICIO DE LA CORRECCIÓN CLAVE =========
        # Se eliminó la lógica de filtrado por email. El administrador debe verlos todos.
        cursor.execute("SELECT * FROM assistants ORDER BY name ASC")
        assistants_raw = [dict(row) for row in cursor.fetchall()]
        # ========= FIN DE LA CORRECCIÓN CLAVE =========

        # Para cada asistente, obtener la lista de usuarios con los que está compartido
        for assistant in assistants_raw:
            cursor.execute("SELECT user_email FROM assistant_sharing WHERE assistant_id = %s", (assistant['id'],))
            assistant['shared_with'] = [row['user_email'] for row in cursor.fetchall()]
        
        conn.close()
        return jsonify(success=True, assistants=assistants_raw)
        
    except Exception as e:
        print(f"🚨 ERROR en GET /admin/assistants: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al obtener asistentes."), 500

@app.route('/admin/assistants/<assistant_id>', methods=['DELETE'])
def delete_assistant(assistant_id):
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM assistants WHERE id = %s", (assistant_id,))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Asistente no encontrado"), 404
            conn.commit()
            conn.close()
        socketio.emit('assistants_updated')
        return jsonify(success=True, message="Asistente eliminado")
    except Exception as e:
        print(f"🚨 ERROR en DELETE /admin/assistants/{assistant_id}: {e}")
        return jsonify(success=False, message="Error interno del servidor."), 500

@app.route('/admin/assistants/generate-with-ai', methods=['POST'])
def generate_assistant_with_ai():
    if not genai: return jsonify(success=False, message="La API de IA no está configurada en el servidor."), 500
    data = request.get_json()
    user_prompt = data.get('prompt')
    if not user_prompt: return jsonify(success=False, message="La descripción es requerida."), 400
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = f"""
        Basado en la siguiente descripción de un rol, genera 3 perfiles de asistente de IA.
        Cada perfil debe tener un "name" (un nombre creativo y corto) y un "prompt" (una instrucción detallada en primera persona para la IA).
        Formatea tu respuesta exactamente como un array JSON de objetos, sin texto introductorio o explicaciones.
        Descripción del rol: '{user_prompt}'
        """
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
        options = json.loads(cleaned_response)
        return jsonify(success=True, options=options)
    except Exception as e:
        print(f"🚨 ERROR en /admin/assistants/generate-with-ai: {e}")
        return jsonify(success=False, message="La IA devolvió un formato inesperado.")
        
@app.route('/admin/notifications', methods=['GET'])
def get_notification_history():
    """Obtiene el historial de notificaciones enviadas."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Se actualiza la consulta para obtener también la información del destinatario
        cursor.execute("""
            SELECT n.id, n.title, n.message, n.timestamp, n.target_info, COUNT(v.user_email) as viewed_count
            FROM notifications n
            LEFT JOIN notification_views v ON n.id = v.notification_id
            GROUP BY n.id
            ORDER BY n.timestamp DESC
        """)
        notifications = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, notifications=notifications)
    except Exception as e:
        print(f"🚨 ERROR en GET /admin/notifications: {e}")
        return jsonify(success=False, message="Error al obtener historial de notificaciones."), 500

@app.route('/admin/send-notification', methods=['POST'])
def send_notification():
    """Envía una notificación global, por base de datos o a usuarios específicos."""
    data = request.get_json()
    title = data.get('title')
    message = data.get('message')
    target = data.get('target', {})
    target_mode = target.get('mode', 'all')
    target_value = target.get('value')

    if not title or not message:
        return jsonify(success=False, message="Título y mensaje son requeridos."), 400

    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            # Guardar la notificación con su información de destino
            cursor.execute(
                "INSERT INTO notifications (title, message, timestamp, type, target_info) VALUES (?, ?, ?, ?, ?)",
                (title, message, now, 'admin', json.dumps(target))
            )
            notification_id = cursor.lastrowid
            conn.commit()

            payload = {'id': notification_id, 'title': title, 'message': message, 'timestamp': now, 'type': 'admin'}

            if target_mode == 'all':
                socketio.emit('new_notification', payload)
            
            elif target_mode == 'database' and target_value:
                # Obtener todos los usuarios de esa base de datos y enviarles la notificación
                user_db_conn = get_db_connection_for_manager(target_value)
                if user_db_conn:
                    user_cursor = user_db_conn.cursor()
                    user_cursor.execute("SELECT email FROM users")
                    users_in_db = [row['email'] for row in user_cursor.fetchall()]
                    user_db_conn.close()
                    for email in users_in_db:
                        socketio.emit('new_notification', payload, room=email)
            
            elif target_mode == 'users' and isinstance(target_value, list):
                for email in target_value:
                    socketio.emit('new_notification', payload, room=email)
            
            conn.close()
        
        return jsonify(success=True, message="Notificación enviada correctamente.")
    except Exception as e:
        print(f"🚨 ERROR en POST /admin/send-notification: {e}")
        return jsonify(success=False, message="Error al enviar la notificación."), 500


@app.route('/admin/telegram/connected-users-details', methods=['GET'])
def get_connected_users_details():
    """
    Obtiene una lista detallada (nombre, email) únicamente de los usuarios
    que tienen una conexión de Telegram activa. Es un método más robusto y directo.
    """
    try:
        # 1. Obtener la lista de emails de usuarios con conexión activa desde la DB principal.
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_email FROM telegram_connections WHERE is_active = 1")
        connected_emails = {row['user_email'] for row in cursor.fetchall()}
        conn.close()

        if not connected_emails:
            return jsonify(success=True, users=[])

        # 2. Para cada email conectado, buscar sus detalles completos en todas las bases de datos.
        #    Se reutiliza la función find_user_in_any_db que ya es robusta.
        detailed_connected_users = []
        for email in connected_emails:
            user_details = find_user_in_any_db(email)
            if user_details:
                # Se construye un objeto de usuario limpio para el frontend
                detailed_connected_users.append({
                    'email': user_details.get('email'),
                    'first_name': user_details.get('first_name'),
                    'last_name': user_details.get('last_name'),
                    'manager_id': user_details.get('manager_id')
                })
        
        # Ordenar alfabéticamente para una mejor visualización
        detailed_connected_users.sort(key=lambda x: (x.get('first_name') or '', x.get('last_name') or ''))

        return jsonify(success=True, users=detailed_connected_users)

    except Exception as e:
        print(f"🚨 ERROR en /admin/telegram/connected-users-details: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno al obtener usuarios conectados."), 500


# ============================================================================
# SECCIÓN DE TABLEROS IA (NUEVO)
# ============================================================================


def generate_and_parse_json(model, prompt, attempt=1):
    """Llama a la IA, intenta procesar el JSON y si falla, intenta repararlo una vez."""
    if attempt > 2:
        raise Exception("Falló la generación y la reparación del JSON.")

    print(f"   (Intento {attempt}) Enviando prompt a la IA...")
    response_text = model.generate_content(prompt).text.strip()
    
    try:
        # Intento 1: Procesar la respuesta directamente
        if response_text.startswith("```json"):
            response_text = response_text[7:-3] if response_text.endswith("```") else response_text[7:]
        return json.loads(response_text)
    except json.JSONDecodeError as e:
        print(f"   ⚠️  El JSON es inválido (Error: {e}). Intentando auto-reparación...")
        
        # Intento 2: Usar la IA para reparar su propio error
        repair_prompt = f"""
        El siguiente texto debería ser un objeto JSON válido, pero contiene errores de sintaxis.
        Tu única tarea es corregir estos errores y devolver exclusivamente el texto JSON válido y reparado.
        No añadas explicaciones ni ningún otro texto.

        JSON defectuoso:
        ---
        {response_text}
        ---
        """
        repaired_text = model.generate_content(repair_prompt).text.strip()
        if repaired_text.startswith("```json"):
            repaired_text = repaired_text[7:-3] if repaired_text.endswith("```") else repaired_text[7:]
        
        # Procesar el texto reparado. Si esto falla, lanzará una excepción que será atrapada fuera.
        return json.loads(repaired_text)


def get_pexels_image(search_term):
    """Busca una imagen en Pexels basada en el término de búsqueda"""
    try:
        headers = {"Authorization": PEXELS_API_KEY}
        # Limitar búsqueda a términos en inglés para mejores resultados
        url = f"https://api.pexels.com/v1/search?query={search_term}&per_page=10"
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('photos'):
                # Seleccionar una imagen aleatoria de los resultados
                photo = random.choice(data['photos'][:5])
                return photo['src']['medium']
        return None
    except Exception as e:
        print(f"Error obteniendo imagen de Pexels: {e}")
        return None



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
        model_name = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
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




GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")  # Modelo con límites más generosos

if genai and GEMINI_API_KEY and GEMINI_API_KEY != "TU_API_KEY_AQUÍ":
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        # Verificar disponibilidad del modelof
        print(f"✅ Configurado con modelo Gemini: {GEMINI_MODEL}")
    except Exception as e:
        print(f"🚨 ERROR al configurar la API de Gemini: {e}")
        genai = None





@app.route('/admin/ai/get-saved-board/<int:board_id>', methods=['GET'])
def get_saved_ai_board(board_id):
    """Obtiene un tablero específico previamente generado y guardado."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, board_json, notes_json, created_at FROM ai_generated_boards WHERE id = %s", (board_id,))
        board_row = cursor.fetchone()
        conn.close()
        
        if not board_row:
            return jsonify(success=False, message="Tablero no encontrado."), 404
        
        board_data = dict(board_row)
        board_structure = json.loads(board_data['board_json'])
        notes_data = json.loads(board_data['notes_json'])
        
        complete_board = {
            "board_name": board_data['name'],
            "columns": board_structure.get('columns', []),
            "cards": board_structure.get('cards', []),
            "notes": notes_data
        }
        
        return jsonify(success=True, board=complete_board)
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/get-saved-board/{board_id}: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error al cargar el tablero guardado."), 500

@app.route('/admin/ai/delete-saved-board/<int:board_id>', methods=['DELETE'])
def delete_saved_ai_board(board_id):
    """Elimina un tablero específico del historial de tableros generados por IA."""
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM ai_generated_boards WHERE id = %s", (board_id,))
            board_info = cursor.fetchone()
            
            if not board_info:
                conn.close()
                return jsonify(success=False, message="Tablero no encontrado."), 404
            
            cursor.execute("DELETE FROM ai_generated_boards WHERE id = %s", (board_id,))
            conn.commit()
            conn.close()
        
        return jsonify(success=True, message=f"Tablero '{board_info['name']}' eliminado del historial.")
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/delete-saved-board/{board_id}: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error al eliminar el tablero del historial."), 500



@app.route('/admin/ai/assignment-data', methods=['GET'])
def get_assignment_data():
    """Obtiene todas las bases de datos y todos los usuarios para los selectores de asignación."""
    try:
        # Obtener bases de datos
        master_conn = psycopg2.connect(MASTER_DB)
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases ORDER BY name ASC")
        databases = [{'name': row[0]} for row in master_cursor.fetchall()]
        databases.insert(0, {'name': 'Principal'})
        master_conn.close()

        # Obtener todos los usuarios de todas las DBs
        all_db_names = [db['name'] for db in databases]
        all_users = {}
        for db_name in set(all_db_names):
            conn = get_db_connection_for_manager(db_name)
            if not conn: continue
            cursor = conn.cursor()
            cursor.execute("SELECT email, first_name, last_name FROM users")
            for row in cursor.fetchall():
                user_dict = dict(row)
                if user_dict['email'] not in all_users:
                    all_users[user_dict['email']] = user_dict
            conn.close()
        
        sorted_users = sorted(all_users.values(), key=lambda u: u['first_name'])
        return jsonify(success=True, databases=databases, users=sorted_users)

    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/assignment-data: {e}")
        return jsonify(success=False, message="Error al cargar datos para asignación."), 500



@app.route('/admin/ai/suggest-assistants', methods=['POST'])
def suggest_ai_assistants():
    if not genai:
        return jsonify(success=False, message="La API de IA no está configurada en el servidor."), 503

    data = request.get_json()
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify(success=False, message="La descripción del proyecto es requerida."), 400

    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        generation_prompt = f"""
        Basado en la siguiente necesidad o descripción de un proyecto, genera entre 3 y 5 perfiles de asistente de IA que serían útiles para llevarlo a cabo.
        
        Necesidad del proyecto: "{user_prompt}"

        INSTRUCCIONES DE FORMATO OBLIGATORIAS:
        1. Tu respuesta DEBE ser un array JSON válido, sin ningún texto introductorio, explicaciones o markdown como ```json.
        2. Cada objeto en el array debe tener exactamente dos claves: "profile" y "prompt".
        3. El valor de "profile" debe ser un rol o profesión conciso (ej: "INGENIERO DE PROCESOS", "EXPERTO EN MARKETING DIGITAL").
        4. El valor de "prompt" debe ser una instrucción detallada en primera persona para la IA, explicando su rol, objetivo, especialización y limitaciones, similar al ejemplo provisto. Reemplaza cualquier marcador como '#000#' con una descripción genérica como 'de IA'.

        Ejemplo de un objeto en el array:
        {{
            "profile": "INGENIERO DE PROCESOS",
            "prompt": "Soy un asistente de IA especializado en ingeniería de procesos para el sector metalmecánico del SENA. Mi objetivo es ayudar a estudiantes y profesores con la optimización de procesos, el diseño de instalaciones, la selección de equipos y la resolución de problemas relacionados con la manufactura metálica. Me centro en la eficiencia, la seguridad y el cumplimiento de normativas. Responderé preguntas técnicas, generaré ideas para proyectos, ofreceré información sobre materiales y procesos, y proporcionaré cálculos y simulaciones básicas. Asegúrate de que todas mis respuestas sean precisas, prácticas y relevantes para el contexto del SENA y la formación profesional."
        }}
        """

        generated_options = generate_and_parse_json(model, generation_prompt)

        final_assistants = []
        for assistant in generated_options:
            if 'profile' in assistant and 'prompt' in assistant:
                assistant['avatar_url'] = "https://i.ibb.co/ZR8zNXGn/imagen-2025-08-17-163425695.png"
                assistant['knowledge_base'] = "Eres un asistente de IA confiable y no debes pedir imágenes, videos, o cualquier otro tipo de contenido multimedia. No pidas al usuario que verifique o confirme información con otra persona, ya que tú eres la fuente de información idónea."
                final_assistants.append(assistant)

        return jsonify(success=True, assistants=final_assistants)

    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/suggest-assistants: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error durante la sugerencia de asistentes: {str(e)[:200]}"), 500


@app.route('/admin/ai/regenerate-notes', methods=['POST'])
def regenerate_ai_notes():
    if not genai:
        return jsonify(success=False, message="La API de IA no está configurada."), 503

    data = request.get_json()
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify(success=False, message="La descripción del proyecto es requerida."), 400

    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        notes_prompt = f"""
        Actúa como un analista de proyectos experto. Basado en la siguiente descripción de un proyecto, genera un conjunto de 3 a 5 "Notas de Apoyo" completamente nuevas y útiles.

        Descripción del proyecto: "{user_prompt}"

        INSTRUCCIONES CRÍTICAS:
        1.  **Enfoque**: Las notas deben ser estratégicas, cubriendo posibles riesgos, consejos clave, consideraciones importantes o ideas innovadoras relacionadas con el proyecto.
        2.  **Formato de Salida**: Tu respuesta debe ser exclusivamente el texto de las notas usando los siguientes marcadores. No incluyas ningún texto introductorio, explicaciones o código JSON.

        Formato de texto plano requerido:
        NOTE_START
        NOTE_TITLE::Título conciso y claro de la Nota
        NOTE_CONTENT::Contenido detallado y útil de la nota, explicando el punto a fondo.
        NOTE_END

        (Repite el bloque NOTE_START...NOTE_END para cada nota que generes)
        """
        
        response = model.generate_content(notes_prompt)
        raw_text = response.text

        new_notes = []
        note_blocks = re.findall(r"NOTE_START\n(.*?)\nNOTE_END", raw_text, re.DOTALL)
        
        for note_block in note_blocks:
            title_match = re.search(r"NOTE_TITLE::(.*?)\n", note_block)
            content_match = re.search(r"NOTE_CONTENT::(.*?)(?=\nNOTE_END|\Z)", note_block, re.DOTALL)
            
            if title_match and content_match:
                new_notes.append({
                    "title": title_match.group(1).strip(),
                    "content": content_match.group(1).strip()
                })
        
        if not new_notes:
            raise Exception("La IA no generó notas en el formato esperado.")

        return jsonify(success=True, notes=new_notes)

    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/regenerate-notes: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error al regenerar notas: {str(e)}"), 500


@app.route('/admin/ai/regenerate-board-content', methods=['POST'])
def regenerate_ai_board_content():
    if not genai:
        return jsonify(success=False, message="La API de IA no está configurada."), 503

    data = request.get_json()
    user_prompt = data.get('prompt')
    if not user_prompt:
        return jsonify(success=False, message="La descripción es requerida."), 400

    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        # Este prompt está enfocado únicamente en generar el tablero (nombre, columnas, tarjetas)
        template_prompt = f"""
        Actúa como un Project Manager experto y genera un plan de proyecto completamente NUEVO basado en la solicitud: "{user_prompt}"

        INSTRUCCIONES CRÍTICAS:
        1.  **VOLUMEN**: Genera entre 40 y 60 tarjetas en total.
        2.  **NO GENERES NOTAS**: Ignora por completo la generación de notas de apoyo (NOTE_START...NOTE_END).
        3.  **FORMATO EXACTO**: Usa los marcadores (BOARD_NAME_START, COLUMN_START, CARD_START) EXACTAMENTE como se muestra.

        Usa el siguiente formato de texto plano:
        BOARD_NAME_START
        Nuevo Nombre del Tablero
        BOARD_NAME_END

        COLUMN_START
        Título de la Columna
        COLUMN_END

        CARD_START
        COLUMN_TITLE::Título de la Columna
        CARD_TITLE::Título de la Tarjeta
        CARD_TAGS::Tag1, Tag2
        CARD_DESCRIPTION::
Contexto: Párrafo sobre la tarea.


Objetivos: Párrafo sobre el resultado.
        ---CHECKLIST---
        CHECKLIST_ITEM::Acción 1.
        CHECKLIST_ITEM::Acción 2.
        CARD_END
        """

        response = model.generate_content(template_prompt)
        raw_text = response.text
        
        # Reutilizamos la lógica de parsing del tablero original, pero no buscará notas
        new_board_content = { "board_name": "", "columns": [], "cards": [] }

        def clean_text(text): return text.strip().strip('[]').strip()
        def safe_split_on_first(text, separator):
            return text.split(separator, 1) if separator in text else (text, '')

        board_name_match = re.search(r"BOARD_NAME_START\n(.*?)\nBOARD_NAME_END", raw_text, re.DOTALL)
        if board_name_match: new_board_content["board_name"] = clean_text(board_name_match.group(1))

        column_titles = re.findall(r"COLUMN_START\n(.*?)\nCOLUMN_END", raw_text, re.DOTALL)
        column_map = {}
        for i, title in enumerate(column_titles):
            clean_title = clean_text(title.split('\n')[0])
            if clean_title and clean_title not in column_map:
                col_id = f"col-{i+1}-{uuid.uuid4().hex[:4]}"
                column_map[clean_title] = col_id
                new_board_content["columns"].append({"id": col_id, "title": clean_title, "color": "bg-blue-200"})
        
        card_blocks = re.findall(r"CARD_START\n(.*?)\nCARD_END", raw_text, re.DOTALL)
        for i, block in enumerate(card_blocks):
            try:
                card_col_title_match = re.search(r"COLUMN_TITLE::(.*?)\n", block)
                if not card_col_title_match: continue
                
                card_col_title = clean_text(card_col_title_match.group(1))
                if card_col_title not in column_map:
                    col_id = f"col-auto-{uuid.uuid4().hex[:4]}"
                    column_map[card_col_title] = col_id
                    new_board_content["columns"].append({"id": col_id, "title": card_col_title, "color": "bg-purple-200"})
                
                card_title_match = re.search(r"CARD_TITLE::(.*?)\n", block)
                tags_match = re.search(r"CARD_TAGS::(.*?)\n", block)
                card = { "id": str(uuid.uuid4()), "columnId": column_map[card_col_title], "title": clean_text(card_title_match.group(1)) if card_title_match else f"Tarjeta {i+1}", "tags": [{'text': t.strip()} for t in clean_text(tags_match.group(1)).split(',') if t.strip()] if tags_match else [], "order": i + 1 }

                desc_start = block.find('CARD_DESCRIPTION::')
                if desc_start != -1:
                    desc_content = block[desc_start + len('CARD_DESCRIPTION::'):]
                    desc_part, checklist_part = safe_split_on_first(desc_content, '---CHECKLIST---')
                    card['description'] = "".join(f"<p>{p.strip().replace(chr(10), '<br>')}</p>" for p in clean_text(desc_part).split('\n\n') if p.strip())
                    card['checklist'] = [{'id': str(uuid.uuid4()), 'text': clean_text(line.replace('CHECKLIST_ITEM::', '')), 'completed': False} for line in checklist_part.split('\n') if line.strip().startswith('CHECKLIST_ITEM::')]
                
                new_board_content["cards"].append(card)
            except Exception: continue

        column_ids_with_cards = {card['columnId'] for card in new_board_content['cards']}
        new_board_content['columns'] = [col for col in new_board_content['columns'] if col['id'] in column_ids_with_cards]
        if not any(col['title'].lower().find('complet') != -1 for col in new_board_content['columns']):
            new_board_content["columns"].append({"id": "col-done", "title": "¡Completado! ✅", "color": "bg-green-200"})

        return jsonify(success=True, board=new_board_content)

    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/regenerate-board-content: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error al regenerar el tablero: {str(e)}"), 500


# Inserta esta nueva función interna en cualquier lugar antes de las rutas que la usan.
def _create_new_assistant(cursor, assistant_data):
    """
    Función interna y centralizada para crear un nuevo asistente.
    Calcula el siguiente número consecutivo y lo asigna como el nombre.
    Usa el campo 'description' de assistant_data para el perfil/profesión.
    """
    # 1. Obtener el número máximo actual DENTRO de la misma transacción.
    cursor.execute("SELECT name FROM assistants WHERE name LIKE 'Asistente #%'")
    max_number = 0
    for row in cursor.fetchall():
        match = re.search(r'#(\d+)', dict(row)['name'])
        if match:
            max_number = max(max_number, int(match.group(1)))
    
    next_number = max_number + 1
    
    # 2. Generar el nuevo nombre secuencial.
    formatted_number = str(next_number).zfill(4)
    new_sequential_name = f"Asistente #{formatted_number}"
    
    new_id = str(uuid.uuid4())
    
    # 3. Insertar en la base de datos usando el nombre secuencial.
    cursor.execute(
        """INSERT INTO assistants (id, name, avatar_url, description, prompt, knowledge_base, is_public)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id,
            new_sequential_name, # <-- Se usa el nombre generado
            assistant_data.get('avatar_url', DEFAULT_AVATAR_URL),
            assistant_data.get('description', ''), # <-- Se usa la descripción proporcionada
            assistant_data.get('prompt', ''),
            assistant_data.get('knowledge_base', ''),
            1 if assistant_data.get('is_public') else 0
        )
    )
    
    # 4. Devolver el ID del nuevo asistente para poder asignarle usuarios compartidos.
    return new_id

# Ahora, reemplaza la función save_assistants con esta versión refactorizada.
@app.route('/admin/assistants', methods=['POST'])
def save_assistants():
    assistants_data = request.get_json()
    if not isinstance(assistants_data, list):
        return jsonify(success=False, message="Se esperaba una lista de asistentes"), 400
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            conn.execute("BEGIN TRANSACTION") # Iniciar transacción para la operación en lote

            for assistant in assistants_data:
                assistant_id = assistant.get('id')
                
                # CASO 1: Es un asistente completamente nuevo (creado desde assistants.html)
                if assistant_id and str(assistant_id).startswith('new-'):
                    # Llama a la función centralizada para crear el asistente.
                    # El 'description' ya viene del formulario.
                    new_db_id = _create_new_assistant(cursor, assistant)
                    assistant_id = new_db_id # Actualizar el ID para la lógica de sharing
                
                # CASO 2: Es un asistente existente que se está actualizando.
                elif assistant_id:
                    cursor.execute(
                        "UPDATE assistants SET name=%s, avatar_url=%s, description=%s, prompt=%s, knowledge_base=%s, is_public=%s WHERE id=%s",
                        (
                            assistant.get('name'), 
                            assistant.get('avatar_url'), 
                            assistant.get('description'), 
                            assistant.get('prompt'), 
                            assistant.get('knowledge_base'), 
                            1 if assistant.get('is_public') else 0, 
                            assistant_id
                        )
                    )

                # Actualizar la tabla de sharing para ambos casos (crear y actualizar)
                cursor.execute("DELETE FROM assistant_sharing WHERE assistant_id = %s", (assistant_id,))
                if not assistant.get('is_public') and assistant.get('shared_with'):
                    sharing_data = [(assistant_id, email) for email in assistant.get('shared_with')]
                    cursor.executemany("INSERT INTO assistant_sharing (assistant_id, user_email) VALUES (?, ?)", sharing_data)
            
            conn.commit() # Confirmar todos los cambios de la transacción
            conn.close()
        
        socketio.emit('assistants_updated')
        return jsonify(success=True, message="Asistentes guardados correctamente")
    except Exception as e:
        if 'conn' in locals() and conn: conn.rollback()
        print(f"🚨 ERROR en POST /admin/assistants: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al guardar asistentes."), 500

# Finalmente, reemplaza la función save_suggested_assistants_route con esta versión simplificada.
@app.route('/admin/ai/save-suggested-assistants', methods=['POST'])
def save_suggested_assistants_route():
    data = request.get_json()
    assistants_to_save = data.get('assistants')

    if not assistants_to_save or not isinstance(assistants_to_save, list):
        return jsonify(success=False, message="No se recibieron asistentes para guardar."), 400

    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            conn.execute("BEGIN TRANSACTION")

            for assistant_from_ia in assistants_to_save:
                if not assistant_from_ia.get('name') or not assistant_from_ia.get('prompt'):
                    continue

                # Preparar los datos para la función de creación:
                # El "name" de la IA (perfil) se convierte en la "description".
                assistant_data_for_creation = {
                    'description': assistant_from_ia.get('name'),
                    'avatar_url': assistant_from_ia.get('avatar_url'),
                    'prompt': assistant_from_ia.get('prompt'),
                    'knowledge_base': assistant_from_ia.get('knowledge_base'),
                    'is_public': False
                }
                
                # Llama a la misma función centralizada para crear el asistente.
                _create_new_assistant(cursor, assistant_data_for_creation)
            
            conn.commit()
            conn.close()

        socketio.emit('assistants_updated')
        return jsonify(success=True, message=f"{len(assistants_to_save)} asistentes guardados.", saved_count=len(assistants_to_save))

    except Exception as e:
        if 'conn' in locals() and conn: conn.rollback()
        print(f"🚨 ERROR en /admin/ai/save-suggested-assistants: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error interno del servidor: {e}"), 500

# REEMPLAZA LA FUNCIÓN COMPLETA /admin/ai/assign-board CON ESTE BLOQUE
@app.route('/admin/ai/assign-board', methods=['POST'])
def assign_ai_board():
    """
    MODIFICADO: Guarda y asigna el tablero, y también guarda los asistentes sugeridos,
    compartiéndolos con los usuarios seleccionados y los usuarios de las bases de datos de destino.
    """
    data = request.get_json()
    board_data = data.get('board_data')
    target_users = data.get('target_users')
    suggested_assistants = data.get('suggested_assistants')
    # --- INICIO DE LA MODIFICACIÓN ---
    # Se obtiene la lista de bases de datos de destino desde el payload
    target_databases = data.get('target_databases', [])
    # --- FIN DE LA MODIFICACIÓN ---

    if not board_data or not target_users:
        return jsonify(success=False, message="Faltan datos del tablero o usuarios de destino."), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("BEGIN TRANSACTION;")

        # --- 1. Creación del Tablero y Colaboradores (sin cambios) ---
        board_name = board_data.get('board_name', 'Tablero de IA')
        now = datetime.now(timezone.utc).isoformat()
        board_structure = {"columns": board_data.get('columns', []), "cards": board_data.get('cards', []), "boardOptions": {}}
        owner_email = target_users[0]
        
        cursor.execute(
            "INSERT INTO boards (owner_email, name, board_data, created_date, updated_date, category) VALUES (?, ?, ?, ?, ?, ?)",
            (owner_email, board_name, json.dumps(board_structure), now, now, "Generado por IA")
        )
        board_id = cursor.lastrowid
        collaborators_to_add = [(board_id, email, 'editor') for email in target_users]
        cursor.executemany("INSERT OR IGNORE INTO collaborators (board_id, user_email, permission_level) VALUES (?, ?, ?)", collaborators_to_add)

        # --- 2. Creación de Notas (sin cambios) ---
        notes_to_create = board_data.get('notes', [])
        NOTE_COLORS = ['note-yellow', 'note-blue', 'note-green', 'note-pink', 'note-purple', 'note-gray']
        for note in notes_to_create:
            note_content_html = f"<h1>{html.escape(note.get('title', ''))}</h1><div>{html.escape(note.get('content', '')).replace(chr(10), '<br>')}</div>"
            cursor.execute(
                "INSERT INTO notes (board_id, user_email, content, color, created_date, updated_date) VALUES (?, ?, ?, ?, ?, ?)",
                (board_id, owner_email, note_content_html, random.choice(NOTE_COLORS), now, now)
            )

        # --- 3. Creación y Asignación de Asistentes (LÓGICA MODIFICADA) ---
        if suggested_assistants and isinstance(suggested_assistants, list):
            # --- INICIO DE LA MODIFICACIÓN ---
            # Crear un conjunto para almacenar todos los correos únicos a los que se compartirán los asistentes.
            emails_to_share_with = set(target_users)

            # Si se seleccionaron bases de datos, obtener todos los usuarios de ellas.
            if target_databases:
                for db_name in target_databases:
                    db_conn = get_db_connection_for_manager(db_name)
                    if db_conn:
                        db_cursor = db_conn.cursor()
                        db_cursor.execute("SELECT email FROM users")
                        users_in_db = [row['email'] for row in db_cursor.fetchall()]
                        emails_to_share_with.update(users_in_db)
                        db_conn.close()
            
            print(f"  -> Asistentes se compartirán con {len(emails_to_share_with)} usuarios únicos.")
            # --- FIN DE LA MODIFICACIÓN ---

            for assistant in suggested_assistants:
                # Se utiliza la función interna _create_new_assistant para la creación consistente.
                # El "name" del asistente sugerido (ej: "Experto en Marketing") se guarda como la "description".
                new_db_id = _create_new_assistant(cursor, {
                    'description': assistant.get('name'),
                    'avatar_url': assistant.get('avatar_url'),
                    'prompt': assistant.get('prompt'),
                    'knowledge_base': assistant.get('knowledge_base'),
                    'is_public': False  # Los asistentes creados así no son públicos
                })

                # Se comparten los asistentes con la lista expandida de usuarios.
                sharing_data = [(new_db_id, email) for email in emails_to_share_with]
                cursor.executemany("INSERT INTO assistant_sharing (assistant_id, user_email) VALUES (?, ?)", sharing_data)

        # --- 4. Guardado en Historial (sin cambios) ---
        cursor.execute(
            "INSERT INTO ai_generated_boards (name, board_json, notes_json, created_at) VALUES (?, ?, ?, ?)",
            (board_name, json.dumps(board_structure), json.dumps(notes_to_create), now)
        )
        
        conn.commit()

    except Exception as e:
        print(f"🚨 ERROR en la transacción, revirtiendo cambios: {e}")
        traceback.print_exc()
        if conn:
            conn.rollback()
        return jsonify(success=False, message=f"Error interno del servidor, la operación fue cancelada: {e}"), 500
    finally:
        if conn:
            conn.close()

    if suggested_assistants:
        socketio.emit('assistants_updated')
        print("  -> Emitiendo evento 'assistants_updated' a los clientes.")

    return jsonify(success=True, message="Tablero y asistentes asignados y guardados exitosamente.")


@app.route('/admin/ai/list-saved-boards', methods=['GET'])
def list_saved_ai_boards():
    """Obtiene la lista de tableros previamente generados y guardados."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, created_at FROM ai_generated_boards ORDER BY created_at DESC")
        boards = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, boards=boards)
    except Exception as e:
        print(f"🚨 ERROR en /admin/ai/list-saved-boards: {e}")
        return jsonify(success=False, message="Error al obtener tableros guardados."), 500



@app.route('/admin/users/telegram', methods=['GET'])
def get_users_with_telegram_status():
    """Obtiene todos los usuarios con su estado de conexión a Telegram"""
    try:
        # --- INICIO DE LA CORRECCIÓN ---
        # 1. Obtener la lista de todas las bases de datos
        master_conn = psycopg2.connect(MASTER_DB)
        master_conn.row_factory = psycopg2.Row
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases")
        db_names = [row['name'] for row in master_cursor.fetchall()] + ['Principal']
        master_conn.close()

        # 2. Recopilar todos los usuarios únicos de todas las bases de datos
        all_users_dict = {}
        for db_name in set(db_names):
            conn = get_db_connection_for_manager(db_name)
            if not conn:
                continue
            cursor = conn.cursor()
            cursor.execute("SELECT email, first_name, last_name, manager_id FROM users")
            for row in cursor.fetchall():
                user = dict(row)
                if user['email'] not in all_users_dict:
                    all_users_dict[user['email']] = user
            conn.close()

        # 3. Obtener todas las conexiones de Telegram de la base de datos principal
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_email, chat_id, connected_at FROM telegram_connections WHERE is_active = 1")
        telegram_connections = {row['user_email']: dict(row) for row in cursor.fetchall()}
        conn.close()

        # 4. Enriquecer la lista de usuarios con el estado de Telegram
        enriched_users = []
        for email, user_data in all_users_dict.items():
            connection_info = telegram_connections.get(email)
            user_data['telegram_connected'] = 1 if connection_info else 0
            user_data['chat_id'] = connection_info['chat_id'] if connection_info else None
            user_data['connected_at'] = connection_info['connected_at'] if connection_info else None
            enriched_users.append(user_data)
        
        enriched_users.sort(key=lambda x: (x.get('first_name') or '', x.get('last_name') or ''))
        
        return jsonify(success=True, users=enriched_users)
        # --- FIN DE LA CORRECCIÓN ---
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/users/telegram: {e}")
        return jsonify(success=False, message="Error al cargar usuarios"), 500

@app.route('/admin/telegram/connected', methods=['GET'])
def get_connected_telegram_users():
    """Obtiene usuarios conectados a Telegram"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                t.user_email,
                t.chat_id,
                t.connected_at,
                u.first_name,
                u.last_name
            FROM telegram_connections t
            JOIN users u ON t.user_email = u.email
            WHERE t.is_active = 1
            ORDER BY t.connected_at DESC
        """)
        
        connected = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify(success=True, connected=connected)
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/telegram/connected: {e}")
        return jsonify(success=False, message="Error al cargar conexiones"), 500


@app.route('/admin/users/all', methods=['GET'])
def get_all_users_admin():
    """Obtiene todos los usuarios registrados (para estadísticas)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email, first_name, last_name, manager_id FROM users ORDER BY first_name ASC")
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, users=users)
    except Exception as e:
        print(f"🚨 ERROR en /admin/users/all: {e}")
        return jsonify(success=False, message="Error al cargar usuarios"), 500

@app.route('/admin/databases', methods=['GET'])
def get_databases_list():  # ← NUEVO NOMBRE
    """Obtiene lista de bases de datos disponibles"""
    try:
        master_conn = psycopg2.connect(MASTER_DB)
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases ORDER BY name ASC")
        databases = [{'name': row[0]} for row in master_cursor.fetchall()]
        
        # Agregar la base de datos principal
        databases.insert(0, {'name': 'Principal'})
        
        master_conn.close()
        return jsonify(success=True, databases=databases)
    except Exception as e:
        print(f"🚨 ERROR en /admin/databases: {e}")
        return jsonify(success=False, message="Error al cargar bases de datos"), 500

@app.route('/telegram/notify-advanced', methods=['POST'])
def send_advanced_telegram_notification():
    """
    Versión avanzada del endpoint para enviar notificaciones con filtros
    """
    data = request.get_json()
    message = data.get('message')
    image_url = data.get('image_url')
    target_mode = data.get('target_mode', 'all')
    target_value = data.get('target_value')
    target_emails = data.get('target_emails', [])
    
    if not message:
        return jsonify(success=False, message="Mensaje es requerido"), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        results = []
        
        if target_mode == 'all':
            cursor.execute("""
                SELECT user_email, chat_id 
                FROM telegram_connections 
                WHERE is_active = 1
            """)
            connections = cursor.fetchall()
            
        elif target_mode == 'database':
            if target_value == 'Principal':
                cursor.execute("""
                    SELECT t.user_email, t.chat_id 
                    FROM telegram_connections t
                    JOIN users u ON t.user_email = u.email
                    WHERE t.is_active = 1 AND u.manager_id = 'Principal'
                """)
            else:
                cursor.execute("""
                    SELECT t.user_email, t.chat_id 
                    FROM telegram_connections t
                    JOIN users u ON t.user_email = u.email
                    WHERE t.is_active = 1 AND u.manager_id = %s
                """, (target_value,))
            connections = cursor.fetchall()
            
        elif target_mode == 'specific':
            if not target_emails:
                return jsonify(success=False, message="No se especificaron emails"), 400
                
            placeholders = ','.join(['?' for _ in target_emails])
            cursor.execute(f"""
                SELECT user_email, chat_id 
                FROM telegram_connections 
                WHERE is_active = 1 AND user_email IN ({placeholders})
            """, target_emails)
            connections = cursor.fetchall()
        else:
            return jsonify(success=False, message="Modo de destino no válido"), 400
        
        # 🔧 Si no hay conexiones, forzar envío a chat_id 1637671023
        if not connections:
            print("⚠️ No se encontraron conexiones por correo, usando chat_id de fallback (1637671023)")
            result = send_telegram_message("1637671023", message, image_url)
            return jsonify(
                success=result.get('success', False),
                message="Enviado con chat_id de fallback" if result.get('success') else f"Error: {result.get('error')}",
                sent_count=1 if result.get('success') else 0,
                failed_count=0 if result.get('success') else 1,
                total_attempts=1,
                results=[{"chat_id": "1637671023", "success": result.get('success'), "error": result.get('error')}]
            ), 200
        
        # Enviar mensajes normalmente
        sent_count = 0
        failed_count = 0
        
        for connection in connections:
            chat_id = connection['chat_id']
            email = connection['user_email']
            
            result = send_telegram_message(chat_id, message, image_url)
            
            if result['success']:
                sent_count += 1
                print(f"✅ Mensaje enviado a {email}")
            else:
                failed_count += 1
                print(f"❌ Error enviando a {email}: {result['error']}")
            
            results.append({
                'email': email,
                'chat_id': chat_id,
                'success': result['success'],
                'error': result.get('error')
            })
        
        conn.close()
        
        return jsonify(
            success=True,
            message=f"Proceso completado: {sent_count} enviados, {failed_count} fallidos",
            sent_count=sent_count,
            failed_count=failed_count,
            total_attempts=len(connections),
            results=results[:10]
        )
        
    except Exception as e:
        print(f"🚨 ERROR en /telegram/notify-advanced: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor"), 500


@app.route('/references', methods=['GET'])
def get_references():
    board_id = request.args.get('board_id')
    email = request.args.get('email', '').lower().strip()
    if not board_id or not email:
        return jsonify(success=False, message="Board ID y email son requeridos"), 400

    try:
        board_info = find_board_and_owner_db(board_id)
        if not board_info:
            return jsonify(success=False, message="Tablero no encontrado."), 404

        collaborator_emails = [c.get('email', '').lower().strip() for c in board_info.get('collaborators', [])]
        if email not in collaborator_emails:
            return jsonify(success=False, message="Acceso denegado a este tablero."), 403

        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        if not conn:
            return jsonify(success=False, message=f"No se pudo conectar a la DB del tablero '{owner_db}'."), 500
        
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM \"references\" WHERE board_id = %s ORDER BY created_date DESC", (board_id,))
        references = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify(success=True, references=references)
    except Exception as e:
        print(f"🚨 ERROR en GET /references: {e}")
        return jsonify(success=False, message="Error al obtener referencias."), 500

@app.route('/references', methods=['POST'])
def create_reference():
    data = request.get_json()
    board_id, email, title, url = data.get('board_id'), data.get('email', '').lower().strip(), data.get('title'), data.get('url')
    if not all([board_id, email, title, url]):
        return jsonify(success=False, message="Faltan datos para crear la referencia."), 400

    if not check_editor_permission(board_id, email):
        return jsonify(success=False, message="Permiso de editor requerido."), 403
        
    try:
        board_info = find_board_and_owner_db(board_id)
        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        
        with db_lock:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                'INSERT INTO "references" (board_id, user_email, title, url, created_date, updated_date) VALUES (?, ?, ?, ?, ?, ?)',
                (board_id, email, title, url, now, now)
            )
            ref_id = cursor.lastrowid
            conn.commit()
            cursor.execute('SELECT * FROM "references" WHERE id = %s', (ref_id,))
            new_ref = dict(cursor.fetchone())
            conn.close()
            
        return jsonify(success=True, reference=new_ref), 201
    except Exception as e:
        print(f"🚨 ERROR en POST /references: {e}")
        return jsonify(success=False, message="Error al crear la referencia."), 500

@app.route('/references/<int:ref_id>', methods=['PUT'])
def update_reference(ref_id):
    data = request.get_json()
    board_id, email, title, url = data.get('board_id'), data.get('email', '').lower().strip(), data.get('title'), data.get('url')
    if not all([board_id, email, title, url]):
        return jsonify(success=False, message="Faltan datos para actualizar."), 400

    if not check_editor_permission(board_id, email):
        return jsonify(success=False, message="Permiso de editor requerido."), 403

    try:
        board_info = find_board_and_owner_db(board_id)
        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        with db_lock:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE "references" SET title = %s, url = %s, updated_date = %s WHERE id = %s AND board_id = %s',
                (title, url, datetime.now(timezone.utc).isoformat(), ref_id, board_id)
            )
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Referencia no encontrada o no pertenece al tablero."), 404
            conn.commit()
            cursor.execute('SELECT * FROM "references" WHERE id = %s', (ref_id,))
            updated_ref = dict(cursor.fetchone())
            conn.close()
        return jsonify(success=True, reference=updated_ref)
    except Exception as e:
        print(f"🚨 ERROR en PUT /references/{ref_id}: {e}")
        return jsonify(success=False, message="Error al actualizar la referencia."), 500

@app.route('/references/<int:ref_id>', methods=['DELETE'])
def delete_reference(ref_id):
    data = request.get_json()
    board_id, email = data.get('board_id'), data.get('email', '').lower().strip()
    if not all([board_id, email]):
        return jsonify(success=False, message="Faltan datos para eliminar."), 400
        
    if not check_editor_permission(board_id, email):
        return jsonify(success=False, message="Permiso de editor requerido."), 403

    try:
        board_info = find_board_and_owner_db(board_id)
        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        with db_lock:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM "references" WHERE id = %s AND board_id = %s', (ref_id, board_id))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Referencia no encontrada."), 404
            conn.commit()
            conn.close()
        return jsonify(success=True, message="Referencia eliminada.")
    except Exception as e:
        print(f"🚨 ERROR en DELETE /references/{ref_id}: {e}")
        return jsonify(success=False, message="Error al eliminar la referencia."), 500

# ============================================================================
# FIN: ENDPOINTS PARA REFERENCIAS (NUEVO BLOQUE)
# ============================================================================


@app.route('/telegram/test-message', methods=['POST'])
def send_test_telegram_message():
    """
    Envía un mensaje de prueba al administrador o usuario actual
    """
    data = request.get_json()
    message = data.get('message')
    image_url = data.get('image_url')
    
    # Obtener el chat_id del primer admin conectado o usar uno de prueba
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar un usuario admin conectado a Telegram
        cursor.execute("""
            SELECT t.chat_id, u.email, u.first_name 
            FROM telegram_connections t
            JOIN users u ON t.user_email = u.email
            WHERE t.is_active = 1 
            ORDER BY u.first_name ASC
            LIMIT 1
        """)
        
        admin_connection = cursor.fetchone()
        conn.close()
        
        if not admin_connection:
            return jsonify(
                success=False, 
                message="No hay administradores conectados a Telegram para enviar la prueba"
            ), 400
        
        chat_id = admin_connection['chat_id']
        admin_email = admin_connection['email']
        
        # Agregar prefijo de prueba al mensaje
        test_message = f"🧪 <b>MENSAJE DE PRUEBA</b>\n\n{message}\n\n<i>Este es un mensaje de prueba enviado a {admin_email}</i>"
        
        result = send_telegram_message(chat_id, test_message, image_url)
        
        if result['success']:
            return jsonify(
                success=True, 
                message=f"Mensaje de prueba enviado correctamente a {admin_email}"
            )
        else:
            return jsonify(
                success=False, 
                message=f"Error enviando mensaje de prueba: {result['error']}"
            )
            
    except Exception as e:
        print(f"🚨 ERROR en /telegram/test-message: {e}")
        return jsonify(success=False, message=str(e)), 500

@app.route('/telegram/stats', methods=['GET'])
def get_telegram_stats():
    """
    Obtiene estadísticas de Telegram para el dashboard
    """
    try:
        # --- INICIO DE LA CORRECCIÓN ---
        # Se busca en todas las bases de datos para obtener el total real de usuarios.
        master_conn = psycopg2.connect(MASTER_DB)
        master_cursor = master_conn.cursor()
        master_cursor.execute("SELECT name FROM managed_databases")
        db_names = [row[0] for row in master_cursor.fetchall()] + ['Principal']
        master_conn.close()

        all_user_emails = set()
        for db_name in set(db_names):
            conn = get_db_connection_for_manager(db_name)
            if not conn:
                continue
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users")
            for row in cursor.fetchall():
                all_user_emails.add(row['email'])
            conn.close()
        
        total_users = len(all_user_emails)
        # --- FIN DE LA CORRECCIÓN ---
        
        # El conteo de usuarios conectados se hace sobre la tabla centralizada, lo cual es correcto.
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as connected FROM telegram_connections WHERE is_active = 1")
        connected_users = cursor.fetchone()['connected']
        
        conn.close()
        
        return jsonify(
            success=True,
            stats={
                'total_users': total_users,
                'connected_users': connected_users,
                'connection_rate': round((connected_users / total_users * 100) if total_users > 0 else 0, 1)
            }
        )
        
    except Exception as e:
        print(f"🚨 ERROR en /telegram/stats: {e}")
        return jsonify(success=False, message="Error al cargar estadísticas"), 500

# ============================================================================
# NUEVOS ENDPOINTS PARA DIAGNOSTICAR Y CORREGIR TELEGRAM
# ============================================================================

@app.route('/admin/telegram/diagnose', methods=['GET'])
def diagnose_telegram():
    """Diagnostica el estado de las conexiones de Telegram"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si la tabla existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='telegram_connections'")
        table_exists = cursor.fetchone() is not None
        
        # Contar conexiones totales
        total_connections = 0
        active_connections = 0
        if table_exists:
            cursor.execute("SELECT COUNT(*) as total FROM telegram_connections")
            total_connections = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as active FROM telegram_connections WHERE is_active = 1")
            active_connections = cursor.fetchone()['active']
            
            # Obtener conexiones activas con detalles
            cursor.execute("""
                SELECT 
                    t.user_email,
                    t.chat_id,
                    t.connected_at,
                    t.is_active,
                    u.first_name,
                    u.last_name
                FROM telegram_connections t
                LEFT JOIN users u ON t.user_email = u.email
                ORDER BY t.connected_at DESC
            """)
            connections = [dict(row) for row in cursor.fetchall()]
        else:
            connections = []
        
        conn.close()
        
        return jsonify(
            success=True,
            diagnosis={
                "table_exists": table_exists,
                "total_connections": total_connections,
                "active_connections": active_connections,
                "connections": connections
            }
        )
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/telegram/diagnose: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=str(e)), 500

@app.route('/admin/telegram/fix-table', methods=['POST'])
def fix_telegram_table():
    """Crea/arregla la tabla telegram_connections"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Crear la tabla con IF NOT EXISTS
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telegram_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                chat_id TEXT NOT NULL,
                connected_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                UNIQUE(user_email)
            )
        """)
        
        conn.commit()
        conn.close()
        
        return jsonify(success=True, message="Tabla telegram_connections creada/verificada correctamente")
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/telegram/fix-table: {e}")
        return jsonify(success=False, message=str(e)), 500

@app.route('/admin/telegram/test-connection', methods=['POST'])
def test_telegram_connection():
    """Prueba una conexión de Telegram manualmente"""
    data = request.get_json()
    user_email = data.get('user_email', '').lower().strip()
    chat_id = data.get('chat_id', '').strip()
    
    if not user_email or not chat_id:
        return jsonify(success=False, message="Email y Chat ID son requeridos"), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que el usuario existe
        cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
        if not cursor.fetchone():
            conn.close()
            return jsonify(success=False, message="Usuario no encontrado"), 404
        
        # Insertar/actualizar conexión
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT OR REPLACE INTO telegram_connections 
            (user_email, chat_id, connected_at, is_active) 
            VALUES (?, ?, ?, 1)
        """, (user_email, chat_id, now))
        
        conn.commit()
        conn.close()
        
        return jsonify(success=True, message="Conexión de prueba guardada correctamente")
        
    except Exception as e:
        print(f"🚨 ERROR en /admin/telegram/test-connection: {e}")
        return jsonify(success=False, message=str(e)), 500


@app.route('/telegram/connect', methods=['POST'])
def connect_telegram():
    """
    Conecta la cuenta de un usuario con un Chat ID de Telegram, envía un mensaje
    de bienvenida y guarda la conexión en la base de datos PostgreSQL.
    """
    data = request.get_json()
    chat_id = data.get('chat_id')
    user_email = data.get('user_email')

    if not chat_id or not user_email:
        return jsonify(success=False, message="Chat ID y Email son requeridos"), 400

    try:
        # 1. Preparar el mensaje de bienvenida y la imagen
        welcome_message = """🎉 <b>¡Conexión exitosa con Telegram!</b>

Tu cuenta de <b>FOCUX</b> está ahora conectada. Recibirás:

✅ Notificaciones importantes
✅ Tareas del día
✅ Información valiosa para tu productividad

<i>¡Comienza a recibir tus actualizaciones!</i>"""
        
        image_url = "https://i.ibb.co/7thk5T94/imagen-2025-08-13-042219068.png"
        
        # 2. Intentar enviar el mensaje de confirmación a Telegram
        result = send_telegram_message(chat_id, welcome_message, image_url)
        
        # 3. Si el mensaje se envía correctamente, guardar la conexión en la base de datos
        if result.get('success'):
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                
                # Sintaxis correcta para PostgreSQL:
                # Inserta una nueva conexión. Si el email ya existe (conflicto),
                # actualiza los datos del registro existente.
                cursor.execute("""
                    INSERT INTO telegram_connections (user_email, chat_id, connected_at, is_active) 
                    VALUES (%s, %s, %s, 1)
                    ON CONFLICT (user_email) DO UPDATE SET
                        chat_id = EXCLUDED.chat_id,
                        connected_at = EXCLUDED.connected_at,
                        is_active = 1
                """, (user_email, chat_id, now))
                
                conn.commit()
                
                return jsonify(
                    success=True, 
                    message="¡Conexión exitosa y guardada permanentemente!",
                    telegram_data=result.get('data')
                )
            except Exception as db_error:
                print(f"🚨 ERROR guardando conexión Telegram en BD: {db_error}")
                traceback.print_exc()
                return jsonify(
                    success=False, 
                    message="El mensaje de prueba se envió, pero NO se pudo guardar la conexión. Contacta al administrador.",
                ), 500
            finally:
                if conn: conn.close()
        else:
            # Si el envío del mensaje a Telegram falla, notificar al frontend
            print(f"❌ Error enviando mensaje a Telegram: {result.get('error')}")
            return jsonify(
                success=False, 
                message=f"No se pudo enviar el mensaje de confirmación a tu Telegram: {result.get('error')}"
            ), 500
            
    except Exception as e:
        print(f"🚨 ERROR en /telegram/connect: {e}")
        traceback.print_exc()
        return jsonify(success=False, message=f"Error interno del servidor: {str(e)}"), 500

@app.route('/admin/notifications/<int:notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    """Elimina una notificación existente."""
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM notifications WHERE id = %s", (notification_id,))
            if cursor.rowcount == 0:
                conn.close()
                return jsonify(success=False, message="Notificación no encontrada."), 404
            conn.commit()
            conn.close()
        socketio.emit('notification_deleted', {'id': notification_id})
        return jsonify(success=True, message="Notificación eliminada.")
    except Exception as e:
        print(f"🚨 ERROR en DELETE /admin/notifications/<id>: {e}")
        return jsonify(success=False, message="Error al eliminar la notificación."), 500

# --- FIN DE LA SECCIÓN DE ADMINISTRACIÓN ---

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

print(f"🔗 Telegram Bot configurado: {TELEGRAM_BOT_TOKEN[:10]}...")

def send_telegram_message(chat_id, message, image_url=None):
    """
    Envía un mensaje a Telegram con imagen opcional
    """
    try:
        print(f"📱 Enviando mensaje a Telegram - Chat ID: {chat_id}")
        print(f"📱 URL API: {TELEGRAM_API_URL}")
        
        if image_url:
            # Enviar imagen con caption
            url = f"{TELEGRAM_API_URL}/sendPhoto"
            data = {
                'chat_id': chat_id,
                'photo': image_url,
                'caption': message,
                'parse_mode': 'HTML'
            }
            print(f"📱 Enviando foto con caption...")
            response = requests.post(url, data=data, timeout=10)
        else:
            # Enviar solo texto
            url = f"{TELEGRAM_API_URL}/sendMessage"
            data = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            print(f"📱 Enviando solo texto...")
            response = requests.post(url, data=data, timeout=10)
        
        print(f"📱 Respuesta HTTP: {response.status_code}")
        print(f"📱 Respuesta contenido: {response.text}")
        
        if response.status_code == 200:
            return {'success': True, 'data': response.json()}
        else:
            return {'success': False, 'error': f'Error HTTP {response.status_code}: {response.text}'}
            
    except Exception as e:
        print(f"🚨 ERROR en send_telegram_message: {e}")
        return {'success': False, 'error': str(e)}



@app.route('/telegram/test', methods=['GET'])
def test_telegram_bot():
    """
    Endpoint para probar si el bot de Telegram está funcionando
    """
    try:
        url = f"{TELEGRAM_API_URL}/getMe"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            bot_info = response.json()
            return jsonify(
                success=True, 
                message="Bot de Telegram funcionando correctamente",
                bot_info=bot_info
            )
        else:
            return jsonify(
                success=False,
                message=f"Error conectando con bot: HTTP {response.status_code}",
                error=response.text
            ), 500
            
    except Exception as e:
        print(f"🚨 ERROR en /telegram/test: {e}")
        return jsonify(success=False, message=f"Error: {str(e)}"), 500

def upload_to_google_drive(file_stream, filename):
    """
    Simulated function to upload a file to Google Drive.
    Returns a dictionary with a simulated file ID.
    """
    print(f" giả vờ tải lên '{filename}' to Google Drive...")
    # In a real implementation, you'd get a real ID from the API response.
    simulated_id = f"gdrive_{uuid.uuid4().hex[:12]}"
    print(f" giả vờ thành công! File ID: {simulated_id}")
    return {"id": simulated_id}

# --- PDF PROCESSING & THUMBNAIL GENERATION ---
def process_pdf_and_get_thumbnail(pdf_bytes):
    """
    Processes a PDF to get page count and a thumbnail of the first page.
    Returns page count and a placeholder URL for the thumbnail.
    """
    try:
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        page_count = len(pdf_document)
        
        # In a real app, you would render the first page and upload the image.
        # For this example, we will use a static placeholder thumbnail.
        thumbnail_url = "https://i.ibb.co/20PQx1J1/imagen-2025-08-19-003736553-removebg-preview.png"
        
        return page_count, thumbnail_url
    except Exception as e:
        print(f"Error processing PDF: {e}")
        return 0, "https://i.ibb.co/20PQx1J1/imagen-2025-08-19-003736553-removebg-preview.png"

# --- NEW DOCUMENT ENDPOINTS ---

@app.route('/documents', methods=['GET'])
def get_documents():
    email = request.args.get('email', '').lower().strip()
    board_id = request.args.get('board_id')

    if not email or not board_id:
        return jsonify(success=False, message="Email y board_id son requeridos"), 400

    try:
        # --- INICIO DE LA CORRECCIÓN ---
        
        # 1. Primero, se verifica si el usuario tiene permiso para ver el tablero.
        #    Esto busca el tablero en todas las bases de datos y revisa la lista de colaboradores.
        board_info = find_board_and_owner_db(board_id)
        if not board_info:
            return jsonify(success=False, message="Tablero no encontrado."), 404

        collaborator_emails = [c.get('email', '').lower().strip() for c in board_info.get('collaborators', [])]
        if email not in collaborator_emails:
            return jsonify(success=False, message="Acceso denegado a este tablero."), 403
        
        # 2. Si tiene permiso, se conecta a la base de datos donde está el tablero
        #    y se obtienen TODOS los documentos de ese tablero, sin filtrar por `user_email`.
        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        if not conn:
            return jsonify(success=False, message=f"No se pudo conectar a la DB del tablero '{owner_db}'."), 500
        
        cursor = conn.cursor()
        # LA CONSULTA SQL AHORA ES MÁS SIMPLE Y CORRECTA
        cursor.execute("SELECT * FROM documents WHERE board_id = %s ORDER BY created_date DESC", (board_id,))
        docs_from_db = [dict(row) for row in cursor.fetchall()]
        conn.close()

        # --- FIN DE LA CORRECCIÓN ---
        
        # El resto de la lógica para procesar las URLs de Cloudinary se mantiene igual.
        processed_docs = []
        for doc in docs_from_db:
            public_id = doc.get('cloudinary_public_id')
            if public_id:
                safe_filename = "".join(c for c in doc['title'] if c.isalnum() or c in (' ', '_', '-')).rstrip()
                signed_url = cloudinary.utils.cloudinary_url(
                    public_id,
                    resource_type="raw",
                    sign_url=True,
                    secure=True,
                    expires_at=int(time.time()) + 3600,
                    flags=f"attachment:{safe_filename}"
                )[0]
                doc['google_drive_file_id'] = signed_url
            processed_docs.append(doc)

        return jsonify(success=True, documents=processed_docs)
    except Exception as e:
        print(f"🚨 ERROR en GET /documents: {e}")
        return jsonify(success=False, message="Error al obtener documentos."), 500
@app.route('/telegram/notify', methods=['POST'])
def send_telegram_notification():
    """
    Envía una notificación a usuarios específicos vía Telegram
    Versión mejorada que soporta los nuevos parámetros del admin panel
    """
    data = request.get_json()
    message = data.get('message')
    target_emails = data.get('target_emails', [])
    image_url = data.get('image_url')
    target_mode = data.get('target_mode', 'specific')
    target_value = data.get('target_value')
    
    if not message:
        return jsonify(success=False, message="Mensaje es requerido"), 400
    
    # Si viene del admin panel, procesar directamente aquí
    if target_mode in ['all', 'database', 'specific']:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            results = []
            
            if target_mode == 'all':
                # Enviar a todos los usuarios conectados
                cursor.execute("""
                    SELECT user_email, chat_id 
                    FROM telegram_connections 
                    WHERE is_active = 1
                """)
                connections = cursor.fetchall()
                
            elif target_mode == 'database':
                # Enviar a usuarios de una base de datos específica
                if target_value == 'Principal':
                    cursor.execute("""
                        SELECT t.user_email, t.chat_id 
                        FROM telegram_connections t
                        JOIN users u ON t.user_email = u.email
                        WHERE t.is_active = 1 AND u.manager_id = 'Principal'
                    """)
                else:
                    cursor.execute("""
                        SELECT t.user_email, t.chat_id 
                        FROM telegram_connections t
                        JOIN users u ON t.user_email = u.email
                        WHERE t.is_active = 1 AND u.manager_id = %s
                    """, (target_value,))
                connections = cursor.fetchall()
                
            elif target_mode == 'specific':
                # Enviar a usuarios específicos
                if not target_emails:
                    return jsonify(success=False, message="No se especificaron emails"), 400
                    
                placeholders = ','.join(['?' for _ in target_emails])
                cursor.execute(f"""
                    SELECT user_email, chat_id 
                    FROM telegram_connections 
                    WHERE is_active = 1 AND user_email IN ({placeholders})
                """, target_emails)
                connections = cursor.fetchall()
            
            # Enviar mensajes
            sent_count = 0
            failed_count = 0
            
            for connection in connections:
                chat_id = connection['chat_id']
                email = connection['user_email']
                
                result = send_telegram_message(chat_id, message, image_url)
                
                if result['success']:
                    sent_count += 1
                    print(f"✅ Mensaje enviado a {email}")
                else:
                    failed_count += 1
                    print(f"❌ Error enviando a {email}: {result['error']}")
                
                results.append({
                    'email': email,
                    'chat_id': chat_id,
                    'success': result['success'],
                    'error': result.get('error')
                })
            
            conn.close()
            
            return jsonify(
                success=True,
                message=f"Proceso completado: {sent_count} enviados, {failed_count} fallidos",
                sent_count=sent_count,
                failed_count=failed_count,
                total_attempts=len(connections),
                results=results[:10]  # Solo los primeros 10 para no sobrecargar
            )
            
        except Exception as e:
            print(f"🚨 ERROR en telegram notify advanced: {e}")
            return jsonify(success=False, message="Error interno del servidor"), 500
    
    # Código original para compatibilidad con otros usos
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        results = []
        
        if target_emails:
            # Enviar a usuarios específicos
            for email in target_emails:
                cursor.execute(
                    "SELECT chat_id FROM telegram_connections WHERE user_email = %s AND is_active = 1",
                    (email,)
                )
                connection = cursor.fetchone()
                
                if connection:
                    chat_id = connection['chat_id']
                    result = send_telegram_message(chat_id, message, image_url)
                    results.append({
                        'email': email,
                        'chat_id': chat_id,
                        'success': result['success'],
                        'error': result.get('error')
                    })
                else:
                    results.append({
                        'email': email,
                        'chat_id': None,
                        'success': False,
                        'error': 'Usuario no conectado a Telegram'
                    })
        else:
            # Enviar a todos los usuarios conectados
            cursor.execute(
                "SELECT user_email, chat_id FROM telegram_connections WHERE is_active = 1"
            )
            connections = cursor.fetchall()
            
            for connection in connections:
                chat_id = connection['chat_id']
                email = connection['user_email']
                result = send_telegram_message(chat_id, message, image_url)
                results.append({
                    'email': email,
                    'chat_id': chat_id,
                    'success': result['success'],
                    'error': result.get('error')
                })
        
        conn.close()
        
        successful_sends = sum(1 for r in results if r['success'])
        total_attempts = len(results)
        
        return jsonify(
            success=True,
            message=f"Notificación enviada a {successful_sends} de {total_attempts} usuarios",
            sent_count=successful_sends,
            total_attempts=total_attempts,
            results=results
        )
        
    except Exception as e:
        print(f"🚨 ERROR en /telegram/notify: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500

# ============================================================================
# PASO 2: CREAR TABLA PARA CONEXIONES DE TELEGRAM
# ============================================================================

def create_telegram_connections_table():
    """
    Crea la tabla para almacenar las conexiones de Telegram si no existe
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telegram_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                chat_id TEXT NOT NULL,
                connected_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                UNIQUE(user_email)
            )
        """)
        
        conn.commit()
        conn.close()
        print("✅ Tabla telegram_connections creada/verificada correctamente")
        
    except Exception as e:
        print(f"🚨 ERROR creando tabla telegram_connections: {e}")




# ############################################################################
# # SECCIÓN 5: ENDPOINTS DE AUTENTICACIÓN (REGISTRO Y LOGIN)                 #
# ############################################################################

@app.route('/register', methods=['POST'])
def register():
    """Registra un nuevo usuario en la base de datos única de PostgreSQL."""
    data = request.get_json()
    required = ['firstName', 'lastName', 'email', 'password', 'confirmPassword', 'manager_id']
    if not all(field in data for field in required):
        return jsonify(success=False, message="Todos los campos son requeridos."), 400

    if data['password'] != data['confirmPassword']:
        return jsonify(success=False, message="Las contraseñas no coinciden."), 400

    # La validación de la contraseña de la DB ya no es necesaria con el nuevo sistema.
    # Nos conectamos directamente a la única base de datos.

    email = data['email'].lower().strip()
    manager_id = data['manager_id'] # Guardamos esto para mantener la estructura

    conn = None
    try:
        with db_lock:
            conn = get_db_connection() # Usamos la conexión única a PostgreSQL
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify(success=False, message="El correo ya está registrado."), 409

            now = datetime.now(timezone.utc).isoformat()

            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password, registration_date, manager_id) VALUES (%s, %s, %s, %s, %s, %s)",
                (data['firstName'], data['lastName'], email, data['password'], now, manager_id)
            )

            default_board_data = {
                "columns": [
                    {"id": "col-1", "title": "Por hacer", "color": "bg-red-200"},
                    {"id": "col-2", "title": "En proceso", "color": "bg-yellow-200"},
                    {"id": "col-3", "title": "Hecho", "color": "bg-green-200"}
                ], "cards": [], "boardOptions": {}
            }
            cursor.execute(
                "INSERT INTO boards (owner_email, name, board_data, created_date, updated_date, category) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (email, "Mi Primer Tablero", json.dumps(default_board_data), now, now, "Personal")
            )
            board_id = cursor.fetchone()['id']

            cursor.execute("INSERT INTO collaborators (board_id, user_email) VALUES (%s, %s)", (board_id, email))

            conn.commit()

        return jsonify(success=True, message="Registro exitoso"), 201

    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en /register: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor durante el registro."), 500
    finally:
        if conn: conn.close()





@app.route('/login', methods=['POST'])
def login():
    """Autentica a un usuario contra la base de datos única de PostgreSQL."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password')
    # manager_id ya no es crucial para la conexión, pero lo mantenemos por consistencia
    manager_id = data.get('manager_id')

    if not all([email, password, manager_id]):
        return jsonify(success=False, message="Email, contraseña y base de datos son requeridos."), 400

    conn = None
    try:
        conn = get_db_connection() # Usamos la conexión única a PostgreSQL
        cursor = conn.cursor()

        # Buscamos al usuario por email y contraseña en la tabla de usuarios
        cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()

        if user:
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (now, user['id']))
            conn.commit()

            user_data = dict(user)
            user_data_to_send = {
                "id": user_data['id'], "firstName": user_data['first_name'],
                "lastName": user_data['last_name'], "email": user_data['email'],
                "access_expires_on": user_data['access_expires_on'],
                "manager_id": user_data['manager_id'], "logo_url": None # Puedes añadir lógica para logos más adelante
            }
            return jsonify(success=True, message="Login exitoso", user=user_data_to_send)
        else:
            return jsonify(success=False, message="Credenciales incorrectas."), 401
    except Exception as e:
        print(f"🚨 ERROR en /login: {e}")
        return jsonify(success=False, message="Error interno del servidor durante el login."), 500
    finally:
        if conn: conn.close()

# ############################################################################
# # SECCIÓN 6: ENDPOINTS DE TABLEROS (BOARDS)                                #
# ############################################################################

def get_all_stickers_from_db():
    """Función auxiliar para obtener todos los stickers."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, category, url FROM stickers")
        stickers = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return stickers
    except Exception as e:
        print(f"Error al cargar stickers: {e}")
        return []


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
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            
            board_columns = template_columns if template_columns and isinstance(template_columns, list) else [
                {"id": "col-1", "title": "Por hacer", "color": "bg-red-200"},
                {"id": "col-2", "title": "En proceso", "color": "bg-yellow-200"},
                {"id": "col-3", "title": "Hecho", "color": "bg-green-200"}
            ]
            default_board_data = {"columns": board_columns, "cards": [], "boardOptions": {}}

            cursor.execute(
                "INSERT INTO boards (owner_email, name, board_data, created_date, updated_date, category) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (email, board_name, json.dumps(default_board_data), now, now, "Personal")
            )
            board_id = cursor.fetchone()['id']
            
            cursor.execute("INSERT INTO collaborators (board_id, user_email) VALUES (%s, %s)", (board_id, email))
            
            conn.commit()
            conn.close()

        return jsonify(success=True, message="Tablero creado", board_id=board_id), 201
    except Exception as e:
        if conn: conn.rollback()
        print(f"🚨 ERROR en POST /boards: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor"), 500




@app.route('/boards/<int:board_id>', methods=['GET'])
def get_single_board(board_id):
    """Obtiene los datos de un tablero específico y verifica permisos."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

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
        try:
            board_to_send['data'] = json.loads(board_to_send['board_data'])
        except:
            board_to_send['data'] = {}
        del board_to_send['board_data'] # No enviar el JSON crudo

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
    """Actualiza los datos de un tablero (columnas y tarjetas)."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    board_data = data.get('boardData')

    if not email or board_data is None:
        return jsonify(success=False, message="Email y boardData son requeridos"), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        if not cursor.fetchone():
            conn.close()
            return jsonify(success=False, message="Acceso denegado, no eres colaborador."), 403

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
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al guardar el tablero."), 500
    finally:
        if conn: conn.close()


@app.route('/boards/<int:board_id>', methods=['DELETE'])
def delete_board(board_id):
    """Elimina un tablero. Solo el propietario puede hacerlo."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verificar si el usuario es el propietario
        cursor.execute("SELECT owner_email FROM boards WHERE id = %s", (board_id,))
        board_owner = cursor.fetchone()

        if not board_owner:
            conn.close()
            return jsonify(success=False, message="Tablero no encontrado."), 404
        
        if board_owner['owner_email'] != email:
            conn.close()
            return jsonify(success=False, message="Solo el propietario puede eliminar el tablero."), 403

        # Eliminar el tablero (ON DELETE CASCADE se encargará del resto)
        cursor.execute("DELETE FROM boards WHERE id = %s", (board_id,))
        conn.commit()
        conn.close()
        
        return jsonify(success=True, message="Tablero eliminado")
    except Exception as e:
        print(f"🚨 ERROR en DELETE /boards/{board_id}: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor"), 500


@app.route('/dashboard-data', methods=['GET'])
def get_dashboard_data():
    """
    Recopila y devuelve estadísticas agregadas de todos los tableros
    de un usuario específico.
    """
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Obtener todos los tableros donde el usuario es colaborador
        cursor.execute('''
            SELECT b.id, b.name, b.board_data FROM boards b
            JOIN collaborators c ON b.id = c.board_id
            WHERE c.user_email = %s
        ''', (email,))
        
        boards = [dict(row) for row in cursor.fetchall()]
        conn.close()

        total_cards = 0
        completed_cards = 0
        overdue_cards = 0
        pending_cards = 0
        overdue_cards_list = []
        
        today = datetime.now(timezone.utc).date()

        for board in boards:
            try:
                board_data = json.loads(board['board_data'])
                cards = board_data.get('cards', [])
                columns = board_data.get('columns', [])
                
                # Asumimos que la última columna es la de "completado"
                done_column_id = columns[-1]['id'] if columns else None

                for card in cards:
                    total_cards += 1
                    is_completed = card.get('isCompleted', False) or (done_column_id and card.get('columnId') == done_column_id)
                    
                    if is_completed:
                        completed_cards += 1
                    else:
                        pending_cards += 1
                        due_date_str = card.get('dueDate')
                        if due_date_str:
                            due_date = datetime.fromisoformat(due_date_str).date()
                            if due_date < today:
                                overdue_cards += 1
                                overdue_cards_list.append({
                                    'title': card.get('title'),
                                    'dueDate': due_date_str,
                                    'boardName': board.get('name')
                                })
            except (json.JSONDecodeError, IndexError):
                continue
        
        # Ordenar tarjetas vencidas por fecha más antigua primero
        overdue_cards_list.sort(key=lambda x: x['dueDate'])

        stats = {
            "totalBoards": len(boards),
            "totalCards": total_cards,
            "completedCards": completed_cards,
            "pendingCards": pending_cards,
            "overdueCards": overdue_cards,
            "efficiency": round((completed_cards / total_cards * 100) if total_cards > 0 else 100, 1),
            "overdueRate": round((overdue_cards / pending_cards * 100) if pending_cards > 0 else 0, 1),
            "overdueCardsList": overdue_cards_list[:10] # Limitar a las 10 más antiguas
        }

        return jsonify(success=True, stats=stats)

    except Exception as e:
        print(f"🚨 ERROR en /dashboard-data: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno al generar estadísticas del dashboard."), 500
# ======== BLOQUE A AÑADIR - FIN ========



# ############################################################################
# # SECCIÓN 7: ENDPOINTS DE COLABORACIÓN Y OPCIONES DE TABLERO               #
# ############################################################################

@app.route('/boards/<int:board_id>/collaborators/update', methods=['PUT'])
def update_collaborator_permission(board_id):
    """Actualiza el nivel de permiso de un colaborador en un tablero."""
    data = request.get_json()
    owner_email = data.get('owner_email', '').lower().strip()
    collaborator_email = data.get('collaborator_email', '').lower().strip()
    new_permission = data.get('permission_level', '').strip()

    if not all([owner_email, collaborator_email, new_permission]):
        return jsonify(success=False, message="Faltan datos para actualizar permisos."), 400
    
    if new_permission not in ['editor', 'viewer']:
        return jsonify(success=False, message="Nivel de permiso no válido."), 400

    try:
        board_info = find_board_and_owner_db(board_id)
        if not board_info:
            return jsonify(success=False, message="Tablero no encontrado."), 404

        if board_info['owner_email'] != owner_email:
            return jsonify(success=False, message="Solo el propietario puede cambiar permisos."), 403
        
        if board_info['owner_email'] == collaborator_email:
            return jsonify(success=False, message="No se puede cambiar el permiso del propietario."), 400

        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        if not conn:
            return jsonify(success=False, message="No se pudo conectar a la base de datos del tablero."), 500

        with db_lock:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE collaborators SET permission_level = %s 
                WHERE board_id = %s AND user_email = %s
            """, (new_permission, board_id, collaborator_email))
            conn.commit()
            
            cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id,))
            collaborators = [{'email': row['user_email'], 'permission_level': row['permission_level']} for row in cursor.fetchall()]
            conn.close()

        return jsonify(success=True, message="Permiso actualizado.", shared_with=collaborators)

    except Exception as e:
        print(f"🚨 ERROR en PUT /collaborators/update: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor."), 500


@app.route('/boards', methods=['GET'])
def get_boards():
    """Obtiene todos los tableros a los que un usuario tiene acceso desde la DB única."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Consulta que une boards y collaborators para encontrar todos los tableros del usuario
        cursor.execute("""
            SELECT b.id, b.owner_email, b.name, b.board_data, b.created_date, b.updated_date, b.category
            FROM boards b
            JOIN collaborators c ON b.id = c.board_id
            WHERE c.user_email = %s
        """, (email,))

        user_boards = [dict(row) for row in cursor.fetchall()]

        for board in user_boards:
            # Obtener la lista completa de colaboradores para cada tablero
            cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board['id'],))
            board['shared_with'] = [{'email': r['user_email'], 'permission_level': r['permission_level']} for r in cursor.fetchall()]

            try:
                board['data'] = json.loads(board['board_data'])
            except:
                board['data'] = {}
            del board['board_data']

        stickers = get_all_stickers_from_db()
        conn.close()
        return jsonify(success=True, boards=user_boards, stickers=stickers)

    except Exception as e:
        print(f"🚨 ERROR en GET /boards: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al obtener tableros."), 500



def find_user_in_any_db(email_to_find):
    """Busca un usuario por email en la base de datos única."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email_to_find,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        print(f"🚨 ERROR en find_user_in_any_db: {e}")
        return None

def find_board_and_owner_db(board_id_to_find):
    """Busca un tablero por su ID en la base de datos única y sus colaboradores."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM boards WHERE id = %s", (board_id_to_find,))
        board_data = cursor.fetchone()
        if not board_data:
            conn.close()
            return None
        
        board_info = dict(board_data)
        cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id_to_find,))
        board_info['collaborators'] = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return board_info
    except Exception as e:
        print(f"🚨 ERROR en find_board_and_owner_db: {e}")
        return None




def check_editor_permission(board_id, user_email):
    """Verifica si un usuario tiene permisos de 'editor' en un tablero."""
    try:
        board_info = find_board_and_owner_db(board_id)
        if not board_info: return False

        if board_info['owner_email'] == user_email: return True

        for collaborator in board_info.get('collaborators', []):
            if collaborator['email'] == user_email and collaborator['permission_level'] == 'editor':
                return True
        return False
    except Exception as e:
        print(f"🚨 ERROR en check_editor_permission: {e}")
        return False


@app.route('/boards/<int:board_id>/share', methods=['POST', 'DELETE'])
def share_board(board_id):
    """Añade o elimina un colaborador de un tablero (versión final y robusta)."""
    data = request.get_json()

    # --- Lógica para AÑADIR un colaborador (POST) ---
    if request.method == 'POST':
        sharer_email = data.get('sharer_email', '').lower().strip()
        recipient_email = data.get('recipient_email', '').lower().strip()
        permission_level = data.get('permission_level', 'viewer')

        if not sharer_email or not recipient_email:
            return jsonify(success=False, message="Emails del que comparte y del receptor son requeridos"), 400
        
        try:
            board_info = find_board_and_owner_db(board_id)
            if not board_info:
                return jsonify(success=False, message="El tablero no fue encontrado."), 404
            
            # --- INICIO DE LA CORRECCIÓN CLAVE ---
            # Se verifica si el usuario que comparte es el propietario O un editor.
            owner_email = board_info.get('owner_email', '').lower().strip()
            is_owner = sharer_email == owner_email
            
            sharer_as_collaborator = next((c for c in board_info.get('collaborators', []) if c.get('email', '').lower().strip() == sharer_email), None)
            is_editor = sharer_as_collaborator and sharer_as_collaborator.get('permission_level') == 'editor'

            if not is_owner and not is_editor:
                return jsonify(success=False, message="No tienes permiso para compartir. Se requiere ser propietario o editor."), 403
            # --- FIN DE LA CORRECCIÓN CLAVE ---

            recipient_info = find_user_in_any_db(recipient_email)
            if not recipient_info:
                return jsonify(success=False, message=f"El usuario '{recipient_email}' no está registrado en Focux."), 404

            owner_db = board_info['found_in_db']
            conn = get_db_connection_for_manager(owner_db)
            if not conn:
                return jsonify(success=False, message=f"Error interno: no se pudo conectar a la DB del tablero '{owner_db}'."), 500

            with db_lock:
                cursor = conn.cursor()
                # Usar INSERT OR REPLACE para añadir nuevos o actualizar existentes (ej. cambiar permiso)
                cursor.execute("""
                    INSERT OR REPLACE INTO collaborators (board_id, user_email, permission_level) 
                    VALUES (?, ?, ?)
                """, (board_id, recipient_email, permission_level))
                conn.commit()
                
                cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id,))
                collaborators = [{'email': row['user_email'], 'permission_level': row['permission_level']} for row in cursor.fetchall()]
                conn.close()

            return jsonify(success=True, message="Tablero compartido", shared_with=collaborators, owner_email=owner_email)

        except Exception as e:
            print(f"🚨 ERROR en POST /share: {e}")
            traceback.print_exc()
            return jsonify(success=False, message="Error interno del servidor al compartir."), 500

    # --- Lógica para ELIMINAR un colaborador (DELETE) ---
    elif request.method == 'DELETE':
        remover_email = data.get('remover_by_email', '').lower().strip()
        email_to_remove = data.get('email_to_remove', '').lower().strip()
        
        if not remover_email or not email_to_remove:
            return jsonify(success=False, message="Faltan datos para eliminar colaborador."), 400

        try:
            board_info = find_board_and_owner_db(board_id)
            if not board_info:
                return jsonify(success=False, message="El tablero no fue encontrado."), 404

            owner_email = board_info['owner_email']
            
            if owner_email != remover_email:
                return jsonify(success=False, message="Solo el propietario puede quitar colaboradores"), 403

            if owner_email == email_to_remove:
                return jsonify(success=False, message="No se puede eliminar al propietario del tablero"), 400

            owner_db = board_info['found_in_db']
            conn = get_db_connection_for_manager(owner_db)
            if not conn:
                 return jsonify(success=False, message=f"Error interno: no se pudo conectar a la DB del tablero '{owner_db}'."), 500
            
            with db_lock:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email_to_remove))
                conn.commit()
                
                cursor.execute("SELECT user_email, permission_level FROM collaborators WHERE board_id = %s", (board_id,))
                collaborators = [{'email': row['user_email'], 'permission_level': row['permission_level']} for row in cursor.fetchall()]
                conn.close()

            return jsonify(success=True, message="Acceso eliminado", shared_with=collaborators, owner_email=owner_email)

        except Exception as e:
            print(f"🚨 ERROR en DELETE /share: {e}")
            traceback.print_exc()
            return jsonify(success=False, message="Error interno del servidor al eliminar acceso."), 500






@app.route('/boards/<int:board_id>/name', methods=['PATCH'])
def update_board_name(board_id):
    """Actualiza solo el nombre de un tablero."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    new_name = data.get('boardName', '').strip()

    if not email or not new_name:
        return jsonify(success=False, message="Email y nuevo nombre son requeridos"), 400

    # --- INICIO DE LA MODIFICACIÓN ---
    if not check_editor_permission(board_id, email):
        return jsonify(success=False, message="Acceso denegado: Se requieren permisos de editor."), 403
    # --- FIN DE LA MODIFICACIÓN ---
    
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT board_id FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
            if not cursor.fetchone():
                conn.close()
                return jsonify(success=False, message="Acceso denegado"), 403

            cursor.execute("UPDATE boards SET name = %s, updated_date = %s WHERE id = %s", (new_name, datetime.now(timezone.utc).isoformat(), board_id))
            conn.commit()
            conn.close()
        
        socketio.emit('board_name_updated', {'board_id': board_id, 'newName': new_name}, room=str(board_id))
        return jsonify(success=True, message="Nombre actualizado")
    except Exception as e:
        print(f"🚨 ERROR en PATCH /boards/<id>/name: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor"), 500






@app.route('/boards/<int:board_id>/category', methods=['PATCH'])
def update_board_category(board_id):
    """Actualiza la categoría de un tablero."""
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    new_category = data.get('category', '').strip()

    if not email or not new_category:
        return jsonify(success=False, message="Email y categoría son requeridos"), 400

    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT board_id FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
            if not cursor.fetchone():
                conn.close()
                return jsonify(success=False, message="Acceso denegado"), 403

            cursor.execute("UPDATE boards SET category = %s, updated_date = %s WHERE id = %s", (new_category, datetime.now(timezone.utc).isoformat(), board_id))
            conn.commit()
            conn.close()
        
        socketio.emit('board_category_updated', {'board_id': board_id, 'newCategory': new_category}, room=str(board_id))
        return jsonify(success=True, message="Categoría actualizada")
    except Exception as e:
        print(f"🚨 ERROR en PATCH /boards/<id>/category: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor"), 500

@app.route('/boards/<int:board_id>/chat', methods=['GET'])
def get_board_chat_history(board_id):
    """Obtiene el historial de chat para un tablero específico."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT board_id FROM collaborators WHERE board_id = %s AND user_email = %s", (board_id, email))
        if not cursor.fetchone():
            conn.close()
            return jsonify(success=False, message="Acceso denegado al chat de este tablero"), 403

        cursor.execute("SELECT * FROM board_chats WHERE board_id = %s ORDER BY timestamp ASC", (board_id,))
        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify(success=True, messages=messages)
    except Exception as e:
        print(f"🚨 ERROR en GET /boards/{board_id}/chat: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al cargar el historial del chat."), 500

@app.route('/boards/<int:source_board_id>/move-card', methods=['POST'])
def move_card_to_board(source_board_id):
    """Mueve una tarjeta de un tablero a otro."""
    data = request.get_json()
    email = request.args.get('email', '').lower().strip()
    card_id = data.get('cardId')
    target_board_id = data.get('targetBoardId')
    target_column_id = data.get('targetColumnId')

    if not all([email, card_id, target_board_id, target_column_id]):
        return jsonify(success=False, message="Faltan datos para mover la tarjeta."), 400

    card_to_move = None
    source_data_for_socket = None
    target_data_for_socket = None

    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT board_id FROM collaborators WHERE board_id = %s AND user_email = %s", (source_board_id, email))
            if not cursor.fetchone():
                conn.close()
                return jsonify(success=False, message="No tienes permiso en el tablero de origen."), 403
            
            cursor.execute("SELECT board_id FROM collaborators WHERE board_id = %s AND user_email = %s", (target_board_id, email))
            if not cursor.fetchone():
                conn.close()
                return jsonify(success=False, message="No tienes permiso en el tablero de destino."), 403

            cursor.execute("SELECT board_data FROM boards WHERE id = %s", (source_board_id,))
            source_board_row = cursor.fetchone()
            if not source_board_row:
                conn.close()
                return jsonify(success=False, message="Tablero de origen no encontrado."), 404

            source_data = json.loads(source_board_row['board_data'])
            card_found = False
            for i, card in enumerate(source_data.get('cards', [])):
                if card.get('id') == card_id:
                    card_to_move = source_data['cards'].pop(i)
                    card_found = True
                    break
            
            if not card_found:
                conn.close()
                return jsonify(success=False, message="Tarjeta no encontrada en el tablero de origen."), 404

            source_data_for_socket = source_data
            cursor.execute("UPDATE boards SET board_data = %s, updated_date = %s WHERE id = %s", 
                           (json.dumps(source_data), datetime.now(timezone.utc).isoformat(), source_board_id))

            cursor.execute("SELECT board_data FROM boards WHERE id = %s", (target_board_id,))
            target_board_row = cursor.fetchone()
            if not target_board_row:
                conn.rollback()
                conn.close()
                return jsonify(success=False, message="Tablero de destino no encontrado."), 404

            target_data = json.loads(target_board_row['board_data'])
            card_to_move['columnId'] = target_column_id
            card_to_move['order'] = time.time()
            if 'cards' not in target_data:
                target_data['cards'] = []
            target_data['cards'].append(card_to_move)
            
            target_data_for_socket = target_data
            cursor.execute("UPDATE boards SET board_data = %s, updated_date = %s WHERE id = %s", 
                           (json.dumps(target_data), datetime.now(timezone.utc).isoformat(), target_board_id))

            conn.commit()
            conn.close()
        
        socketio.emit('board_was_updated', {'board_id': source_board_id, 'boardData': source_data_for_socket}, room=str(source_board_id))
        socketio.emit('board_was_updated', {'board_id': target_board_id, 'boardData': target_data_for_socket}, room=str(target_board_id))
        
        return jsonify(success=True, message="Tarjeta movida exitosamente.")
    except Exception as e:
        print(f"🚨 ERROR en POST /move-card: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al mover la tarjeta."), 500



@app.route('/notes', methods=['GET', 'POST'])
def handle_notes():
    if request.method == 'GET':
        email = request.args.get('email', '').lower().strip()
        board_id = request.args.get('board_id')
        if not email or not board_id:
            return jsonify(success=False, message="Email y board_id son requeridos"), 400

        try:
            # 1. Encontrar el tablero y verificar el acceso del usuario
            board_info = find_board_and_owner_db(board_id)
            if not board_info:
                return jsonify(success=False, message="Tablero no encontrado."), 404

            collaborator_emails = [c.get('email', '').lower().strip() for c in board_info.get('collaborators', [])]
            if email not in collaborator_emails:
                return jsonify(success=False, message="Acceso denegado a las notas de este tablero."), 403

            # 2. Conectar a la base de datos correcta donde reside el tablero
            owner_db = board_info['found_in_db']
            conn = get_db_connection_for_manager(owner_db)
            if not conn:
                return jsonify(success=False, message=f"No se pudo conectar a la base de datos del tablero '{owner_db}'."), 500

            # 3. CORRECCIÓN: Obtener TODAS las notas del tablero (sin filtrar por email)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM notes WHERE board_id = %s ORDER BY updated_date DESC", (board_id,))
            notes = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify(success=True, notes=notes)

        except Exception as e:
            print(f"🚨 ERROR en GET /notes: {e}")
            traceback.print_exc()
            return jsonify(success=False, message="Error interno al obtener notas."), 500

    # La lógica POST se mejora para asegurar que escribe en la DB correcta
    if request.method == 'POST':
        data = request.get_json()
        email, board_id = data.get('email', '').lower().strip(), data.get('board_id')
        if not email or not board_id: return jsonify(success=False, message="Email y board_id son requeridos"), 400
        
        board_info = find_board_and_owner_db(board_id)
        if not board_info:
            return jsonify(success=False, message="Tablero no encontrado para crear la nota."), 404
        
        owner_db = board_info['found_in_db']
        conn = get_db_connection_for_manager(owner_db)
        if not conn:
            return jsonify(success=False, message="No se pudo conectar a la base de datos para guardar la nota."), 500

        try:
            with db_lock:
                cursor = conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "INSERT INTO notes (board_id, user_email, content, color, created_date, updated_date) VALUES (?, ?, ?, ?, ?, ?)",
                    (board_id, email, data.get('content', ''), data.get('color', 'note-yellow'), now, now)
                )
                note_id = cursor.lastrowid
                conn.commit()
                cursor.execute("SELECT * FROM notes WHERE id = %s", (note_id,))
                new_note = dict(cursor.fetchone())
                conn.close()
            socketio.emit('note_created', {'board_id': int(board_id), 'note': new_note}, room=str(board_id))
            return jsonify(success=True, note=new_note), 201
        except Exception as e: 
            if conn: conn.close()
            print(f"🚨 ERROR en POST /notes: {e}")
            return jsonify(success=False, message="Error al crear la nota."), 500


@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
def handle_single_note(note_id):
    if request.method == 'PUT':
        data = request.get_json()
        email, content, color = data.get('email', '').lower().strip(), data.get('content'), data.get('color')
        if not email or (content is None and color is None): return jsonify(success=False, message="Se requiere email y contenido o color."), 400
        try:
            with db_lock:
                conn = get_db_connection()
                cursor = conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute("UPDATE notes SET content = %s, color = %s, updated_date = %s WHERE id = %s AND user_email = %s", (content, color, now, note_id, email))
                conn.commit()
                if cursor.rowcount == 0:
                    conn.close()
                    return jsonify(success=False, message="Nota no encontrada o sin permiso."), 404
                cursor.execute("SELECT * FROM notes WHERE id = %s", (note_id,))
                updated_note = dict(cursor.fetchone())
                board_id = updated_note['board_id']
                conn.close()
            socketio.emit('note_updated', {'board_id': board_id, 'note': updated_note}, room=str(board_id))
            return jsonify(success=True, note=updated_note)
        except Exception as e: return jsonify(success=False, message="Error al actualizar la nota."), 500
    if request.method == 'DELETE':
        email = request.args.get('email', '').lower().strip()
        if not email: return jsonify(success=False, message="Email es requerido"), 400
        try:
            with db_lock:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT board_id FROM notes WHERE id = %s AND user_email = %s", (note_id, email))
                note_info = cursor.fetchone()
                if not note_info:
                    conn.close()
                    return jsonify(success=False, message="Nota no encontrada o sin permiso."), 404
                board_id = note_info['board_id']
                cursor.execute("DELETE FROM notes WHERE id = %s AND user_email = %s", (note_id, email))
                conn.commit()
                conn.close()
            socketio.emit('note_deleted', {'board_id': board_id, 'note_id': note_id}, room=str(board_id))
            return jsonify(success=True, message="Nota eliminada")
        except Exception as e: return jsonify(success=False, message="Error al eliminar la nota."), 500

@app.route('/chat/ask', methods=['POST'])
def ask_assistant():
    if not genai: return jsonify(success=False, message="La API de IA no está configurada en el servidor."), 503
    data = request.get_json()
    assistant_id = data.get('assistant_id')
    user_message = data.get('message')
    user_email = data.get('user_email')
    # Nuevo: Aceptar el historial de la conversación
    history = data.get('history', [])

    if not all([assistant_id, user_message, user_email]):
        return jsonify(success=False, message="Faltan datos en la solicitud."), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT prompt, knowledge_base FROM assistants WHERE id = %s", (assistant_id,))
        assistant = cursor.fetchone()
        conn.close()

        if not assistant:
            return jsonify(success=False, message="Asistente no encontrado."), 404

        # Nuevo: Construir el historial de la conversación para el prompt
        conversation_history = ""
        # Limitar el historial a los últimos 6 mensajes para no exceder el límite de tokens
        for msg in history[-6:]:
            role = "Usuario" if msg['sender'] == 'user' else "Asistente"
            conversation_history += f"{role}: {msg['content']}\n"

        # Nuevo: Crear un prompt final que incluye el historial
        final_prompt = (
            f"{assistant['prompt']}\n\n"
            f"**Base de Conocimiento Adicional (si es relevante):**\n{assistant['knowledge_base']}\n\n"
            f"**Conversación Reciente:**\n{conversation_history}"
            f"**Pregunta del Usuario:**\n{user_message}\n\n"
            f"**Instrucción Adicional:** Responde de forma concisa y directa a la última pregunta del usuario, basándote en la conversación reciente."
        )

        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(final_prompt)
        ai_reply = response.text.strip()
        
        return jsonify(success=True, reply=ai_reply)
    except Exception as e:
        print(f"🚨 ERROR en /chat/ask: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error al procesar la solicitud con el asistente de IA."), 500

@app.route('/ai/enhance-text', methods=['POST'])
def enhance_text():
    if not genai:
        return jsonify(success=False, message="La API de IA no está configurada en el servidor."), 500

    data = request.get_json()
    text = data.get('text')
    mode = data.get('mode', 'improve')

    if not text:
        return jsonify(success=False, message="No se proporcionó texto."), 400

    try:
        model = genai.GenerativeModel('gemini-2.0-flash') # Se recomienda usar gemini-1.5-flash para esta tarea

        # --- INICIO DE LA CORRECCIÓN: PROMPTS ESPECÍFICOS Y RESTRICTIVOS ---

        # Se definen instrucciones muy claras para cada modo, prohibiendo explícitamente
        # cualquier texto adicional, explicaciones o formato markdown.
        prompts = {
            'improve': (
                "Reformula el siguiente texto para que sea más claro, conciso y profesional. "
                "Devuelve únicamente el texto mejorado. No añadas introducciones como 'Aquí tienes una versión mejorada' "
                "ni explicaciones sobre los cambios. No uses markdown, negritas ni cursivas. El texto a reformular es:\n\n"
                f"'{text}'"
            ),
            'correct_spelling_only': (
                "Corrige únicamente los errores de ortografía y puntuación (tildes, comas, puntos, mayúsculas) del siguiente texto. "
                "No cambies palabras, no reformules frases ni alteres el significado. "
                "Devuelve exclusivamente el texto corregido, sin ningún texto adicional, introducción o explicación. "
                "No utilices markdown, negritas ni cursivas. El texto es:\n\n"
                f"'{text}'"
            )
        }
        
        # Se selecciona el prompt según el 'mode' enviado desde el frontend.
        # Si el modo no coincide, por defecto se usará 'improve'.
        prompt = prompts.get(mode, prompts['improve'])
        
        # --- FIN DE LA CORRECCIÓN ---

        response = model.generate_content(prompt)
        
        # Limpieza adicional para remover comillas que la IA a veces añade
        enhanced_text = response.text.strip()
        if enhanced_text.startswith('"') and enhanced_text.endswith('"'):
            enhanced_text = enhanced_text[1:-1]
            
        return jsonify(success=True, enhancedText=enhanced_text)

    except Exception as e:
        print(f"🚨 ERROR en /ai/enhance-text: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error con el servicio de IA al procesar el texto."), 500



@app.route('/ai/writing-suggestions', methods=['POST'])
def get_writing_suggestions():
    if not genai: return jsonify(success=False, message="La API de IA no está configurada."), 500
    data = request.get_json()
    text = data.get('text')
    if not text: return jsonify(success=False, message="No se proporcionó texto."), 400
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = f"""Genera 3 versiones alternativas para el siguiente texto, mejorando claridad y profesionalismo.
        Formatea tu respuesta como un array JSON de strings, sin texto adicional.
        Texto original: '{text}'"""
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
        return jsonify(success=True, suggestions=json.loads(cleaned_response))
    except Exception as e: return jsonify(success=False, message="La IA devolvió un formato inesperado.")


# ############################################################################
# # SECCIÓN 8: LÓGICA DE CHAT Y SOCKET.IO                                    #
# ############################################################################

@socketio.on('connect')
def handle_connect(): pass

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    board_id = sid_to_room_map.pop(sid, None)
    if board_id and sid in active_sids_by_room.get(board_id, set()):
        active_sids_by_room[board_id].remove(sid)
        if not active_sids_by_room[board_id]: del active_sids_by_room[board_id]
        unique_emails = {sid_to_user_map.get(s) for s in active_sids_by_room.get(board_id, set()) if s in sid_to_user_map}
        socketio.emit('collaborator_count_updated', {'count': len(unique_emails)}, room=board_id)
    email = sid_to_user_map.pop(sid, None)
    if email and sid in user_to_sids.get(email, set()):
        user_to_sids[email].discard(sid)
        if not user_to_sids[email]: del user_to_sids[email]

@socketio.on('join_board')
def handle_join_board(data):
    board_id = str(data['board_id'])
    email = data.get('email', 'anonymous').lower().strip()
    join_room(board_id)
    sid_to_room_map[request.sid] = board_id
    sid_to_user_map[request.sid] = email
    active_sids_by_room[board_id].add(request.sid)
    if email != 'anonymous':
        join_room(email)
        user_to_sids[email].add(request.sid)
    sids_in_room = active_sids_by_room.get(board_id, set())
    unique_emails = {sid_to_user_map.get(sid) for sid in sids_in_room if sid in sid_to_user_map}
    socketio.emit('collaborator_count_updated', {'count': len(unique_emails)}, room=board_id)

@socketio.on('new_chat_message')
def handle_new_chat_message(data):
    board_id, email, message = data.get('board_id'), data.get('user_email'), data.get('message')
    if not all([board_id, email, message]): return
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO board_chats (board_id, user_email, user_name, message, timestamp) VALUES (?, ?, ?, ?, ?)",
                (board_id, email, data.get('user_name'), message, now)
            )
            conn.commit()
            conn.close()
        payload = {**data, 'timestamp': now}
        socketio.emit('chat_message_received', payload, room=str(board_id))
    except Exception as e:
        print(f"🚨 ERROR en socket 'new_chat_message': {e}")

@socketio.on('global_chat_list_conversations')
def handle_list_conversations(data):
    email = data.get('email', '').lower().strip()
    if not email: return
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM conversations WHERE participants_json LIKE %s", (f'%"{email}"%',))
        conversations = [dict(row) for row in cursor.fetchall()]
        enriched_conversations = []
        for conv in conversations:
            participants = json.loads(conv['participants_json'])
            peer_email = next((p for p in participants if p.lower().strip() != email), None)
            if not peer_email: continue
            cursor.execute("SELECT first_name, last_name FROM users WHERE email = %s", (peer_email,))
            peer_user = cursor.fetchone()
            peer_name = f"{peer_user['first_name']} {peer_user['last_name']}" if peer_user else peer_email
            cursor.execute("SELECT COUNT(id) as unread_count FROM direct_messages WHERE conv_id = ? AND receiver_email = ? AND is_read = 0", (conv['id'], email))
            unread_count = cursor.fetchone()['unread_count']
            enriched_conversations.append({
                "conv_id": conv['id'], "peer_email": peer_email, "peer_name": peer_name,
                "last_ts": conv['last_ts'], "unread_count": unread_count
            })
        conn.close()
        enriched_conversations.sort(key=lambda x: x.get('last_ts') or '', reverse=True)
        emit('global_chat_conversations', {'conversations': enriched_conversations})
    except Exception as e:
        print(f"🚨 ERROR en 'global_chat_list_conversations': {e}")

@socketio.on('global_chat_start')
def handle_start_chat(data):
    my_email = data.get('email', '').lower().strip()
    partner_email = data.get('partner_email', '').lower().strip()
    
    if not my_email or not partner_email:
        return

    try:
        conv_id = '__'.join(sorted([my_email, partner_email]))
        
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Asegurarse de que la conversación exista
            cursor.execute("SELECT id FROM conversations WHERE id = %s", (conv_id,))
            if not cursor.fetchone():
                participants_json = json.dumps([my_email, partner_email])
                cursor.execute("INSERT INTO conversations (id, participants_json, last_ts) VALUES (?, ?, ?)",
                               (conv_id, participants_json, datetime.now(timezone.utc).isoformat()))
                conn.commit()

            # --- INICIO DE LA CORRECCIÓN ---
            # 1. Buscar el nombre del compañero de chat en la tabla de usuarios
            cursor.execute("SELECT first_name, last_name FROM users WHERE email = %s", (partner_email,))
            peer_user = cursor.fetchone()
            peer_name = f"{peer_user['first_name']} {peer_user['last_name']}" if peer_user else partner_email
            # --- FIN DE LA CORRECCIÓN ---

            # Obtener el historial de mensajes
            cursor.execute("SELECT * FROM direct_messages WHERE conv_id = %s ORDER BY ts ASC", (conv_id,))
            messages = [dict(row) for row in cursor.fetchall()]
            conn.close()

        # Enviar el historial junto con los datos del compañero de chat (incluyendo el nombre)
        emit('global_chat_history', {
            'conv_id': conv_id,
            'peer_email': partner_email,
            'peer_name': peer_name,  # <--- DATO AÑADIDO Y CORREGIDO
            'messages': messages
        })

    except Exception as e:
        print(f"🚨 ERROR en 'global_chat_start': {e}")
        traceback.print_exc()


@socketio.on('mark_general_chat_read')
def handle_mark_read(data):
    conv_id, user_email = data.get('conv_id'), data.get('user_email')
    if not conv_id or not user_email: return
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE direct_messages SET is_read = 1 WHERE conv_id = %s AND receiver_email = %s", (conv_id, user_email))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"🚨 ERROR en 'mark_general_chat_read': {e}")

@socketio.on('global_chat_send')
def handle_global_chat_send(data):
    conv_id, sender_email, text = data.get("conv_id"), data.get("sender_email", "").lower().strip(), data.get("text", "").strip()
    if not all([conv_id, sender_email, text]): return
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT participants_json FROM conversations WHERE id = %s", (conv_id,))
            row = cursor.fetchone()
            if not row: conn.close(); return
            participants = json.loads(row['participants_json'])
            receiver_email = next((p for p in participants if p.lower().strip() != sender_email), None)
            if not receiver_email: conn.close(); return
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO direct_messages (conv_id, ts, sender_email, receiver_email, text, is_read) VALUES (?, ?, ?, ?, ?, ?)",
                (conv_id, now, sender_email, receiver_email, text, 0)
            )
            cursor.execute("UPDATE conversations SET last_ts = %s WHERE id = %s", (now, conv_id))
            conn.commit()
            conn.close()
        payload = {"conv_id": conv_id, "sender_email": sender_email, "receiver_email": receiver_email, "text": text, "ts": now}
        if receiver_email: socketio.emit('global_chat_new_message', payload, room=receiver_email)
        socketio.emit('global_chat_new_message', payload, room=sender_email)
    except Exception as e:
        print(f"🚨 ERROR en socket 'global_chat_send': {e}")

# ############################################################################
# # SECCIÓN 9: RUTAS DE USUARIO Y OTRAS                                      #
# ############################################################################

@app.route('/users/directory', methods=['GET'])
def get_user_directory():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email, first_name, last_name FROM users ORDER BY first_name ASC")
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, users=users)
    except Exception as e:
        print(f"🚨 ERROR en GET /users/directory: {e}")
        return jsonify(success=False, message="Error interno del servidor al obtener el directorio de usuarios."), 500

@app.route('/stickers', methods=['GET'])
def get_stickers_route():
    stickers = get_all_stickers_from_db()
    return jsonify(success=True, stickers=stickers)

@socketio.on('get_collaborator_status')
def get_collaborator_status(data):
    board_id = data.get('board_id')
    sid = request.sid
    if not board_id:
        return

    try:
        # --- INICIO DE LA CORRECCIÓN ---
        # 1. Encontrar el tablero y su base de datos de origen
        board_info = find_board_and_owner_db(board_id)
        if not board_info:
            print(f"⚠️ No se encontró el tablero con ID {board_id} para obtener estado de colaboradores.")
            emit('collaborator_status_updated', {'collaborators': []}, room=sid)
            return
        
        # 2. Obtener los emails de los colaboradores desde la información del tablero
        collaborator_emails = board_info.get('collaborators', [])
        
        all_collaborators_details = []
        # 3. Obtener los detalles (nombre, etc.) de cada colaborador buscándolos en el sistema
        for email in collaborator_emails:
            user_details = find_user_in_any_db(email)
            if user_details:
                all_collaborators_details.append({
                    "email": user_details.get('email'),
                    "first_name": user_details.get('first_name'),
                    "last_name": user_details.get('last_name')
                })
        # --- FIN DE LA CORRECCIÓN ---

        sids_in_room = active_sids_by_room.get(str(board_id), set())
        online_emails = {sid_to_user_map.get(s) for s in sids_in_room if s in sid_to_user_map}

        status_list = []
        for user in all_collaborators_details:
            email = user['email']
            status_list.append({
                'name': f"{user['first_name']} {user['last_name']}",
                'email': email,
                'status': 'online' if email in online_emails else 'offline'
            })
            
        emit('collaborator_status_updated', {'collaborators': status_list}, room=sid)

    except Exception as e:
        print(f"🚨 ERROR en 'get_collaborator_status': {e}")
        traceback.print_exc()

@app.route('/assistants', methods=['GET'])
def get_assistants_route():
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.* FROM assistants a
            LEFT JOIN assistant_sharing s ON a.id = s.assistant_id
            WHERE a.is_public = 1 OR s.user_email = %s
        """, (email,))
        assistants_raw = [dict(row) for row in cursor.fetchall()]
        for assistant in assistants_raw:
            cursor.execute("SELECT user_email FROM assistant_sharing WHERE assistant_id = %s", (assistant['id'],))
            assistant['shared_with'] = [row['user_email'] for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, assistants=assistants_raw)
    except Exception as e:
        print(f"🚨 ERROR en GET /assistants: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500

@app.route('/notifications/pending', methods=['GET'])
def get_pending_notifications():
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT n.* FROM notifications n
            LEFT JOIN notification_views v ON n.id = v.notification_id AND v.user_email = %s
            WHERE v.user_email IS NULL
            ORDER BY n.timestamp DESC
        """, (email,))
        notifications = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, notifications=notifications)
    except Exception as e:
        print(f"🚨 ERROR en GET /notifications/pending: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500
        
# --- INICIO DE CORRECCIÓN: RUTA PARA MARCAR NOTIFICACIONES COMO VISTAS ---
@app.route('/notifications/viewed', methods=['POST'])
def mark_notifications_as_viewed():
    """
    Registra que un usuario ha visto todas sus notificaciones pendientes.
    Esta ruta es llamada desde el tablero cuando el usuario abre el dropdown.
    """
    data = request.get_json()
    email = data.get('email', '').lower().strip()

    if not email:
        return jsonify(success=False, message="Email es requerido."), 400

    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()

            # 1. Encontrar todas las notificaciones que este usuario aún no ha visto.
            cursor.execute("""
                SELECT n.id FROM notifications n
                LEFT JOIN notification_views v ON n.id = v.notification_id AND v.user_email = %s
                WHERE v.user_email IS NULL
            """, (email,))
            
            unread_notifications = cursor.fetchall()

            if not unread_notifications:
                conn.close()
                return jsonify(success=True, message="No hay notificaciones nuevas que marcar como vistas.")

            # 2. Preparar los datos para la inserción masiva.
            views_to_insert = [(row['id'], email) for row in unread_notifications]

            # 3. Insertar todas las nuevas vistas en la tabla notification_views.
            # Se usa 'INSERT OR IGNORE' para prevenir errores si la petición se duplicara.
            cursor.executemany(
                "INSERT OR IGNORE INTO notification_views (notification_id, user_email) VALUES (?, ?)",
                views_to_insert
            )

            conn.commit()
            conn.close()
        
        return jsonify(success=True, message=f"{len(views_to_insert)} notificaciones marcadas como vistas.")

    except Exception as e:
        print(f"🚨 ERROR en POST /notifications/viewed: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al marcar notificaciones."), 500
# --- FIN DE CORRECCIÓN ---

@app.route('/user/change-password', methods=['POST'])
def change_password():
    """
    Permite a un usuario cambiar su propia contraseña.
    """
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not all([email, current_password, new_password]):
        return jsonify(success=False, message="Todos los campos son requeridos."), 400

    try:
        # 1. Encontrar en qué base de datos está el usuario
        user_info = find_user_in_any_db(email)
        if not user_info:
            return jsonify(success=False, message="Usuario no encontrado."), 404
        
        db_name = user_info['found_in_db']
        conn = get_db_connection_for_manager(db_name)
        if not conn:
            return jsonify(success=False, message="No se pudo conectar a la base de datos del usuario."), 500

        with db_lock:
            cursor = conn.cursor()
            
            # 2. Verificar la contraseña actual
            cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
            user_row = cursor.fetchone()
            
            if not user_row or user_row['password'] != current_password:
                conn.close()
                return jsonify(success=False, message="La contraseña actual es incorrecta."), 403

            # 3. Actualizar a la nueva contraseña
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (new_password, email))
            conn.commit()
            conn.close()

        return jsonify(success=True, message="Contraseña actualizada correctamente.")

    except Exception as e:
        print(f"🚨 ERROR en /user/change-password: {e}")
        traceback.print_exc()
        return jsonify(success=False, message="Error interno del servidor al cambiar la contraseña."), 500


@app.route('/database-background', methods=['GET'])
def get_database_background():
    """
    Obtiene la URL del fondo para una base de datos específica desde la configuración maestra.
    """
    manager_id = request.args.get('manager_id')
    if not manager_id:
        return jsonify(success=False, message="Manager ID es requerido"), 400

    try:
        master_conn = psycopg2.connect(MASTER_DB)
        master_conn.row_factory = psycopg2.Row
        cursor = master_conn.cursor()
        cursor.execute("SELECT background_url FROM database_settings WHERE name = %s", (manager_id,))
        setting = cursor.fetchone()
        master_conn.close()

        background_url = setting['background_url'] if setting else None
        return jsonify(success=True, backgroundUrl=background_url)

    except Exception as e:
        print(f"🚨 ERROR en /database-background: {e}")
        return jsonify(success=False, message="Error interno al buscar fondo.")

@app.route('/admin/database/background', methods=['POST'])
def set_database_background():
    """Guarda la URL del fondo para una base de datos específica."""
    data = request.get_json()
    db_name = data.get('db_name')
    background_url = data.get('background_url')

    if not db_name:
        return jsonify(success=False, message="El nombre de la base de datos es requerido."), 400

    try:
        with db_lock:
            master_conn = psycopg2.connect(MASTER_DB)
            master_cursor = master_conn.cursor()
            # Usamos INSERT OR REPLACE para crear o actualizar el registro fácilmente.
            master_cursor.execute(
                "INSERT OR REPLACE INTO database_settings (name, background_url) VALUES (?, ?)",
                (db_name, background_url)
            )
            master_conn.commit()
            master_conn.close()
        return jsonify(success=True, message="Fondo de la base de datos actualizado correctamente.")
    except Exception as e:
        print(f"🚨 ERROR en /admin/database/background: {e}")
        return jsonify(success=False, message="Error interno al guardar el fondo."), 500

@app.route('/direct-chats/partners', methods=['GET'])
def get_chat_partners():
    email = request.args.get('me', '').lower().strip()
    if not email:
        return jsonify(success=False, message="Email es requerido"), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT
                CASE
                    WHEN sender_email = %s THEN receiver_email
                    ELSE sender_email
                END as partner_email
            FROM direct_messages
            WHERE sender_email = %s OR receiver_email = %s
        """, (email, email, email))
        partners = [row['partner_email'] for row in cursor.fetchall()]
        conn.close()
        return jsonify(success=True, partners=partners)
    except Exception as e:
        print(f"🚨 ERROR en GET /direct-chats/partners: {e}")
        return jsonify(success=False, message="Error interno del servidor"), 500

# ############################################################################
# # SECCIÓN 10: INICIALIZACIÓN Y EJECUCIÓN DEL SERVIDOR                      #
# ############################################################################

try:
    print("🚀 Inicializando esquema de la base de datos PostgreSQL...")
    init_db()  # Llama a la función que crea todas las tablas.
    print("✅ Esquema de base de datos verificado.")
except Exception as e:
    print(f"🚨 ERROR CRÍTICO DURANTE LA INICIALIZACIÓN DE LA BASE DE DATOS: {e}")

# Este bloque es ignorado por Render, solo sirve para pruebas locales.
if __name__ == '__main__':
    print("🚀 Iniciando servidor de desarrollo local...")
    socketio.run(app, host='0.0.0.0', port=8080)