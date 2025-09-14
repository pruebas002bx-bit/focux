import re

# --- Configuración ---
INPUT_FILE = 'app.py'
OUTPUT_FILE = 'app_postgres.py'

def convert_sql_placeholders(file_content):
    """
    Reemplaza los marcadores de posición de SQLite (?) por los de PostgreSQL (%s)
    de una manera más segura, enfocándose en las llamadas a execute().
    
    Args:
        file_content (str): El contenido completo del archivo Python.
        
    Returns:
        tuple: (contenido_modificado, numero_de_cambios)
    """
    # Expresión regular para encontrar las llamadas a cursor.execute()
    # Captura el contenido entre los primeros paréntesis de la función.
    # re.DOTALL (o la bandera `s`) permite que '.' coincida con saltos de línea,
    # crucial para consultas multilínea.
    pattern = re.compile(r"(\.execute\s*\()([^)]+)(\))", re.DOTALL)
    
    cambios = 0
    
    def replacer(match):
        nonlocal cambios
        # match.group(1) es ".execute("
        # match.group(2) es el contenido: "'SELECT * FROM ...', (params,)"
        # match.group(3) es ")"
        
        content_inside_parentheses = match.group(2)
        
        # Realiza el reemplazo solo dentro del contenido capturado
        if '?' in content_inside_parentheses:
            cambios += content_inside_parentheses.count('?')
            modified_content = content_inside_parentheses.replace('?', '%s')
            # Reconstruye la llamada a la función
            return f"{match.group(1)}{modified_content}{match.group(3)}"
        
        # Si no hay '?', devuelve el original sin cambios
        return match.group(0)

    # Usa re.sub con la función replacer para aplicar los cambios
    modified_code = re.sub(pattern, replacer, file_content)
    
    return modified_code, cambios

def main():
    """
    Función principal que lee, convierte y escribe el archivo.
    """
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            original_content = f.read()
            
        print(f"🔄 Analizando el archivo '{INPUT_FILE}'...")
        
        converted_content, changes_count = convert_sql_placeholders(original_content)
        
        if changes_count > 0:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(converted_content)
            
            print("\n" + "="*50)
            print("✅ ¡Conversión completada exitosamente!")
            print(f"   - Se han realizado {changes_count} reemplazos de '?' por '%s'.")
            print(f"   - El archivo modificado ha sido guardado como '{OUTPUT_FILE}'.")
            print(f"   - El archivo original '{INPUT_FILE}' no ha sido modificado.")
            print("="*50)
            print("\n👉 **Siguiente paso:** Reemplaza el contenido de tu `app.py` original con el de `app_postgres.py` y continúa con los demás pasos de la migración.")
        else:
            print("\n" + "="*50)
            print("🟢 No se encontraron marcadores de posición '?' para reemplazar.")
            print(f"   El archivo '{INPUT_FILE}' ya parece estar listo o no contiene consultas SQL con este formato.")
            print("="*50)

    except FileNotFoundError:
        print(f"\n❌ **Error:** No se encontró el archivo '{INPUT_FILE}'.")
        print("   Asegúrate de que este script esté en la misma carpeta que tu aplicación Flask.")
    except Exception as e:
        print(f"\n❌ **Error inesperado:** Ocurrió un problema durante la conversión.")
        print(f"   Detalle: {e}")

if __name__ == "__main__":
    main()