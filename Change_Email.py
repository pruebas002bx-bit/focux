import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from ttkthemes import ThemedTk

class TextReplacerApp:
    """
    Una aplicación de escritorio para buscar y reemplazar texto en archivos .html y .py
    y opcionalmente cambiar una contraseña de usuario local de Windows.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Buscador y Reemplazador de Texto v3.0")
        self.root.geometry("700x800")
        self.root.resizable(False, False)

        # Variables para almacenar el estado
        self.file_vars = {}
        self.find_text_var = tk.StringVar()
        self.replace_text_var = tk.StringVar()
        self.search_path_var = tk.StringVar()
        self.current_search_path = os.path.dirname(os.path.abspath(__file__))
        
        # Variables para la nueva funcionalidad de servidor
        self.run_server_cmd_var = tk.BooleanVar(value=False)
        self.new_key_var = tk.StringVar()

        self.create_widgets()
        
        self.search_path_var.set(f"Carpeta actual: {self.current_search_path}")
        self.scan_files(self.current_search_path)

    def create_widgets(self):
        """Crea y organiza todos los widgets en la ventana principal."""
        main_frame = ttk.Frame(self.root, padding="15 15 15 15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Paso 1: Ingresar textos ---
        input_frame = ttk.LabelFrame(main_frame, text="Paso 1: Ingresa los textos", padding="10")
        input_frame.pack(fill=tk.X, expand=True, pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="Texto a buscar:").grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        ttk.Entry(input_frame, textvariable=self.find_text_var, width=60).grid(row=0, column=1, pady=5, sticky="ew")

        ttk.Label(input_frame, text="Reemplazar con:").grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")
        ttk.Entry(input_frame, textvariable=self.replace_text_var, width=60).grid(row=1, column=1, pady=5, sticky="ew")

        # --- Paso 2: Elegir carpeta ---
        folder_frame = ttk.LabelFrame(main_frame, text="Paso 2: Elige la carpeta de búsqueda", padding="10")
        folder_frame.pack(fill=tk.X, expand=True, pady=10)
        folder_frame.columnconfigure(1, weight=1)

        ttk.Button(folder_frame, text="Seleccionar Carpeta...", command=self.select_directory).grid(row=0, column=0, padx=(0, 10))
        ttk.Label(folder_frame, textvariable=self.search_path_var, wraplength=550, anchor="w").grid(row=0, column=1, sticky="ew")

        # --- Paso 3: Seleccionar archivos ---
        files_frame = ttk.LabelFrame(main_frame, text="Paso 3: Selecciona los archivos a modificar", padding="10")
        files_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.files_list_frame = scrolledtext.ScrolledText(files_frame, wrap=tk.WORD, height=15, relief="flat", bg=self.root.cget('bg'))
        self.files_list_frame.pack(fill=tk.BOTH, expand=True)
        self.files_list_frame.configure(state='disabled')
        
        # --- Paso 4: Acción Opcional de Servidor ---
        server_action_frame = ttk.LabelFrame(main_frame, text="Paso 4: Acción Opcional de Servidor", padding="10")
        server_action_frame.pack(fill=tk.X, expand=True, pady=10)
        server_action_frame.columnconfigure(1, weight=1)

        ttk.Checkbutton(server_action_frame, text="Activar reemplazo de cuenta en servidor", variable=self.run_server_cmd_var, command=self.toggle_key_field_state).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0,5))
        
        ttk.Label(server_action_frame, text="Nueva Clave:").grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")
        self.new_key_entry = ttk.Entry(server_action_frame, textvariable=self.new_key_var, show="*", state="disabled")
        self.new_key_entry.grid(row=1, column=1, pady=5, sticky="ew")
        ttk.Label(server_action_frame, text="Nota: Requiere ejecutar la aplicación como Administrador.", font=("", 8, "italic")).grid(row=2, column=0, columnspan=2, sticky='w')


        # --- Paso 5: Iniciar proceso ---
        control_frame = ttk.LabelFrame(main_frame, text="Paso 5: Inicia el proceso", padding="10")
        control_frame.pack(fill=tk.X, expand=True, pady=(10, 0))
        control_frame.columnconfigure(0, weight=1)

        self.run_button = ttk.Button(control_frame, text="Iniciar Reemplazo", command=self.start_processing)
        self.run_button.grid(row=0, column=1, padx=10, pady=5)
        
        self.refresh_button = ttk.Button(control_frame, text="Refrescar Lista", command=self.refresh_scan)
        self.refresh_button.grid(row=0, column=2, pady=5)

        self.progress_bar = ttk.Progressbar(control_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=1, column=0, columnspan=3, pady=(10, 5), sticky="ew")

        self.status_label = ttk.Label(control_frame, text="Listo para empezar.")
        self.status_label.grid(row=2, column=0, columnspan=3, pady=(5, 0), sticky="w")

    def toggle_key_field_state(self):
        """Habilita o deshabilita el campo de la nueva clave según el estado del checkbox."""
        state = "normal" if self.run_server_cmd_var.get() else "disabled"
        self.new_key_entry.config(state=state)

    def select_directory(self):
        """Abre un diálogo para que el usuario seleccione una carpeta y luego la escanea."""
        directory = filedialog.askdirectory(title="Selecciona una carpeta para buscar archivos")
        if directory:
            self.current_search_path = directory
            self.search_path_var.set(f"Carpeta seleccionada: {directory}")
            self.scan_files(directory)

    def refresh_scan(self):
        """Vuelve a escanear la última carpeta seleccionada."""
        self.scan_files(self.current_search_path)
        
    def scan_files(self, search_path):
        """
        Escanea el directorio especificado (y subdirectorios) en busca de archivos .html y .py
        y los muestra en la lista con checkboxes.
        """
        self.status_label.config(text="Escaneando archivos...")
        self.file_vars.clear()
        
        self.files_list_frame.configure(state='normal')
        self.files_list_frame.delete('1.0', tk.END)

        found_files = False
        try:
            for dirpath, _, filenames in os.walk(search_path):
                for filename in sorted(filenames):
                    if filename.endswith(".html") or filename.endswith(".py"):
                        found_files = True
                        var = tk.BooleanVar(value=True)
                        filepath = os.path.join(dirpath, filename)
                        self.file_vars[filepath] = var
                        
                        display_name = os.path.relpath(filepath, search_path)
                        cb = ttk.Checkbutton(self.files_list_frame, text=display_name, variable=var)
                        self.files_list_frame.window_create(tk.END, window=cb)
                        self.files_list_frame.insert(tk.END, '\n')
        
            if not found_files:
                self.files_list_frame.insert(tk.END, "No se encontraron archivos .html o .py en esta carpeta.")
                self.status_label.config(text="No se encontraron archivos compatibles.")
            else:
                self.status_label.config(text=f"Se encontraron {len(self.file_vars)} archivos. Selecciona cuáles procesar.")
        
        except Exception as e:
            messagebox.showerror("Error de Escaneo", f"Ocurrió un error al buscar archivos: {e}")
            self.status_label.config(text="Error al escanear archivos.")
        finally:
            self.files_list_frame.configure(state='disabled')


    def start_processing(self):
        """Valida las entradas e inicia el proceso de reemplazo en un hilo separado."""
        find_text = self.find_text_var.get()
        selected_files = [fp for fp, var in self.file_vars.items() if var.get()]

        if not find_text:
            messagebox.showwarning("Entrada Inválida", "El campo 'Texto a buscar' no puede estar vacío.")
            return

        if not selected_files:
            messagebox.showwarning("Sin Selección", "Por favor, selecciona al menos un archivo para procesar.")
            return

        if self.run_server_cmd_var.get() and not self.new_key_var.get():
            messagebox.showwarning("Entrada Inválida", "El campo 'Nueva Clave' no puede estar vacío si la acción de servidor está activada.")
            return

        self.run_button.config(state="disabled")
        self.refresh_button.config(state="disabled")

        process_thread = threading.Thread(
            target=self.process_files_thread,
            args=(find_text, self.replace_text_var.get(), selected_files),
            daemon=True
        )
        process_thread.start()

    def process_files_thread(self, find_text, replace_text, files_to_process):
        """
        Lógica de reemplazo que se ejecuta en un hilo. Al finalizar, puede ejecutar un comando de sistema.
        """
        total_files = len(files_to_process)
        self.progress_bar["maximum"] = total_files
        self.progress_bar["value"] = 0
        files_changed = 0
        
        for i, filepath in enumerate(files_to_process):
            filename = os.path.basename(filepath)
            self.status_label.config(text=f"Procesando ({i+1}/{total_files}): {filename}...")
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                self.status_label.config(text=f"Error al leer {filename}: {e}")
                self.progress_bar["value"] = i + 1
                continue

            if find_text in content:
                new_content = content.replace(find_text, replace_text)
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    files_changed += 1
                except Exception as e:
                    self.status_label.config(text=f"Error al escribir en {filename}: {e}")

            self.progress_bar["value"] = i + 1

        # --- Ejecución de comando opcional ---
        if self.run_server_cmd_var.get():
            self.status_label.config(text="Ejecutando comando de servidor...")
            new_key = self.new_key_var.get()
            username = "Administrator"  # Usuario a modificar
            command = f'net user "{username}" "{new_key}"'
            
            try:
                # Ocultar la ventana de la consola en Windows
                creationflags = 0
                if os.name == 'nt':
                    creationflags = subprocess.CREATE_NO_WINDOW
                
                subprocess.run(command, shell=True, check=True, capture_output=True, text=True, creationflags=creationflags)
                self.root.after(0, lambda: messagebox.showinfo("Éxito", f"La contraseña del usuario '{username}' se cambió correctamente."))

            except subprocess.CalledProcessError as e:
                error_message = (f"Error al cambiar la clave. Asegúrate de ejecutar como Administrador.\n\n"
                               f"Error: {e.stderr}")
                self.root.after(0, lambda: messagebox.showerror("Error de Comando", error_message))
            except FileNotFoundError:
                error_message = "Error: El comando 'net' no se encontró. Esta función es para Windows."
                self.root.after(0, lambda: messagebox.showerror("Error de Comando", error_message))

        final_message = f"Proceso completado. Se modificaron {files_changed} de {total_files} archivos."
        self.status_label.config(text=final_message)
        self.root.after(0, lambda: messagebox.showinfo("Proceso Finalizado", final_message))
        
        self.run_button.config(state="normal")
        self.refresh_button.config(state="normal")
        self.progress_bar["value"] = 0

if __name__ == "__main__":
    root = ThemedTk(theme="arc")
    app = TextReplacerApp(root)
    root.mainloop()

