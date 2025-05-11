import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, secrets, json

# Mis variables
public_key = None
private_key = None
public_key_path = ""
private_key_path = ""

# RSA
def generar_claves():
    global public_key, private_key, public_key_path, private_key_path
    nombre = filedialog.asksaveasfilename(defaultextension=".pem", title="Guardar clave privada como...", initialfile="mi_clave_private.pem")
    if not nombre:
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key_path = nombre
    public_key_path = nombre.replace("_private", "_public")
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    messagebox.showinfo("Éxito", f"Claves generadas:\n{private_key_path}\n{public_key_path}")
    actualizar_estado_claves()

def cargar_clave_privada():
    global private_key, private_key_path
    ruta = filedialog.askopenfilename(title="Selecciona clave privada (.pem)")
    if not ruta: return
    with open(ruta, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    private_key_path = ruta
    messagebox.showinfo("Clave Privada", f"Cargada:\n{ruta}")
    actualizar_estado_claves()

def cargar_clave_publica():
    global public_key, public_key_path
    ruta = filedialog.askopenfilename(title="Selecciona clave pública (.pem)")
    if not ruta: return
    with open(ruta, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    public_key_path = ruta
    messagebox.showinfo("Clave Pública", f"Cargada:\n{ruta}")
    actualizar_estado_claves()

def actualizar_estado_claves():
    estado = f"🔓 Pública: {'✅' if public_key else '❌'} ({os.path.basename(public_key_path) if public_key_path else ''})\n"
    estado += f"🔐 Privada: {'✅' if private_key else '❌'} ({os.path.basename(private_key_path) if private_key_path else ''})"
    estado_lbl.config(text=estado)

# Mi Cifrado y Descifrado
def encriptar_documento():
    if not public_key:
        messagebox.showerror("Error", "Debes cargar una clave pública.")
        return
    path = filedialog.askopenfilename(title="Selecciona archivo a cifrar")
    if not path: return
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    with open(path, "rb") as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    output_path = path + ".safedocs"
    with open(output_path, "wb") as f:
        f.write(len(encrypted_key).to_bytes(4, 'big'))
        f.write(encrypted_key)
        f.write(iv)
        f.write(encrypted_data)
    messagebox.showinfo("Cifrado exitoso", f"Archivo cifrado:\n{output_path}")

def desencriptar_documento():
    if not private_key:
        messagebox.showerror("Error", "Debes cargar una clave privada.")
        return
    path = filedialog.askopenfilename(title="Selecciona archivo .safedocs")
    if not path: return
    try:
        with open(path, "rb") as f:
            key_len = int.from_bytes(f.read(4), 'big')
            encrypted_key = f.read(key_len)
            iv = f.read(16)
            encrypted_data = f.read()
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        output_path = os.path.splitext(path)[0] + "_descifrado.txt"
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        messagebox.showinfo("Descifrado exitoso", f"Archivo descifrado:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Error al descifrar", str(e))

# Mi vault de contraseñas
def derivar_clave(master_password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(master_password.encode())

def guardar_vault(data: dict, key: bytes, salt: bytes, vault_file: str):
    cipher = Cipher(algorithms.AES(key), modes.CFB(salt), backend=default_backend())
    encryptor = cipher.encryptor()
    raw = json.dumps(data).encode()
    encrypted = encryptor.update(raw) + encryptor.finalize()
    with open(vault_file, "wb") as f:
        f.write(salt + encrypted)

def cargar_vault(master_password: str, vault_file: str):
    with open(vault_file, "rb") as f:
        file = f.read()
    salt = file[:16]
    encrypted = file[16:]
    key = derivar_clave(master_password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(salt), backend=default_backend())
    decryptor = cipher.decryptor()
    raw = decryptor.update(encrypted) + decryptor.finalize()
    data = json.loads(raw.decode())
    return data, key, salt

class VaultManager:
    def __init__(self, tree, status_label):
        self.data = {}
        self.key = None
        self.salt = None
        self.vault_file = None
        self.tree = tree
        self.status_label = status_label

    def update_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for sitio, info in self.data.items():
            self.tree.insert('', 'end', values=(sitio, info['url'], info['usuario'], info['contraseña']))

    def crear_vault(self):
        nombre = simpledialog.askstring("Crear Vault", "Nombre del Vault:")
        clave = simpledialog.askstring("Clave Maestra", "Clave:", show="*")
        if not nombre or not clave:
            messagebox.showerror("Error", "Datos incompletos.")
            return
        self.vault_file = f"vault_{nombre}.dat"
        if os.path.exists(self.vault_file):
            messagebox.showerror("Error", "Ese Vault ya existe.")
            return
        self.salt = secrets.token_bytes(16)
        self.key = derivar_clave(clave, self.salt)
        self.data = {}
        guardar_vault(self.data, self.key, self.salt, self.vault_file)
        self.status_label.config(text=f"🟢 Vault activo: {nombre}")
        self.update_tree()
        messagebox.showinfo("Éxito", "Vault creado.")

    def ingresar_vault(self):
        nombre = simpledialog.askstring("Vault", "Nombre del Vault:")
        clave = simpledialog.askstring("Clave Maestra", "Clave:", show="*")
        self.vault_file = f"vault_{nombre}.dat"
        if not os.path.exists(self.vault_file):
            messagebox.showerror("Error", "Vault no encontrado.")
            return
        try:
            self.data, self.key, self.salt = cargar_vault(clave, self.vault_file)
            self.status_label.config(text=f"🟢 Vault activo: {nombre}")
            self.update_tree()
        except Exception:
            messagebox.showerror("Error", "Clave incorrecta o archivo dañado.")

    def agregar_entrada(self):
        sitio = simpledialog.askstring("Sitio", "Nombre del sitio:")
        url = simpledialog.askstring("URL", "URL:")
        usuario = simpledialog.askstring("Usuario", "Usuario:")
        clave = simpledialog.askstring("Contraseña", "Contraseña:", show="*")
        if sitio and url and usuario and clave:
            self.data[sitio] = {"url": url, "usuario": usuario, "contraseña": clave}
            guardar_vault(self.data, self.key, self.salt, self.vault_file)
            self.update_tree()
        else:
            messagebox.showerror("Error", "Todos los campos son obligatorios.")

    def editar_entrada(self):
        item = self.tree.focus()
        if not item:
            messagebox.showwarning("Aviso", "Selecciona una entrada.")
            return
        sitio = self.tree.item(item)['values'][0]
        actual = self.data[sitio]
        url = simpledialog.askstring("Editar URL", "URL:", initialvalue=actual["url"])
        usuario = simpledialog.askstring("Editar Usuario", "Usuario:", initialvalue=actual["usuario"])
        clave = simpledialog.askstring("Editar Contraseña", "Contraseña:", show="*", initialvalue=actual["contraseña"])
        if url and usuario and clave:
            self.data[sitio] = {"url": url, "usuario": usuario, "contraseña": clave}
            guardar_vault(self.data, self.key, self.salt, self.vault_file)
            self.update_tree()

    def eliminar_entrada(self):
        item = self.tree.focus()
        if not item:
            messagebox.showwarning("Aviso", "Selecciona una entrada.")
            return
        sitio = self.tree.item(item)['values'][0]
        if messagebox.askyesno("Eliminar", f"¿Eliminar '{sitio}'?"):
            del self.data[sitio]
            guardar_vault(self.data, self.key, self.salt, self.vault_file)
            self.update_tree()

# Interfaz
root = tk.Tk()
root.title("SafePass&Docs")
root.geometry("900x900")
root.resizable(False, False)

# Titulo
tk.Label(root, text="🔐 SafePass&Docs", font=("Helvetica", 20, "bold")).pack(pady=15)

# Gestion de Claves RSA
frame_rsa = tk.LabelFrame(root, text="🔑 Gestión de Claves RSA", padx=10, pady=10)
frame_rsa.pack(fill="x", padx=20, pady=10)

tk.Button(frame_rsa, text="🆕 Crear claves", width=25, command=generar_claves).grid(row=0, column=0, padx=10, pady=5)
tk.Button(frame_rsa, text="📂 Cargar clave pública", width=25, command=cargar_clave_publica).grid(row=0, column=1, padx=5)
tk.Button(frame_rsa, text="📂 Cargar clave privada", width=25, command=cargar_clave_privada).grid(row=0, column=2, padx=5)

estado_lbl = tk.Label(frame_rsa, text="🔓 Pública: ❌\n🔐 Privada: ❌", justify="left", fg="blue")
estado_lbl.grid(row=1, column=0, columnspan=3, pady=5)

# Archivos
frame_files = tk.LabelFrame(root, text="📁 Acciones con Archivos", padx=10, pady=10)
frame_files.pack(fill="x", padx=20, pady=10)

tk.Button(frame_files, text="🔒 Encriptar documento", width=30, command=encriptar_documento).pack(pady=5)
tk.Button(frame_files, text="🔓 Desencriptar documento", width=30, command=desencriptar_documento).pack(pady=5)

# Contraseñas
frame_vault = tk.LabelFrame(root, text="🗝️ Vault de Contraseñas", padx=10, pady=10)
frame_vault.pack(fill="both", expand=True, padx=20, pady=10)

frame_top = tk.Frame(frame_vault)
frame_top.pack(fill="x", pady=5)

btn_crear = tk.Button(frame_top, text="📘 Crear Vault", width=20)
btn_ingresar = tk.Button(frame_top, text="🔑 Ingresar Vault", width=20)
btn_crear.pack(side="left", padx=10)
btn_ingresar.pack(side="left", padx=10)

status_lbl = tk.Label(frame_vault, text="🔴 No hay Vault activo", fg="red")
status_lbl.pack(pady=5)

frame_table = tk.Frame(frame_vault)
frame_table.pack(fill="both", expand=True, padx=10)

cols = ("Sitio", "URL", "Usuario", "Contraseña")
tree = ttk.Treeview(frame_table, columns=cols, show="headings")
for col in cols:
    tree.heading(col, text=col)
    tree.column(col, width=180)
tree.pack(fill="both", expand=True, side="left")

scroll = ttk.Scrollbar(frame_table, orient="vertical", command=tree.yview)
tree.configure(yscroll=scroll.set)
scroll.pack(side="right", fill="y")

frame_actions = tk.Frame(frame_vault)
frame_actions.pack(pady=10)

btn_add = tk.Button(frame_actions, text="➕ Agregar", width=20)
btn_edit = tk.Button(frame_actions, text="✏️ Editar", width=20)
btn_delete = tk.Button(frame_actions, text="❌ Eliminar", width=20)

btn_add.pack(side="left", padx=10)
btn_edit.pack(side="left", padx=10)
btn_delete.pack(side="left", padx=10)

# conectar el vault
vault = VaultManager(tree, status_lbl)
btn_crear.config(command=vault.crear_vault)
btn_ingresar.config(command=vault.ingresar_vault)
btn_add.config(command=vault.agregar_entrada)
btn_edit.config(command=vault.editar_entrada)
btn_delete.config(command=vault.eliminar_entrada)

tk.Label(root, text="Desarrollado por Sebastian Rojas", font=("Arial", 9, "italic")).pack(pady=15)

root.mainloop()
