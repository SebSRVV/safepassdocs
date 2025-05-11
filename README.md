# 🔐 SafePass&Docs

**SafePass&Docs** es una aplicación de escritorio desarrollada en Python que permite cifrar documentos y gestionar contraseñas de forma segura utilizando criptografía avanzada con RSA y AES. Todo funciona de forma local y sin depender de internet.

---

## 🧩 Funcionalidades

- 🔑 **Gestión de claves RSA** (crear, importar, exportar)
- 📁 **Cifrado/descifrado de archivos**
  - Cifra con AES-256 en modo CFB.
  - Protege la clave AES con RSA-OAEP y SHA-256.
- 🗝️ **Vault de contraseñas cifrado localmente**
  - Almacena sitios, usuarios, contraseñas y URLs.
  - Cifrado completo con AES + Scrypt.

---

## 🛠️ Tecnologías utilizadas

- `tkinter` – Interfaz gráfica de escritorio.
- `cryptography` – Librería para cifrado seguro.
- `json`, `os`, `secrets` – Módulos estándar de Python.

---

## 🔧 Requisitos

- Python 3.7 o superior
- Dependencias (instálalas con pip):

```bash
pip install cryptography
