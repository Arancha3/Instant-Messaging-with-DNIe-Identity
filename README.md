# DNI-IM Raccoon Edition 🦝

Cliente de mensajería instantánea punto a punto que usa el **DNI electrónico (DNIe)** como identidad, descubre otros nodos en la LAN mediante **mDNS** y establece sesiones cifradas tipo **Noise IK** sobre **UDP** con una GUI en Tkinter.

> Proyecto desarrollado como práctica de la asignatura “Instant Messaging with DNIe Identity”.

---

## 🚀 Características

- Autenticación fuerte con **DNIe vía PKCS#11**.
- Generación y persistencia de una **clave estática X25519** firmada por el DNIe.
- Descubrimiento automático de peers con **mDNS (`_dni-im._udp.local.`)** y actualización dinámica de la lista de contactos.
- Handshake estilo **Noise IK** con:
  - X25519 (estáticas + efímeras)
  - HKDF-BLAKE2s para derivación de claves
  - ChaCha20-Poly1305 para cifrado autenticado.
- Multiplexado sobre un único puerto **UDP 6666** usando **Connection IDs (CID)** y **stream IDs**.
- Libro de contactos persistente (`contacts.json`) asociado a fingerprints de certificados.
- Interfaz gráfica en Tkinter con:
  - Sidebar de peers (online/offline)
  - Historial por contacto
  - Burbujas de chat y mensajes de seguridad
  - Fondo con el mapache nadador 🦝.

---

## 🧱 Arquitectura

### Módulos principales

- **`dnie.py`**  
  Encapsula el acceso al DNIe con PyKCS11: login con PIN, extracción de certificado X.509, obtención del fingerprint SHA-256 y firma con la clave privada correspondiente al certificado.

- **`noise_crypto.py`**  
  Implementa las primitivas criptográficas y la lógica del handshake:  
  - `KeyBundle`, `LocalStaticKey` y `NoiseSession`  
  - funciones `perform_handshake_initiator` y `perform_handshake_responder` que calculan `ss`, `ee`, `se`, `es` y derivan claves simétricas con HKDF-BLAKE2s.

- **`protocol.py`**  
  Define el formato de frame sobre UDP (`Frame`, `pack_frame`, `unpack_frame`), los tipos de frame (handshake y datos) y la generación simétrica del `cid` con BLAKE2s.

- **`discovery.py`**  
  Maneja el anuncio y descubrimiento de peers mediante Zeroconf/mDNS, manteniendo un diccionario de peers con IP, puerto, fingerprint y nickname, y notificando cambios al GUI.

- **`contacts.py`**  
  Capa de persistencia de contactos en `contacts.json` con dataclass `Contact` y función `add_or_update_contact` que mantiene `first_seen` / `last_seen` y nombre amistoso.

- **`gui.py`**  
  Interfaz gráfica **DniIMGUI** en Tkinter:
  - Lista de peers con estado online/offline y última conexión  
  - Área de chat con burbujas (mensajes, avisos de seguridad, errores)  
  - Gestión de entradas de texto y callbacks hacia la lógica de red  
  - Uso de `image_0.png` como fondo del área de chat.

- **`main.py`** (lógica de aplicación)  
  - Inicializa el GUI, lee el PIN y nickname.  
  - Carga certificado y firma del DNIe.  
  - Genera o carga la clave estática X25519, la firma con el DNIe y construye el `KeyBundle` local.  
  - Arranca el bucle `asyncio` en un hilo separado, con `DniIMProtocol` para manejar frames UDP.  
  - Implementa `DniIMApp`, que coordina discovery, handshakes, sesiones cifradas, envío/recepción de mensajes y actualización de contactos/GUI.


---

## 🔧 Requisitos

- **Python 3.10+** (recomendado)
- Librerías Python:
  - `cryptography`
  - `PyKCS11`
  - `zeroconf`
  - `Pillow`
  - `tkinter` (incluido en la mayoría de instalaciones de Python)
- **DNIe** y lector de tarjetas compatible.
- **OpenSC** instalado y ruta correcta a la librería PKCS#11 en `dnie.py`:

```python
LIB_PATH = 'C:/Archivos de programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'
```

Ajusta esta ruta según tu sistema (Windows/Linux/macOS).

---

## ▶️ Uso

1. Conecta el lector de tarjetas y el **DNIe**.
2. Lanza el cliente:

   ```bash
   python main.py
   ```

3. El GUI solicitará:
   - **PIN del DNIe**
   - **Nickname** (mostrarás este alias a otros peers)

4. Al iniciar:
   - El cliente registra un servicio mDNS `_dni-im._udp.local.` en el puerto UDP configurado (`UDP_PORT` en `protocol.py`, por defecto 6666).  
   - Se inicia el browsing de peers y se rellena la lista lateral de contactos.

5. Para chatear:
   - Haz clic en un peer online de la lista, o  
   - Usa el botón **“Conectar Manualmente”** e introduce alias o fingerprint para iniciar el handshake.  
   - Cuando el handshake termine con éxito verás un mensaje tipo `🤝 Handshake completado (Initiator/Responder).` en el chat.  
   - Escribe el mensaje en la caja inferior y pulsa **Enter** o “Enviar”.

6. Los contactos con los que te has comunicado se guardan en `contacts.json`, incluyendo la fecha de primer y último contacto.  

---

## 🔐 Protocolo y criptografía (resumen)

- **Formato de frame UDP**

  Cabecera fija `!QIBH` (CID, Stream ID, tipo, longitud payload) seguida del payload.  

- **Handshake Noise IK simplificado**

  - Cada peer tiene una clave estática X25519 firmada por su DNIe (firma verificada con el certificado del DNIe).  
  - Se intercambian claves efímeras y `KeyBundle` firmados.
  - Se calculan cuatro DH: `ss`, `ee`, `se`, `es`, se concatenan y se pasan por HKDF-BLAKE2s para obtener 64 bytes de material de clave.  
  - Se derivan dos claves:
    - `k_i_to_r` (iniciador → respondedor)
    - `k_r_to_i` (respondedor → iniciador)
  - Cada `NoiseSession` usa **ChaCha20-Poly1305** con nonces crecientes (contador) para cifrado autenticado de mensajes.

- **Connection ID (CID)**  
  Se obtiene aplicando BLAKE2s sobre las claves públicas estáticas de ambos peers ordenadas lexicográficamente y usando los primeros 8 bytes como entero.

---

## 🗂 Estructura del repositorio

```text
.
├── main.py              # Punto de entrada y lógica de aplicación (DniIMApp)
├── gui.py               # Interfaz gráfica Tkinter
├── dnie.py              # Acceso al DNIe via PKCS#11
├── discovery.py         # Anuncio y descubrimiento mDNS
├── protocol.py          # Frames UDP y CID
├── noise_crypto.py      # Primitivas Noise / X25519 / ChaCha20-Poly1305
├── contacts.py          # Libro de contactos persistente
├── A2_IMP_intro.pdf     # Enunciado de la práctica
├── image_0.png          # Fondo mapache del chat
└── contacts.json        # (se genera en tiempo de ejecución)
```

---
