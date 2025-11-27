# Instant-Messaging-with-DNIe-Identity
Cliente de mensajería instantánea punto a punto que usa el DNI electrónico (DNIe) como identidad, descubre otros nodos en la LAN mediante mDNS y establece sesiones cifradas tipo Noise IK sobre UDP con una GUI en Tkinter.
Características

Autenticación fuerte con DNIe vía PKCS#11. 

dnie

Generación y persistencia de una clave estática X25519 firmada por el DNIe.

Descubrimiento automático de peers con mDNS (_dni-im._udp.local.) y actualización dinámica de la lista de contactos.

Handshake estilo Noise IK con:

X25519 (estáticas + efímeras)

HKDF-BLAKE2s para derivación de claves

ChaCha20-Poly1305 para cifrado autenticado.

Multiplexado sobre un único puerto UDP 6666 usando Connection IDs (CID) y stream IDs.

Libro de contactos persistente (contacts.json) asociado a fingerprints de certificados.

Interfaz gráfica en Tkinter con:

Sidebar de peers (online/offline)

Historial por contacto

Burbujas de chat y mensajes de seguridad

Fondo con el mapache nadador 🦝.
