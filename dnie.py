# filename: dnie.py
import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

# ⚠️ Ajusta esta ruta a tu instalación de OpenSC
LIB_PATH = 'C:/Archivos de programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'

_pkcs11 = None
_session = None
_cert = None
_priv_key_handle = None


def _get_pkcs11():
    """Carga la librería PKCS11 una sola vez."""
    global _pkcs11
    if _pkcs11 is None:
        _pkcs11 = PyKCS11.PyKCS11Lib()
        _pkcs11.load(LIB_PATH)
    return _pkcs11


def login_with_pin(pin: str):
    """
    Abre sesión con el DNIe, carga el certificado y la clave privada
    **correspondiente al certificado** usando CKA_ID .

    Devuelve el certificado X.509 ya parseado.
    """
    global _session, _cert, _priv_key_handle

    pkcs11 = _get_pkcs11()

    # Buscar slots con token DNIe
    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        raise RuntimeError("No se encontraron tokens DNIe")

    slot = slots[0]

    # Abrir sesión
    _session = pkcs11.openSession(slot)
    _session.login(pin)

    # Buscar certificados X.509 dentro del DNIe
    certs = _session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)
    ])
    if not certs:
        raise RuntimeError("No se encontró ningún certificado en el DNIe")

    
    cert_obj = certs[2]

    # Leer certificado DER
    cert_der = bytes(
        _session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE], True)[0]
    )
    _cert = x509.load_der_x509_certificate(cert_der)

    # ============================
    #   CARGAR CLAVE PRIVADA REAL (CKA_ID)
    # ============================
    cert_id = _session.getAttributeValue(cert_obj, [PyKCS11.CKA_ID])[0]

    priv_keys = _session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_ID, cert_id),
    ])
    if not priv_keys:
        raise RuntimeError(
            "No se encontró la clave privada correspondiente al certificado del DNIe"
        )

    _priv_key_handle = priv_keys[0]

    return _cert


def sign_dnie(data: bytes) -> bytes:
    """
    Firma 'data' con la clave privada del DNIe usando SHA256 + RSA PKCS#1 v1.5

    Esta firma se verifica correctamente en:
        cert.public_key().verify(sig, data, PKCS1v15(), SHA256())
    """
    global _session, _priv_key_handle

    if _session is None or _priv_key_handle is None:
        raise RuntimeError("No hay sesión abierta con el DNIe")

    mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
    signature = bytes(_session.sign(_priv_key_handle, data, mech))
    return signature


def get_cert() -> x509.Certificate:
    """Devuelve el certificado cargado."""
    if _cert is None:
        raise RuntimeError("No hay certificado cargado")
    return _cert


def get_cert_der() -> bytes:
    """Devuelve el certificado en formato DER."""
    return get_cert().public_bytes(Encoding.DER)


def get_cert_fingerprint_sha256() -> str:
    """Fingerprint SHA256 del certificado."""
    cert = get_cert()
    return cert.fingerprint(hashes.SHA256()).hex()


def logout():
    """Cierra la sesión PKCS11 correctamente."""
    global _session, _cert, _priv_key_handle
    if _session:
        try:
            _session.logout()
            _session.closeSession()
        except Exception:
            pass

    _session = None
    _cert = None
    _priv_key_handle = None


