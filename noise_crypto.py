# filename: noise_crypto.py
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.hashes import BLAKE2s


ROLE_INITIATOR = "initiator"
ROLE_RESPONDER = "responder"


# ============================================================
# PRIMITIVAS CRIPTO
# ============================================================

def hkdf_blake2s(ikm: bytes, info: bytes, length: int = 64) -> bytes:
    """
    HKDF(BLAKE2s) 
    """
    kdf = HKDF(
        algorithm=BLAKE2s(digest_size=32),
        length=length,
        salt=None,
        info=info,
    )
    return kdf.derive(ikm)


# ============================================================
# ESTRUCTURAS DE IDENTIDAD Y SESIÓN
# ============================================================

@dataclass
class KeyBundle:
    """
    Identidad del peer:
      - static_pub: clave pública X25519 estática
      - cert_der: certificado DNIe (DER)
      - signature: firma del DNIe sobre static_pub
    """
    static_pub: bytes
    cert_der: bytes
    signature: bytes


@dataclass
class NoiseSession:
    """
    Sesión de cifrado estilo Noise .
    """
    role: str
    sending_key: bytes
    receiving_key: bytes
    send_nonce: int = 0
    recv_nonce: int = 0

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce_bytes = self.send_nonce.to_bytes(12, "big")
        aead = ChaCha20Poly1305(self.sending_key)
        ct = aead.encrypt(nonce_bytes, plaintext, aad)
        self.send_nonce += 1
        return ct

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        nonce_bytes = self.recv_nonce.to_bytes(12, "big")
        aead = ChaCha20Poly1305(self.receiving_key)
        pt = aead.decrypt(nonce_bytes, ciphertext, aad)
        self.recv_nonce += 1
        return pt


@dataclass
class LocalStaticKey:
    """
    Clave estática local X25519.
    """
    priv: X25519PrivateKey
    pub: X25519PublicKey

    @staticmethod
    def generate() -> "LocalStaticKey":
        priv = X25519PrivateKey.generate()
        return LocalStaticKey(priv=priv, pub=priv.public_key())

    def pub_bytes(self) -> bytes:
        return self.pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_ephemeral() -> Tuple[X25519PrivateKey, bytes]:
    """
    Genera una clave efímera X25519 y devuelve (privada, pública_bytes).
    """
    e_priv = X25519PrivateKey.generate()
    e_pub = e_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return e_priv, e_pub


# ============================================================
# HANDSHAKE: INICIADOR Y RESPONDER
# ============================================================

def perform_handshake_initiator(
    local_static: LocalStaticKey,
    local_bundle: KeyBundle,       # no se usa en el cálculo de claves, pero se deja por simetría
    remote_bundle: KeyBundle,
    remote_ephemeral_pub: bytes,
    local_ephemeral_priv: X25519PrivateKey,
) -> NoiseSession:
    """
    Calcula las claves de sesión desde el punto de vista del INICIADOR.

    Se asume que ya hemos recibido del peer:
      - su KeyBundle (remote_bundle)
      - su clave efímera pública (remote_ephemeral_pub)

    Derivamos 4 secretos DH:

        ss = DH(s_i, S_r)
        ee = DH(e_i, E_r)
        se = DH(s_i, E_r)
        es = DH(e_i, S_r)

    y construimos:

        IKM = ss || ee || se || es

    Luego HKDF-BLAKE2s -> 64 bytes:
        primeros 32: clave initiator -> responder
        últimos 32:  clave responder -> initiator
    """
    remote_static_pub = X25519PublicKey.from_public_bytes(remote_bundle.static_pub)
    remote_ephemeral = X25519PublicKey.from_public_bytes(remote_ephemeral_pub)

    # ss = s_i x S_r
    dh_ss = local_static.priv.exchange(remote_static_pub)
    # ee = e_i x E_r
    dh_ee = local_ephemeral_priv.exchange(remote_ephemeral)
    # se = s_i x E_r
    dh_se = local_static.priv.exchange(remote_ephemeral)
    # es = e_i x S_r
    dh_es = local_ephemeral_priv.exchange(remote_static_pub)

    ikm = dh_ss + dh_ee + dh_se + dh_es
    key_material = hkdf_blake2s(ikm, info=b"NoiseIK-dni-im", length=64)

    k_i_to_r = key_material[:32]
    k_r_to_i = key_material[32:]

    return NoiseSession(
        role=ROLE_INITIATOR,
        sending_key=k_i_to_r,
        receiving_key=k_r_to_i,
    )


def perform_handshake_responder(
    local_static: LocalStaticKey,
    local_bundle: KeyBundle,
    remote_bundle: KeyBundle,
    remote_ephemeral_pub: bytes,
    local_ephemeral_priv: X25519PrivateKey,
) -> NoiseSession:
    """
    Calcula las mismas claves de sesión pero desde el punto de vista del RESPONDER.

    Aquí:
      - local_static / local_ephemeral_priv  ≡ s_r, e_r
      - remote_bundle.static_pub             ≡ S_i
      - remote_ephemeral_pub                 ≡ E_i

    Volvemos a derivar EXACTAMENTE los mismos secretos lógicos:

        ss = DH(s_r, S_i)  = DH(s_i, S_r)
        ee = DH(e_r, E_i)  = DH(e_i, E_r)
        se = DH(e_r, S_i)  = DH(s_i, E_r)
        es = DH(s_r, E_i)  = DH(e_i, S_r)

    y usamos el MISMO orden:

        IKM = ss || ee || se || es

    Del HKDF sacamos las mismas claves (k_i_to_r, k_r_to_i), pero en la sesión
    del responder la clave de envío es k_r_to_i.
    """
    remote_static_pub = X25519PublicKey.from_public_bytes(remote_bundle.static_pub)
    remote_ephemeral = X25519PublicKey.from_public_bytes(remote_ephemeral_pub)

    # ss = s_r x S_i
    dh_ss = local_static.priv.exchange(remote_static_pub)
    # ee = e_r x E_i
    dh_ee = local_ephemeral_priv.exchange(remote_ephemeral)
    # se = e_r x S_i  (≡ s_i x E_r)
    dh_se = local_ephemeral_priv.exchange(remote_static_pub)
    # es = s_r x E_i  (≡ e_i x S_r)
    dh_es = local_static.priv.exchange(remote_ephemeral)

    ikm = dh_ss + dh_ee + dh_se + dh_es
    key_material = hkdf_blake2s(ikm, info=b"NoiseIK-dni-im", length=64)

    k_i_to_r = key_material[:32]
    k_r_to_i = key_material[32:]

    return NoiseSession(
        role=ROLE_RESPONDER,
        sending_key=k_r_to_i,   # responder -> initiator
        receiving_key=k_i_to_r, # initiator -> responder
    )



