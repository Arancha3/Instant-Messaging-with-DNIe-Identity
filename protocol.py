import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import BLAKE2s


UDP_PORT = 443 

# Tipos de frame
FRAME_HANDSHAKE_1 = 0x01
FRAME_HANDSHAKE_2 = 0x02
FRAME_DATA = 0x10

FRAME_HEADER_STRUCT = struct.Struct("!QIBH")
# Q: CID (8 bytes)
# I: Stream ID (4 bytes)
# B: Tipo (1 byte)
# H: Longitud payload (2 bytes)


@dataclass
class Frame:
    cid: int
    stream_id: int
    frame_type: int
    payload: bytes


def make_cid(static_pub_local: bytes, static_pub_remote: bytes) -> int:
    """Genera un Connection ID simétrico para ambos extremos.

    Se aplica BLAKE2s sobre las claves públicas estáticas ordenadas
    lexicográficamente y se toman los primeros 8 bytes como entero.
    """
    digest = hashes.Hash(BLAKE2s(digest_size=32))
    keys = sorted([static_pub_local, static_pub_remote])
    digest.update(keys[0] + keys[1])
    full = digest.finalize()
    cid_bytes = full[:8]
    return int.from_bytes(cid_bytes, "big")


def pack_frame(frame: Frame) -> bytes:
    if len(frame.payload) > 0xFFFF:
        raise ValueError("Payload demasiado grande")
    header = FRAME_HEADER_STRUCT.pack(
        frame.cid,
        frame.stream_id,
        frame.frame_type,
        len(frame.payload),
    )
    return header + frame.payload


def unpack_frame(data: bytes) -> Frame:
    if len(data) < FRAME_HEADER_STRUCT.size:
        raise ValueError("Datagrama demasiado pequeño")
    cid, stream_id, frame_type, length = FRAME_HEADER_STRUCT.unpack_from(data, 0)
    if len(data) < FRAME_HEADER_STRUCT.size + length:
        raise ValueError("Longitud inconsistente")
    payload = data[FRAME_HEADER_STRUCT.size : FRAME_HEADER_STRUCT.size + length]
    return Frame(cid=cid, stream_id=stream_id, frame_type=frame_type, payload=payload)


