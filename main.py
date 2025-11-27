import asyncio
import json, base64
import threading
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519

from gui import DniIMGUI
import dnie
from noise_crypto import (
    LocalStaticKey,
    KeyBundle,
    generate_ephemeral,
    perform_handshake_initiator,
    perform_handshake_responder,
    NoiseSession,
)
from protocol import (
    UDP_PORT,
    FRAME_HANDSHAKE_1,
    FRAME_HANDSHAKE_2,
    FRAME_DATA,
    Frame,
    pack_frame,
    unpack_frame,
    make_cid,
)
from contacts import load_contacts, add_or_update_contact
from discovery import PeerDiscovery
import os


class Connection:
    def __init__(self, cid: int, addr: Tuple[str, int], session: NoiseSession, remote_fingerprint: str):
        self.cid = cid
        self.addr = addr
        self.session = session
        self.remote_fingerprint = remote_fingerprint
        self.next_stream_id = 1

    def get_stream_id(self) -> int:
        sid = self.next_stream_id
        self.next_stream_id += 1
        return sid


class DniIMProtocol(asyncio.DatagramProtocol):
    def __init__(self, app: "DniIMApp"):
        self.app = app
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        print(f"[UDP] Escuchando en {transport.get_extra_info('sockname')}")

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            frame = unpack_frame(data)
        except Exception as e:
            print("[UDP] Datagrama inválido:", e)
            return
        asyncio.create_task(self.app.handle_frame(frame, addr))

    def send_frame(self, frame: Frame, addr) -> None:
        if self.transport:
            self.transport.sendto(pack_frame(frame), addr)


class DniIMApp:
    def __init__(self, pin: str, nickname: str, gui: DniIMGUI):
        self.gui = gui
        self.nickname = nickname

        print("Leyendo DNIe...")
        cert = dnie.login_with_pin(pin)
        self.cert = cert
        self.cert_der = cert.public_bytes(Encoding.DER)
        self.fingerprint = dnie.get_cert_fingerprint_sha256()
        print("[DNIe] Fingerprint cargado.")

        # ============================================================
        #      PERSISTENCIA DE CLAVE ESTÁTICA X25519
        # ============================================================
        STATIC_KEY_PATH = "static_key_x25519.bin"

        if os.path.exists(STATIC_KEY_PATH):
            with open(STATIC_KEY_PATH, "rb") as f:
                key_bytes = f.read()
            priv = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            print("[STATIC] Clave estática cargada de disco.")
        else:
            priv = x25519.X25519PrivateKey.generate()
            with open(STATIC_KEY_PATH, "wb") as f:
                f.write(priv.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption()
                ))
            print("[STATIC] Nueva clave estática generada y guardada.")

        self.local_static = LocalStaticKey(priv=priv, pub=priv.public_key())
        self.local_static_pub_bytes = self.local_static.pub_bytes()

        # Firma de la clave estática con el DNIe
        signature = dnie.sign_dnie(self.local_static_pub_bytes)

        self.local_bundle = KeyBundle(
            static_pub=self.local_static_pub_bytes,
            cert_der=self.cert_der,
            signature=signature,
        )
        # ============================================================

        self.loop = None
        self.transport = None
        self.proto = None

        self.contacts = load_contacts()
        self.connections: Dict[int, Connection] = {}
        self.pending_handshakes: Dict[str, dict] = {}

        self.discovery = PeerDiscovery(
            port=UDP_PORT,
            fingerprint=self.fingerprint,
            nickname=nickname,
            on_peers_change=self.on_peers_change,
        )

    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        transport, protocol = await self.loop.create_datagram_endpoint(
            lambda: DniIMProtocol(self),
            local_addr=("0.0.0.0", UDP_PORT),
        )

        self.transport = transport
        self.proto = protocol

        self.discovery.register_service()
        self.discovery.start_browsing()

        self.on_peers_change({})
        print("[APP] Sistema listo.")

    async def shutdown(self) -> None:
        self.discovery.close()
        dnie.logout()
        if self.transport:
            self.transport.close()

    # ------------------------------------------------------------------
    def on_peers_change(self, mdns_peers) -> None:
        self.contacts = load_contacts()

        peers_by_fp = {}
        for info in mdns_peers.values():
            fp = info.get("fingerprint")
            if fp and fp != self.fingerprint:
                peers_by_fp[fp] = info

        contacts_filtered = {k: v for k, v in self.contacts.items() if k != self.fingerprint}
        self.gui.update_contacts_threadsafe(peers_by_fp, contacts_filtered)

    # ------------------------------------------------------------------
    def connect_to_peer(self, name_or_fp: str) -> None:
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._connect_to_peer_async(name_or_fp)))

    async def _connect_to_peer_async(self, name_or_fp: str) -> None:
        q = name_or_fp.lower()

        fp = None
        for fpi, c in self.contacts.items():
            if c.name.lower() == q or fpi.lower() == q:
                fp = fpi
        for info in self.discovery.peers.values():
            if info.get("nickname", "").lower() == q or info.get("fingerprint", "").lower() == q:
                fp = info.get("fingerprint")

        if fp is None:
            fp = name_or_fp

        for conn in self.connections.values():
            if conn.remote_fingerprint == fp:
                return

        addr = None
        for info in self.discovery.peers.values():
            if info["fingerprint"] == fp:
                addr = info["address"]

        if not addr:
            print("[APP] Peer offline:", fp[:8])
            self.gui.show_security_info_threadsafe(fp, "⚠️ ERROR: Usuario desconectado.")
            return

        print(f"[APP] Handshake con {fp[:8]} en {addr}")

        eph_priv, eph_pub = generate_ephemeral()
        self.pending_handshakes[fp] = {"addr": addr, "eph_priv": eph_priv}

        payload = json.dumps({
            "role": "initiator",
            "bundle": {
                "static_pub": self.local_static_pub_bytes.hex(),
                "cert_der": self.cert_der.hex(),
                "signature": self.local_bundle.signature.hex(),
            },
            "eph_pub": eph_pub.hex(),
        }).encode()

        frame = Frame(cid=0, stream_id=0, frame_type=FRAME_HANDSHAKE_1, payload=payload)
        self.proto.send_frame(frame, addr)

    # ------------------------------------------------------------------
    async def _handle_handshake_1(self, frame: Frame, addr):
        payload = json.loads(frame.payload.decode())

        bundle = payload["bundle"]
        static_pub = bytes.fromhex(bundle["static_pub"])
        cert_der = bytes.fromhex(bundle["cert_der"])
        sig = bytes.fromhex(bundle["signature"])
        eph_pub = bytes.fromhex(payload["eph_pub"])

        cert = x509.load_der_x509_certificate(cert_der)

        try:
            cert.public_key().verify(sig, static_pub, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            print("[HANDSHAKE] ❌ Firma NO válida (iniciador)")
            return

        fp = cert.fingerprint(hashes.SHA256()).hex()
        print("[HS1] Firma válida de:", fp[:8])

        remote_bundle = KeyBundle(static_pub, cert_der, sig)
        eph_priv_local, eph_pub_local = generate_ephemeral()

        session = perform_handshake_responder(
            self.local_static,
            self.local_bundle,
            remote_bundle,
            eph_pub,
            eph_priv_local,
        )

        cid = make_cid(self.local_static_pub_bytes, static_pub)
        conn = Connection(cid, addr, session, fp)
        self.connections[cid] = conn

        payload2 = json.dumps({
            "role": "responder",
            "bundle": {
                "static_pub": self.local_static_pub_bytes.hex(),
                "cert_der": self.cert_der.hex(),
                "signature": self.local_bundle.signature.hex(),
            },
            "eph_pub": eph_pub_local.hex(),
            "cid": cid,
        }).encode()

        frame2 = Frame(cid=0, stream_id=0, frame_type=FRAME_HANDSHAKE_2, payload=payload2)
        self.proto.send_frame(frame2, addr)

        self._on_handshake_complete(fp, "Responder")

    # ------------------------------------------------------------------
    async def _handle_handshake_2(self, frame: Frame, addr):
        payload = json.loads(frame.payload.decode())

        bundle = payload["bundle"]
        static_pub = bytes.fromhex(bundle["static_pub"])
        cert_der = bytes.fromhex(bundle["cert_der"])
        sig = bytes.fromhex(bundle["signature"])
        eph_pub = bytes.fromhex(payload["eph_pub"])
        cid = payload["cid"]

        cert = x509.load_der_x509_certificate(cert_der)

        try:
            cert.public_key().verify(sig, static_pub, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            print("[HANDSHAKE] ❌ Firma NO válida (responder)")
            return

        fp = cert.fingerprint(hashes.SHA256()).hex()
        print("[HS2] Firma válida de:", fp[:8])

        state = self.pending_handshakes.pop(fp, None)
        if not state:
            print("[APP] Error: no pending handshake")
            return

        remote_bundle = KeyBundle(static_pub, cert_der, sig)

        session = perform_handshake_initiator(
            self.local_static,
            self.local_bundle,
            remote_bundle,
            eph_pub,
            state["eph_priv"],
        )

        conn = Connection(cid, addr, session, fp)
        self.connections[cid] = conn

        self._on_handshake_complete(fp, "Initiator")

    def _on_handshake_complete(self, fp: str, role: str):
        try:
            # Actualizar estado del contacto
            add_or_update_contact(self.contacts, fp)
            self.contacts = load_contacts()

            # Notificar en GUI
            self.gui.show_security_info_threadsafe(
                fp,
                f"🤝 Handshake completado ({role})."
            )

            # Refrescar lista
            self.on_peers_change(self.discovery.peers)

        except Exception as e:
            print("[APP] Error en _on_handshake_complete:", e)




    # ------------------------------------------------------------------
    async def _handle_data(self, frame: Frame, addr):
        conn = self.connections.get(frame.cid)
        if not conn:
            return
        try:
            pt = conn.session.decrypt(frame.payload)
            text = pt.decode("utf-8", errors="replace")

            fp = conn.remote_fingerprint
            add_or_update_contact(self.contacts, fp)
            self.contacts = load_contacts()
            self.on_peers_change(self.discovery.peers)

            self.gui.show_message_threadsafe(fp, fp[:8], text)
        except Exception as e:
            print("[APP] Error decrypt:", e)

    # ------------------------------------------------------------------
    async def handle_frame(self, frame: Frame, addr) -> None:
        try:
            if frame.frame_type == FRAME_HANDSHAKE_1:
                await self._handle_handshake_1(frame, addr)
            elif frame.frame_type == FRAME_HANDSHAKE_2:
                await self._handle_handshake_2(frame, addr)
            elif frame.frame_type == FRAME_DATA:
                await self._handle_data(frame, addr)
        except Exception as e:
            print("[APP] Error frame:", e)

    # ------------------------------------------------------------------
    def send_message_to_peer(self, fp_target: str, message: str) -> None:
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._send_message_async(fp_target, message)))

    async def _send_message_async(self, fp: str, message: str) -> None:
        conn = None
        for c in self.connections.values():
            if c.remote_fingerprint == fp:
                conn = c

        if not conn:
            print("[APP] Sin conexión")
            self.gui.show_security_info_threadsafe(fp, "⚠️ ERROR: Usuario desconectado.")
            return

        ct = conn.session.encrypt(message.encode())
        frame = Frame(cid=conn.cid, stream_id=conn.get_stream_id(), frame_type=FRAME_DATA, payload=ct)
        self.proto.send_frame(frame, conn.addr)


# ----------------------------------------------------------------------
def run_asyncio_loop(app: DniIMApp, loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(app.start())
        loop.run_forever()
    except Exception as e:
        print("Error en loop:", e)


def main() -> None:
    print("=== Cliente DNI-IM Raccoon Síncrono (solo GUI) ===")

    app_ref = [None]

    def on_send(fp: str, msg: str) -> None:
        if app_ref[0]:
            app_ref[0].send_message_to_peer(fp, msg)

    def on_connect(target: str) -> None:
        if app_ref[0]:
            app_ref[0].connect_to_peer(target)

    gui = DniIMGUI(on_send_message=on_send, on_connect_to_peer=on_connect)
    pin, nickname = gui.get_pin_dialog()
    if not pin:
        return

    try:
        app = DniIMApp(pin, nickname, gui)
        app_ref[0] = app
    except Exception:
        gui.root.destroy()
        print("Error iniciando app.")
        return

    loop = asyncio.new_event_loop()
    t = threading.Thread(target=run_asyncio_loop, args=(app, loop), daemon=True)
    t.start()

    try:
        gui.start()
    except KeyboardInterrupt:
        pass
    finally:
        if loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
        asyncio.run(app.shutdown())


if __name__ == "__main__":
    main()

