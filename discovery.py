# filename: discovery.py
from zeroconf import (
    ServiceInfo,
    Zeroconf,
    ServiceBrowser,
)
import socket
from typing import Callable, Dict
import threading


SERVICE_TYPE = "_dni-im._udp.local."


class PeerDiscovery:
    def __init__(self, port: int, fingerprint: str, nickname: str,
                 on_peers_change: Callable[[Dict[str, dict]], None]):
        """
        on_peers_change(peers) se llama cuando cambia la lista de peers detectados.
        peers: {instance_name: {"address": (ip,port), "fingerprint":..., "nickname":...}, ...}
        """
        self.port = port
        self.fingerprint = fingerprint
        self.nickname = nickname
        self.on_peers_change = on_peers_change
        self.zeroconf = Zeroconf()
        self.info = None
        self.browser = None
        self.peers: Dict[str, dict] = {}
        self.lock = threading.Lock()

    def _get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def register_service(self):
        hostname = socket.gethostname()
        local_ip = self._get_local_ip()
        desc = {
            "fingerprint": self.fingerprint,
            "nickname": self.nickname,
        }

        info = ServiceInfo(
            SERVICE_TYPE,
            f"{hostname}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=desc,
            server=f"{hostname}.local.",
        )
        self.info = info
        self.zeroconf.register_service(info)

    def _on_service_state_change(self, zeroconf, service_type, name, state_change):
        # Consultar siempre que haya cambio de estado
        info = zeroconf.get_service_info(service_type, name)
        if info is None:
            with self.lock:
                if name in self.peers:
                    del self.peers[name]
                    self.on_peers_change(dict(self.peers))
            return

        addresses = [socket.inet_ntoa(a) for a in info.addresses]
        if not addresses:
            return
        ip = addresses[0]
        port = info.port
        props = {k.decode(): v.decode() for k, v in info.properties.items()}

        with self.lock:
            self.peers[name] = {
                "address": (ip, port),
                "fingerprint": props.get("fingerprint", ""),
                "nickname": props.get("nickname", ""),
            }
            self.on_peers_change(dict(self.peers))

    def start_browsing(self):
        self.browser = ServiceBrowser(
            self.zeroconf,
            SERVICE_TYPE,
            handlers=[self._on_service_state_change],
        )

    def close(self):
        try:
            if self.info:
                self.zeroconf.unregister_service(self.info)
        finally:
            self.zeroconf.close()
