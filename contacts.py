import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

CONTACTS_FILE = Path("contacts.json")


@dataclass
class Contact:
    fingerprint: str
    name: str
    first_seen: str
    last_seen: Optional[str] = None
    trusted: bool = True


def load_contacts() -> Dict[str, Contact]:
    if not CONTACTS_FILE.exists():
        return {}
    try:
        data = json.loads(CONTACTS_FILE.read_text("utf-8"))
    except json.JSONDecodeError:
        return {}

    contacts: Dict[str, Contact] = {}
    for fp, c in data.get("peers", {}).items():
        contacts[fp] = Contact(
            fingerprint=fp,
            name=c["name"],
            first_seen=c["first_seen"],
            last_seen=c.get("last_seen", c["first_seen"]),
            trusted=c.get("trusted", True),
        )
    return contacts


def save_contacts(contacts: Dict[str, Contact]) -> None:
    payload = {"peers": {fp: asdict(c) for fp, c in contacts.items()}}
    CONTACTS_FILE.write_text(json.dumps(payload, indent=2), "utf-8")


def add_or_update_contact(
    contacts: Dict[str, Contact],
    fingerprint: str,
    name: Optional[str] = None,
) -> Contact:
    """Crea o actualiza un contacto.

    - Si el contacto existe, actualiza last_seen y opcionalmente el nombre.
    - Si no existe, lo crea con el nombre dado o un alias por defecto.
    """
    now = datetime.utcnow().isoformat() + "Z"

    if fingerprint in contacts:
        c = contacts[fingerprint]
        if name:
            c.name = name
        c.last_seen = now
    else:
        display_name = name or f"Peer_{fingerprint[:6]}"
        c = Contact(
            fingerprint=fingerprint,
            name=display_name,
            first_seen=now,
            last_seen=now,
        )
        contacts[fingerprint] = c

    save_contacts(contacts)
    return c
