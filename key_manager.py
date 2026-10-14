
"""
Buzón Seguro
Gestión de identidades y almacenamiento de claves.
"""

import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519


# Directorios de almacenamiento locales.
BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
PUBLIC_KEYS_DIR = BASE_DIR / "public_keys"


def validar_nombre(nombre: str) -> str:
    """Acepta nombres de usuario seguros para formar nombres de archivo."""
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", nombre):
        raise ValueError("Nombre de usuario no válido.")
    return nombre


def generar_identidad(nombre: str, contrasena: bytes) -> None:
    """
    Genera claves X25519 y Ed25519.
    Protege las claves privadas con una contraseña y guarda
    las claves públicas en formato binario raw.
    """
    nombre = validar_nombre(nombre)

    if not contrasena:
        raise ValueError("La contraseña no puede estar vacía.")

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_KEYS_DIR.mkdir(parents=True, exist_ok=True)

    # No sobrescribir accidentalmente una identidad existente.
    archivos = [
        KEYS_DIR / f"{nombre}.x25519.private.pem",
        KEYS_DIR / f"{nombre}.ed25519.private.pem",
        PUBLIC_KEYS_DIR / f"{nombre}.x25519.pub",
        PUBLIC_KEYS_DIR / f"{nombre}.ed25519.pub",
    ]

    if any(ruta.exists() for ruta in archivos):
        raise FileExistsError(
            "Ya existen archivos de esta identidad. "
            "No se sobrescribirán automáticamente."
        )

    # La biblioteca genera las claves usando mecanismos seguros.
    clave_privada_x = x25519.X25519PrivateKey.generate()
    clave_privada_ed = ed25519.Ed25519PrivateKey.generate()

    # Extraer las claves públicas correspondientes.
    clave_publica_x = clave_privada_x.public_key()
    clave_publica_ed = clave_privada_ed.public_key()

    # Serializar las claves privadas en PEM y cifrarlas con contraseña.
    privada_x_pem = clave_privada_x.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            contrasena
        ),
    )

    privada_ed_pem = clave_privada_ed.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            contrasena
        ),
    )

    # Las claves públicas se guardan en formato raw.
    publica_x_raw = clave_publica_x.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    publica_ed_raw = clave_publica_ed.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Guardar las claves privadas protegidas.
    (KEYS_DIR / f"{nombre}.x25519.private.pem").write_bytes(
        privada_x_pem
    )
    (KEYS_DIR / f"{nombre}.ed25519.private.pem").write_bytes(
        privada_ed_pem
    )

    # Guardar las claves públicas para compartirlas.
    (PUBLIC_KEYS_DIR / f"{nombre}.x25519.pub").write_bytes(
        publica_x_raw
    )
    (PUBLIC_KEYS_DIR / f"{nombre}.ed25519.pub").write_bytes(
        publica_ed_raw
    )

    print(f"Identidad creada para: {nombre}")
    print("Claves privadas protegidas con contraseña.")
    print("Claves públicas guardadas para su distribución.")
    print("Verifica las huellas antes de confiar en otro usuario.")
