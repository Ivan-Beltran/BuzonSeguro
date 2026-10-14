
"""
Buzón Seguro
Cálculo y consulta de huellas de claves públicas.
"""

import hashlib
from pathlib import Path

from key_manager import validar_nombre


# Directorio donde se guardan las claves públicas.
BASE_DIR = Path(__file__).resolve().parent
PUBLIC_KEYS_DIR = BASE_DIR / "public_keys"


def calcular_huella(clave_publica: bytes) -> str:
    """
    Calcula la huella SHA-256 de los bytes de una clave pública.
    Devuelve el resultado hexadecimal agrupado para facilitar su lectura.
    """
    if not clave_publica:
        raise ValueError("La clave pública está vacía.")

    digest = hashlib.sha256(clave_publica).hexdigest().upper()

    # Agrupar los 64 caracteres hexadecimales en bloques de 4.
    return " ".join(
        digest[i:i + 4] for i in range(0, len(digest), 4)
    )


def obtener_huella_usuario(nombre: str, tipo: str) -> str:
    """
    Obtiene y calcula la huella de una clave pública local.

    tipo debe ser 'x25519' o 'ed25519'.
    """
    nombre = validar_nombre(nombre)

    if tipo not in ("x25519", "ed25519"):
        raise ValueError("Tipo de clave no válido.")

    ruta = PUBLIC_KEYS_DIR / f"{nombre}.{tipo}.pub"

    if not ruta.is_file():
        raise FileNotFoundError(
            f"No se encontró la clave pública de tipo {tipo} "
            f"para el usuario {nombre}."
        )

    clave_publica = ruta.read_bytes()

    # Ambas claves públicas deben tener 32 bytes en formato raw.
    if len(clave_publica) != 32:
        raise ValueError("El archivo de clave pública no es válido.")

    return calcular_huella(clave_publica)


def mostrar_huellas_usuario(nombre: str) -> None:
    """Muestra las huellas de intercambio y firma de un usuario."""
    nombre = validar_nombre(nombre)

    huella_x = obtener_huella_usuario(nombre, "x25519")
    huella_ed = obtener_huella_usuario(nombre, "ed25519")

    print(f"\nHuellas públicas de: {nombre}")
    print("-" * 60)
    print("Clave X25519 (intercambio de claves):")
    print(huella_x)
    print()
    print("Clave Ed25519 (firma digital):")
    print(huella_ed)
    print("-" * 60)
    print("Compara las huellas completas por un canal independiente.")
