
"""
Buzón Seguro
Registro y verificación de claves públicas confiables.
"""

import json
import re
from pathlib import Path

from fingerprint_manager import obtener_huella_usuario
from key_manager import validar_nombre


BASE_DIR = Path(__file__).resolve().parent
TRUST_FILE = BASE_DIR / "trusted_keys.json"


def normalizar_huella(huella: str) -> str:
    """Elimina espacios y convierte la huella a mayúsculas."""
    return re.sub(r"\s+", "", huella).upper()


def cargar_registro() -> dict:
    """Carga el registro local de usuarios confiables."""
    if not TRUST_FILE.exists():
        return {}

    try:
        datos = json.loads(TRUST_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(
            "El registro de confianza está dañado. "
            "No se modificará automáticamente."
        ) from error

    if not isinstance(datos, dict):
        raise ValueError("El formato del registro de confianza no es válido.")

    return datos


def guardar_registro(registro: dict) -> None:
    """Guarda el registro mediante un archivo temporal."""
    temporal = TRUST_FILE.with_suffix(".tmp")

    try:
        temporal.write_text(
            json.dumps(registro, indent=4, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporal.replace(TRUST_FILE)
    finally:
        if temporal.exists():
            temporal.unlink()


def registrar_usuario_confiable(
    nombre: str,
    huella_x_confirmada: str,
    huella_ed_confirmada: str,
) -> None:
    """
    Registra un usuario solo si ambas huellas coinciden
    con las comunicadas por un canal independiente.
    """
    nombre = validar_nombre(nombre)
    registro = cargar_registro()

    if nombre in registro:
        raise ValueError(
            f"{nombre} ya tiene un registro de confianza. "
            "No se actualizará automáticamente. "
            "Investiga cualquier cambio de claves antes de "
            "establecer una nueva confianza."
        )

    huella_x_local = normalizar_huella(
        obtener_huella_usuario(nombre, "x25519")
    )
    huella_ed_local = normalizar_huella(
        obtener_huella_usuario(nombre, "ed25519")
    )

    if (
        normalizar_huella(huella_x_confirmada) != huella_x_local
        or normalizar_huella(huella_ed_confirmada) != huella_ed_local
    ):
        raise ValueError(
            "VERIFICACIÓN FALLIDA: las huellas no coinciden. "
            "El usuario no se ha registrado como confiable."
        )

    registro[nombre] = {
        "x25519": huella_x_local,
        "ed25519": huella_ed_local,
    }

    guardar_registro(registro)

    print(f"Usuario confiable registrado: {nombre}")
    print("Las dos huellas coincidieron con las confirmadas.")


def verificar_usuario_confiable(nombre: str) -> bool:
    """
    Compara las claves públicas actuales con las huellas
    registradas previamente.
    """
    nombre = validar_nombre(nombre)
    registro = cargar_registro()

    if nombre not in registro:
        print(f"NO CONFIABLE: {nombre} no está registrado.")
        print("Verifica sus huellas por un canal independiente.")
        return False

    datos = registro[nombre]

    if not isinstance(datos, dict):
        raise ValueError("El registro de este usuario no es válido.")

    huella_x_actual = normalizar_huella(
        obtener_huella_usuario(nombre, "x25519")
    )
    huella_ed_actual = normalizar_huella(
        obtener_huella_usuario(nombre, "ed25519")
    )

    if (
        datos.get("x25519") != huella_x_actual
        or datos.get("ed25519") != huella_ed_actual
    ):
        print("¡ALERTA! Las claves públicas han cambiado.")
        print("No confíes en las nuevas claves automáticamente.")
        print("Verifica el cambio con el propietario por otro canal.")
        return False

    print(f"CONFIANZA VERIFICADA: {nombre}")
    print("Las dos claves coinciden con el registro.")
    return True
