"""
Buzón Seguro
Bitácora de auditoría con cadena de hashes SHA-256.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUTA_BITACORA = Path(__file__).resolve().parent / "bitacora.jsonl"

# Hash anterior para el primer registro de la cadena.
HASH_INICIAL = "0" * 64


def calcular_hash(registro: dict[str, Any]) -> str:
    """
    Calcula el hash SHA-256 del registro sin incluir su propio hash.
    La serialización canónica permite repetir el cálculo al auditar.
    """
    contenido = {
        clave: valor
        for clave, valor in registro.items()
        if clave != "hash"
    }

    contenido_json = json.dumps(
        contenido,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        contenido_json.encode("utf-8")
    ).hexdigest()


def registrar_evento(
    evento: str,
    detalles: dict[str, Any] | None = None,
) -> None:
    """
    Añade un evento al final de la bitácora.

    Cada registro contiene:
    - Número de línea.
    - Fecha y hora UTC.
    - Tipo de evento.
    - Detalles no sensibles.
    - Hash del registro anterior.
    - Hash del registro actual.
    """
    if detalles is None:
        detalles = {}

    hash_anterior = HASH_INICIAL
    numero = 1

    if RUTA_BITACORA.exists():
        with RUTA_BITACORA.open("rb") as archivo:
            for linea in archivo:
                if linea.strip():
                    numero += 1

        # Obtener el hash almacenado en el último registro.
        with RUTA_BITACORA.open("r", encoding="utf-8") as archivo:
            for linea in archivo:
                if linea.strip():
                    registro_anterior = json.loads(linea)
                    hash_anterior = registro_anterior["hash"]

    registro = {
        "numero": numero,
        "fecha_utc": datetime.now(timezone.utc).isoformat(),
        "evento": evento,
        "detalles": detalles,
        "hash_anterior": hash_anterior,
    }

    registro["hash"] = calcular_hash(registro)

    with RUTA_BITACORA.open("a", encoding="utf-8") as archivo:
        archivo.write(
            json.dumps(
                registro,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )


def auditar_bitacora() -> bool:
    """
    Verifica la integridad de la cadena y señala
    la primera línea que presenta una inconsistencia.
    """
    print("\n=== Auditoría de Buzón Seguro ===")

    if not RUTA_BITACORA.exists():
        print("[AVISO] Todavía no existe una bitácora.")
        print("No hay registros que verificar.")
        return True

    hash_anterior_esperado = HASH_INICIAL
    registros_verificados = 0

    try:
        with RUTA_BITACORA.open(
            "r", encoding="utf-8"
        ) as archivo:

            for numero_linea, linea in enumerate(archivo, start=1):

                if not linea.strip():
                    print(
                        f"[ERROR] Primera línea inconsistente: "
                        f"{numero_linea}"
                    )
                    print("Motivo: línea vacía o eliminada.")
                    return False

                try:
                    registro = json.loads(linea)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    print(
                        f"[ERROR] Primera línea alterada: "
                        f"{numero_linea}"
                    )
                    print("Motivo: el registro no contiene JSON válido.")
                    return False

                if not isinstance(registro, dict):
                    print(
                        f"[ERROR] Primera línea alterada: "
                        f"{numero_linea}"
                    )
                    print("Motivo: formato de registro inválido.")
                    return False

                # Verificar que el número corresponda a su posición.
                if registro.get("numero") != numero_linea:
                    print(
                        f"[ERROR] Primera línea inconsistente: "
                        f"{numero_linea}"
                    )
                    print("Motivo: número de registro incorrecto.")
                    return False

                # Verificar el enlace con la línea anterior.
                if registro.get("hash_anterior") != hash_anterior_esperado:
                    print(
                        f"[ERROR] Primera línea alterada: "
                        f"{numero_linea}"
                    )
                    print("Motivo: el hash anterior no coincide.")
                    return False

                hash_guardado = registro.get("hash")

                if not isinstance(hash_guardado, str):
                    print(
                        f"[ERROR] Primera línea alterada: "
                        f"{numero_linea}"
                    )
                    print("Motivo: falta el hash del registro.")
                    return False

                # Recalcular el hash del registro actual.
                hash_calculado = calcular_hash(registro)

                if hash_calculado != hash_guardado:
                    print(
                        f"[ERROR] Primera línea alterada: "
                        f"{numero_linea}"
                    )
                    print(
                        "Motivo: el hash calculado no coincide "
                        "con el hash almacenado."
                    )
                    return False

                hash_anterior_esperado = hash_guardado
                registros_verificados += 1

    except (OSError, UnicodeError) as error:
        print("[ERROR] No se pudo leer la bitácora.")
        print(f"Detalle: {error}")
        return False

    print("[OK] Bitácora íntegra.")
    print(f"Registros verificados: {registros_verificados}")
    print("No se detectaron alteraciones en la cadena.")

    return True
