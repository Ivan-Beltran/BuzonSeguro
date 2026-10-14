
"""
Buzón Seguro
Cifrado y firma de documentos según el formato del proyecto.
"""

import base64
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from key_manager import validar_nombre
from trust_manager import verificar_usuario_confiable


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_KEYS_DIR = BASE_DIR / "public_keys"
KEYS_DIR = BASE_DIR / "keys"
OUTBOX_DIR = BASE_DIR / "outbox"
DECRYPTED_DIR = BASE_DIR / "decrypted"

VERSION = "buzon-seguro-v1"


def obtener_ruta_unica(
    carpeta: Path,
    nombre_base: str,
    extension: str,
) -> Path:
    """
    Genera una ruta que no exista previamente.

    Ejemplos:
        documento.enc.json
        documento (1).enc.json
        documento (2).enc.json
    """
    ruta = carpeta / f"{nombre_base}{extension}"
    contador = 1

    while ruta.exists():
        ruta = carpeta / f"{nombre_base} ({contador}){extension}"
        contador += 1

    return ruta


def codificar_base64(datos: bytes) -> str:
    """Codifica bytes en Base64 ASCII."""
    return base64.b64encode(datos).decode("ascii")


def serializar_json(datos: dict) -> bytes:
    """Genera una representación JSON determinista."""
    return json.dumps(
        datos,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def derivar_clave(secreto_compartido: bytes) -> bytes:
    """Deriva una clave AES-256 mediante HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"buzon-seguro-v1",
    ).derive(secreto_compartido)


def cargar_clave_publica_x25519(nombre: str):
    """Carga la clave pública X25519 del destinatario."""
    nombre = validar_nombre(nombre)
    ruta = PUBLIC_KEYS_DIR / f"{nombre}.x25519.pub"

    if not ruta.is_file():
        raise FileNotFoundError(
            f"No existe la clave pública X25519 de {nombre}."
        )

    datos = ruta.read_bytes()

    if len(datos) != 32:
        raise ValueError(
            "La clave pública X25519 debe tener 32 bytes."
        )

    return x25519.X25519PublicKey.from_public_bytes(datos)


def cargar_clave_privada_ed25519(
    nombre: str,
    contrasena: bytes,
):
    """Carga la clave privada Ed25519 protegida por contraseña."""
    nombre = validar_nombre(nombre)
    ruta = KEYS_DIR / f"{nombre}.ed25519.private.pem"

    if not ruta.is_file():
        raise FileNotFoundError(
            f"No existe la clave privada de firma de {nombre}."
        )

    clave = serialization.load_pem_private_key(
        ruta.read_bytes(),
        password=contrasena,
    )

    if not isinstance(clave, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada no es Ed25519.")

    return clave


def cifrar_archivo(
    emisor: str,
    destinatario: str,
    archivo: str,
    contrasena: bytes,
) -> Path:
    """Cifra un archivo, genera su hash y firma el paquete."""

    emisor = validar_nombre(emisor)
    destinatario = validar_nombre(destinatario)

    if emisor == destinatario:
        raise ValueError(
            "El emisor y el destinatario deben ser distintos."
        )

    ruta_entrada = Path(archivo)

    if not ruta_entrada.is_file():
        raise FileNotFoundError(
            f"No se encontró el documento: {ruta_entrada}"
        )

    # Verificar las claves del destinatario antes de cifrar.
    if not verificar_usuario_confiable(destinatario):
        raise ValueError(
            f"VERIFICACIÓN FALLIDA: las claves públicas de "
            f"{destinatario} no coinciden con las registradas "
            "mediante el comando 'confiar'. "
            "No se ha creado ningún paquete cifrado."
        )

    # Verificar que las claves públicas necesarias existan
    # y tengan el formato esperado antes de continuar.
    clave_publica_destinatario = cargar_clave_publica_x25519(
        destinatario
    )

    ruta_firma_destinatario = (
        PUBLIC_KEYS_DIR / f"{destinatario}.ed25519.pub"
    )

    if not ruta_firma_destinatario.is_file():
        raise FileNotFoundError(
            f"No existe la clave pública Ed25519 de {destinatario}."
        )

    datos_firma_destinatario = ruta_firma_destinatario.read_bytes()

    if len(datos_firma_destinatario) != 32:
        raise ValueError(
            f"La clave pública Ed25519 de {destinatario} "
            "no tiene el tamaño esperado. No se cifrará."
        )


    clave_privada_firma = cargar_clave_privada_ed25519(
        emisor,
        contrasena,
    )

    # Leer el archivo original y calcular su SHA-256.
    datos_originales = ruta_entrada.read_bytes()
    hash_original = hashlib.sha256(datos_originales).hexdigest()

    # Preparar el contenido que será cifrado.
    contenido_interno = {
        "sha256_original": hash_original,
        "datos": codificar_base64(datos_originales),
    }
    bytes_internos = serializar_json(contenido_interno)

    # Generar una clave X25519 efímera nueva para cada envío.
    clave_privada_efimera = x25519.X25519PrivateKey.generate()
    clave_publica_efimera = clave_privada_efimera.public_key()

    efimera_pub = clave_publica_efimera.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Calcular ECDH y derivar la clave AES.
    secreto = clave_privada_efimera.exchange(
        clave_publica_destinatario
    )
    clave_aes = derivar_clave(secreto)

    # Generar un nonce nuevo de 12 bytes.
    nonce = os.urandom(12)

    # Metadatos del paquete.
    metadatos = {
        "remitente": emisor,
        "destinatario": destinatario,
        "fecha": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "archivo": ruta_entrada.name,
    }

    bytes_metadatos = serializar_json(metadatos)

    # Cifrar y autenticar el contenido mediante AES-GCM.
    cifrado = AESGCM(clave_aes).encrypt(
        nonce,
        bytes_internos,
        bytes_metadatos,
    )

    # Firmar el paquete con Ed25519.
    mensaje_firmado = (
        efimera_pub
        + nonce
        + bytes_metadatos
        + cifrado
    )
    firma = clave_privada_firma.sign(mensaje_firmado)

    # Construir el paquete JSON.
    paquete = {
        "version": VERSION,
        "metadatos": metadatos,
        "efimera_pub": codificar_base64(efimera_pub),
        "nonce": codificar_base64(nonce),
        "cifrado": codificar_base64(cifrado),
        "firma": codificar_base64(firma),
    }

    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)

    # Nombre corto y sin sobrescribir paquetes existentes.
    # Ejemplo: notas.enc.json, notas (1).enc.json.
    ruta_salida = obtener_ruta_unica(
        OUTBOX_DIR,
        ruta_entrada.stem,
        ".buzon",
    )

    # Modo exclusivo: no sobrescribe un archivo existente.
    with ruta_salida.open("x", encoding="utf-8") as salida:
        json.dump(
            paquete,
            salida,
            indent=2,
            ensure_ascii=False,
        )
        salida.write("\n")

    print("Documento cifrado y firmado correctamente.")
    print(f"Remitente: {emisor}")
    print(f"Destinatario: {destinatario}")
    print(f"Archivo generado: {ruta_salida}")

    return ruta_salida


def descifrar_archivo(
    destinatario: str,
    paquete: str,
    contrasena: bytes,
):
    """Verifica la firma, descifra y recupera el documento original."""

    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    destinatario = validar_nombre(destinatario)
    ruta_paquete = Path(paquete)

    if not ruta_paquete.is_file():
        raise FileNotFoundError(
            f"No existe el paquete: {ruta_paquete}"
        )

    # Leer el paquete JSON.
    with ruta_paquete.open("r", encoding="utf-8") as archivo:
        paquete_json = json.load(archivo)

    if paquete_json.get("version") != VERSION:
        raise ValueError("Versión de paquete no compatible.")

    metadatos = paquete_json["metadatos"]
    emisor = validar_nombre(metadatos["remitente"])

    if metadatos["destinatario"] != destinatario:
        raise ValueError(
            "El paquete no está destinado a este usuario."
        )

    # Comprobar la confianza del remitente.
    if not verificar_usuario_confiable(emisor):
        raise ValueError(
            f"El remitente {emisor} no tiene claves verificadas."
        )

    def decodificar(campo):
        return base64.b64decode(
            paquete_json[campo],
            validate=True,
        )

    efimera_pub_bytes = decodificar("efimera_pub")
    nonce = decodificar("nonce")
    cifrado = decodificar("cifrado")
    firma = decodificar("firma")

    # Reconstruir exactamente los metadatos firmados.
    bytes_metadatos = serializar_json(metadatos)

    ruta_firma = (
        PUBLIC_KEYS_DIR / f"{emisor}.ed25519.pub"
    )

    if not ruta_firma.is_file():
        raise FileNotFoundError(
            f"No existe la clave pública de firma: {ruta_firma}"
        )

    clave_publica_firma = Ed25519PublicKey.from_public_bytes(
        ruta_firma.read_bytes()
    )

    mensaje_firmado = (
        efimera_pub_bytes
        + nonce
        + bytes_metadatos
        + cifrado
    )

    # Verificar la firma ANTES de descifrar.
    try:
        clave_publica_firma.verify(
            firma,
            mensaje_firmado,
        )
    except InvalidSignature as exc:
        raise ValueError(
            "Firma inválida: el paquete pudo ser alterado."
        ) from exc

    # Cargar la clave privada X25519 del destinatario.
    ruta_privada = (
        KEYS_DIR / f"{destinatario}.x25519.private.pem"
    )

    if not ruta_privada.is_file():
        raise FileNotFoundError(
            f"No existe la clave privada: {ruta_privada}"
        )

    clave_privada = serialization.load_pem_private_key(
        ruta_privada.read_bytes(),
        password=contrasena,
    )

    # Derivar la misma clave AES que utilizó el emisor.
    clave_efimera = X25519PublicKey.from_public_bytes(
        efimera_pub_bytes
    )

    secreto_compartido = clave_privada.exchange(
        clave_efimera
    )
    clave_aes = derivar_clave(secreto_compartido)

    # AES-GCM comprueba también la autenticidad del contenido.
    try:
        contenido_json = AESGCM(clave_aes).decrypt(
            nonce,
            cifrado,
            bytes_metadatos,
        )
    except InvalidTag as exc:
        raise ValueError(
            "No se pudo autenticar el contenido cifrado."
        ) from exc

    # Recuperar el documento original.
    contenido = json.loads(contenido_json)

    datos_originales = base64.b64decode(
        contenido["datos"],
        validate=True,
    )

    hash_calculado = hashlib.sha256(
        datos_originales
    ).hexdigest()

    if hash_calculado != contenido["sha256_original"]:
        raise ValueError(
            "El SHA-256 no coincide. No se guardará el documento."
        )

    # Guardar únicamente después de verificar todo.
    DECRYPTED_DIR.mkdir(parents=True, exist_ok=True)

    nombre_archivo = Path(metadatos["archivo"]).name

    if nombre_archivo in ("", ".", ".."):
        raise ValueError("Nombre de archivo no válido.")

    # Conservar nombre y extensión; agregar (1), (2), etc.
    nombre_original = Path(nombre_archivo)

    ruta_salida = obtener_ruta_unica(
        DECRYPTED_DIR,
        nombre_original.stem,
        nombre_original.suffix,
    )

    # Modo exclusivo: nunca sobrescribir un documento existente.
    with ruta_salida.open("xb") as archivo:
        archivo.write(datos_originales)

    print("Documento recibido y verificado correctamente.")
    print(f"Remitente: {emisor}")
    print(f"Archivo recuperado: {ruta_salida}")
    print(f"SHA-256: {hash_calculado}")
