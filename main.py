
"""
Buzón Seguro
Interfaz de línea de comandos.
"""

import argparse
from getpass import getpass
from pathlib import Path

from crypto_manager import cifrar_archivo, descifrar_archivo
from key_manager import generar_identidad
from fingerprint_manager import mostrar_huellas_usuario
from trust_manager import (
    registrar_usuario_confiable,
    verificar_usuario_confiable,
)
from audit_manager import registrar_evento, auditar_bitacora


def main() -> None:
    """Interpreta y ejecuta los comandos de la aplicación."""

    parser = argparse.ArgumentParser(
        description="Buzón Seguro: gestión segura de documentos"
    )

    subparsers = parser.add_subparsers(
        dest="accion",
        required=True,
    )

    # Generar identidad.
    generar = subparsers.add_parser(
        "generar",
        help="Generar las claves de un usuario",
    )
    generar.add_argument("--nombre", required=True)

    # Mostrar huellas públicas.
    huella = subparsers.add_parser(
        "huella",
        help="Mostrar las huellas públicas",
    )
    huella.add_argument("--usuario", required=True)

    # Registrar usuario confiable.
    confiar = subparsers.add_parser(
        "confiar",
        help="Registrar un usuario después de verificar sus huellas",
    )
    confiar.add_argument("--usuario", required=True)

    # Verificar claves de un usuario confiable.
    verificar = subparsers.add_parser(
        "verificar",
        help="Verificar las claves de un usuario confiable",
    )
    verificar.add_argument("--usuario", required=True)

    # Cifrar documento.
    cifrar = subparsers.add_parser(
        "cifrar",
        help="Cifrar un documento para otro usuario",
    )
    cifrar.add_argument(
        "--emisor",
        required=True,
        help="Usuario que envía el documento",
    )
    cifrar.add_argument(
        "--destinatario",
        required=True,
        help="Usuario que recibirá el documento",
    )
    cifrar.add_argument(
        "--archivo",
        required=True,
        help="Ruta del documento que se cifrará",
    )

    # Recibir y descifrar documento.
    recibir = subparsers.add_parser(
        "recibir",
        help="Recibir y descifrar un documento",
    )
    recibir.add_argument(
        "--destinatario",
        required=True,
        help="Usuario que recibirá el documento",
    )
    recibir.add_argument(
        "--paquete",
        required=True,
        help="Ruta del paquete cifrado",
    )

    # Auditar la integridad de la bitácora.
    subparsers.add_parser(
        "auditar",
        help="Verificar la integridad de la bitácora",
    )

    args = parser.parse_args()

    try:
        if args.accion == "generar":
            contrasena = getpass(
                "Crea una contraseña para las claves: "
            )
            confirmacion = getpass(
                "Confirma la contraseña: "
            )

            if not contrasena:
                parser.error("La contraseña no puede estar vacía.")

            if contrasena != confirmacion:
                parser.error("Las contraseñas no coinciden.")

            generar_identidad(
                nombre=args.nombre,
                contrasena=contrasena.encode("utf-8"),
            )

            registrar_evento(
                "identidad_generada",
                {"usuario": args.nombre},
            )

        elif args.accion == "huella":
            mostrar_huellas_usuario(args.usuario)

            registrar_evento(
                "huellas_consultadas",
                {"usuario": args.usuario},
            )

        elif args.accion == "confiar":
            print(
                "\nObtén las dos huellas directamente del propietario "
                "por teléfono o presencialmente."
            )
            print(
                "No uses como única referencia la carpeta compartida."
            )

            huella_x = input("\nHuella X25519 confirmada: ")
            huella_ed = input("Huella Ed25519 confirmada: ")

            registrar_usuario_confiable(
                args.usuario,
                huella_x,
                huella_ed,
            )

            registrar_evento(
                "usuario_confiable_registrado",
                {"usuario": args.usuario},
            )

        elif args.accion == "verificar":
            verificar_usuario_confiable(args.usuario)

            registrar_evento(
                "usuario_confiable_verificado",
                {"usuario": args.usuario},
            )

        elif args.accion == "cifrar":
            contrasena = getpass(
                f"Contraseña de la clave privada de {args.emisor}: "
            )

            cifrar_archivo(
                emisor=args.emisor,
                destinatario=args.destinatario,
                archivo=args.archivo,
                contrasena=contrasena.encode("utf-8"),
            )

            registrar_evento(
                "documento_cifrado",
                {
                    "emisor": args.emisor,
                    "destinatario": args.destinatario,
                    "archivo": Path(args.archivo).name,
                },
            )

        elif args.accion == "recibir":
            contrasena = getpass(
                f"Contraseña de la clave privada de "
                f"{args.destinatario}: "
            )

            descifrar_archivo(
                destinatario=args.destinatario,
                paquete=args.paquete,
                contrasena=contrasena.encode("utf-8"),
            )

            registrar_evento(
                "documento_recibido",
                {
                    "destinatario": args.destinatario,
                    "paquete": Path(args.paquete).name,
                },
            )

        elif args.accion == "auditar":
            resultado = auditar_bitacora()

            if not resultado:
                raise SystemExit(1)

    except (
        ValueError,
        FileExistsError,
        FileNotFoundError,
        PermissionError,
    ) as error:
        parser.error(str(error))

    except OSError:
        parser.error(
            "No se pudo acceder a los archivos necesarios."
        )


if __name__ == "__main__":
    main()
