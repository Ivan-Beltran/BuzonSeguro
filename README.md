# Buzón Seguro

Aplicación de línea de comandos desarrollada en Python para proteger el intercambio de documentos mediante cifrado, firmas digitales y verificación de claves públicas.

## Requisitos

- Python instalado.
- Dependencias del proyecto instaladas.

Para instalar las dependencias, ejecuta:

```bash
python -m pip install -r requirements.txt
```

## Uso de la aplicación

Ejecuta los siguientes comandos desde la carpeta raíz del proyecto.

### 1. Generar claves de usuario

Genera la identidad criptográfica de un usuario, incluyendo sus claves privadas y públicas protegidas según el diseño del sistema.

```bash
python main.py generar --nombre "nombre usuario"
```

**Ejemplo:**

```bash
python main.py generar --nombre "ana.martinez"
```

Durante el proceso, se solicitará una contraseña para proteger las claves privadas.

### 2. Verificar el par de claves

Comprueba el par de claves asociado a un usuario.

```bash
python main.py verificar --usuario "ana.martinez"
```

### 3. Consultar las huellas digitales

Muestra las huellas de las claves públicas del usuario. Estas permiten identificar las claves y compararlas con las obtenidas directamente del propietario.

```bash
python main.py huella --usuario "usuario"
```

**Ejemplo:**

```bash
python main.py huella --usuario "ana.martinez"
```

El sistema muestra las huellas correspondientes a:

- **X25519:** intercambio de claves.
- **Ed25519:** firma digital.

### 4. Confirmar las claves de un usuario

Antes de confiar en las claves públicas de otro usuario, compara sus huellas completas mediante un canal independiente y seguro, por ejemplo, presencialmente o por teléfono.

```bash
python main.py confiar --usuario "usuario"
```

**Ejemplo:**

```bash
python main.py confiar --usuario "ana.martinez"
```

> **Importante:** el comando `huella` solamente consulta las huellas. Para registrar la confianza en las claves, utiliza el comando `confiar` y confirma que las huellas coincidan con las proporcionadas directamente por el propietario.

### 5. Cifrar un documento

Cifra un documento para un destinatario, utilizando la identidad del emisor y la del destinatario.

```bash
python main.py cifrar --emisor "usuario_emisor" --destinatario "usuario_destinatario" --archivo "ruta/nombre/archivo"
```

**Ejemplo:**

```bash
python main.py cifrar --emisor "ana.martinez" --destinatario "ivan" --archivo "documentos/informe.pdf"
```

El archivo de entrada debe existir y el emisor y el destinatario deben tener sus identidades correctamente configuradas. Si el sistema exige verificar las claves del destinatario, estas deben estar previamente registradas como confiables.

### 6. Recibir un documento

Permite al destinatario procesar un paquete cifrado y recuperar el documento, verificando las condiciones de seguridad implementadas por la aplicación.

```bash
python main.py recibir --destinatario "usuario" --paquete "ruta/paquete"
```

**Ejemplo:**

```bash
python main.py recibir --destinatario "ivan" --paquete "paquetes/informe.buzon"
```

El destinatario debe disponer de sus claves privadas y de la contraseña correspondiente cuando la aplicación la solicite.

## Flujo de trabajo recomendado

1. Generar las identidades criptográficas de los usuarios.
2. Consultar las huellas de las claves públicas.
3. Intercambiar y comparar las huellas mediante un canal independiente.
4. Registrar como confiables las claves verificadas.
5. Cifrar el documento para el destinatario.
6. Entregar el paquete cifrado al destinatario.
7. Recibir y procesar el paquete para recuperar el documento.

## Consideraciones de seguridad

- No compartir las claves privadas ni sus contraseñas.
- Distribuir las claves públicas y verificar sus huellas antes de confiar en ellas.
- No confiar en una clave únicamente porque aparece en una carpeta compartida.
- Conservar una copia de seguridad segura de las claves y de los registros de confianza.
- No modificar manualmente los registros de confianza para evitar las validaciones de seguridad.

## Tecnologías

- Python
- X25519 para intercambio de claves.
- Ed25519 para firmas digitales.
- Criptografía y verificación de integridad, según la implementación del proyecto.

