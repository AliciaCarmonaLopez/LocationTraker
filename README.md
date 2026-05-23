# LocationTraker

## Requisitos previos

Antes de ejecutar el servidor del fabricante, genera las claves RSA y Paillier.

### Instalar dependencias

```bash
npm install
```

### Generar claves RSA (firmas)

```bash
node generateRSAKeysfiles.js
```

Esto genera:
- `Manufacturer/rsaPublicKeyManufacturer.json`
- `Manufacturer/rsaPrivateKeyManufacturer.json`

### Generar claves Paillier (descifrado)

```bash
node generatePaillierKeysfiles.js
```

Esto genera:
- `Manufacturer/publicKeyManufacturer.json`
- `Manufacturer/privateKeyManufacturer.json`

## Ejecutar el sistema (orden obligatorio)

### 1. Arrancar el servidor del fabricante

```bash
node Manufacturer/manufacturer.js  cd /mnt/c/Users/NitroPC/Desktop/sciotra/LocationTraker-main (HUGO solo)
```
### 2. Arrancar el auth server

```bash
node Manufacturer/authServer.js
```

### 3. Arrancar el device

```bash
node Device/device.js
```
## Flujo de onboarding

### 1. Abre el navegador en la URL de la "pegatina" del dispositivo: http://localhost:5041/pegatina

### 2. Haz clic en Autenticarse en AuthServer.

### 3. Haz login con cualquier usuario y password 1234.

### 4. Confirma la instalación.

### 5. De vuelta en la interfaz del dispositivo (Device UI Paso 2), pulsa Access Request para obtener el token.

### 6. Se abrirá la pantalla UI Device 3. Pulsa Firma Ciega para preparar el certificado cegado.

### 7. Cuando aparezca el botón Enviar certificado cegado, púlsalo para enviarlo al AuthServer y completar la firma ciega.