# Proyecto mediciones ISOC LAC

Este repositorio incluye una interfaz web y un servidor Node.js para realizar mediciones de dominios.

## Uso del servidor

Instala las dependencias (no se requieren paquetes externos) y levanta el servidor:

```
npm start
```

### Endpoints

- `GET /mx/:dominio` – obtiene los registros MX del dominio.
- `GET /smtputf8/:dominio` – verifica si los servidores MX anuncian soporte para SMTPUTF8.
- `GET /dnssec/:dominio` – informa si existe DS en el padre y DNSKEY en el hijo.
- `GET /dkim/:dominio?selector=default` – busca un registro DKIM para el selector indicado.
- `GET /rpki/:dominio` – intenta recuperar información RPKI de las direcciones del dominio.

El cliente web en `index.html` consume estos endpoints para ampliar las mediciones disponibles.
