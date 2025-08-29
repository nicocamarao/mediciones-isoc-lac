# Proyecto mediciones ISOC LAC

Este repositorio incluye una interfaz web y un servidor Node.js para realizar mediciones de dominios.

## Uso del servidor

Instala las dependencias (no se requieren paquetes externos) y levanta el servidor:

```
npm start
```

### Endpoints

- `GET /mx/:dominio` – obtiene los registros MX del dominio.
- `GET /smtputf8/:dominio` – conecta vía Telnet/EHLO a los servidores MX (puertos 25 y 587) para detectar el anuncio de `SMTPUTF8`, reportando tiempos de espera y errores de conexión.
- `GET /dnssec/:dominio` – consulta la presencia de DS/DNSKEY utilizando el resolvedor local y la API de Google DNS.
- `GET /dkim/:dominio?selector=default` – busca un registro DKIM para el selector indicado.
- `GET /rpki/:dominio` – valida las direcciones IPv4 del dominio contra las APIs de Cloudflare, RIPE `rpki-validation` y el resumen de RIPE Stat.

El cliente web en `index.html` consume estos endpoints y muestra los resultados de cada método para una verificación más resiliente.
