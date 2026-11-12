# Demo local de Recon Scope

El motor de Recon Scope **tal cual está en `apps/engine`**, con sitios de práctica propios y una **consola guiada** con botones, todo en esta computadora y con un solo comando. Sirve para ver el producto funcionando de punta a punta, sin revisar ningún sitio real: se registra un dominio, se demuestra que es propio, se escanea desde afuera, se leen los hallazgos en lenguaje claro y se comprueba cómo cambia el informe al corregir el problema.

```
Consola guiada ──▶ Motor de Recon Scope (apps/engine) ──▶ Sitios de práctica
 localhost:4100      API /api/v1 + PostgreSQL              tienda-demo.test            (sano, certificado vigente)
                                                           pruebas.tienda-demo.test    (el servidor que nadie recordaba)
                                                           crt.sh                      (registro de certificados de práctica)
```

El motor, la base y los sitios viven en una red de Docker **sin salida**: no pueden hablar con internet ni con la red local. Lo que muestra la consola es el resultado verdadero del motor, no una animación.

## Qué se necesita

- **Docker Desktop** (Windows con WSL2, macOS o Linux) o Docker Engine con Compose v2. Comprobar con `docker compose version`.
- Unos 2 GB libres y conexión a internet **solo para construir** la primera vez (imágenes y paquetes). Después funciona sin internet.

## Arrancar

Desde una terminal (PowerShell, cmd, bash), en la carpeta `demo/` del repositorio:

```bash
cd demo
docker compose up --build
```

La primera vez tarda unos minutos porque construye las imágenes. Cuando aparece `Consola de la demo lista`, abrir **http://localhost:4100**. Arriba dice **Sistema listo** cuando el motor ya responde.

Para dejarlo en segundo plano, esperando a que todo esté sano, y apagarlo después:

```bash
docker compose up -d --build --wait
docker compose down
```

## Cómo usarla

La página propone seis pasos, en orden. Cada uno deja constancia en **Lo que va pasando**, y **Sitios de práctica** muestra qué es cada sitio.

| Paso | Qué hacer | Qué se ve |
|---|---|---|
| 1. Crear cuenta | Aceptar los términos de la demo y pulsar **Crear la cuenta de práctica** | Una cuenta descartable en el motor: el producto trabaja con cuentas |
| 2. Registrar el dominio | **Registrar tienda-demo.test** | El motor entrega un código de verificación. Todavía no escanea nada |
| 3. Demostrar que el dominio es propio | **Probar un escaneo ahora** → **Verificar propiedad** → **Publicar el archivo en el sitio** → **Verificar propiedad** | El motor se **niega** a escanear un dominio sin verificar. Sin el archivo, la verificación falla. Con el archivo publicado (es lo que haría un cliente real), el motor lo pide por HTTPS, comprueba el certificado y el contenido, y da la propiedad por demostrada |
| 4. Escanear desde afuera | Elegir cuántos puertos probar y pulsar **Iniciar escaneo** | Barra de avance: subdominios, puertos y sitios web |
| 5. Qué se encontró | Leer los hallazgos | Cada uno dice qué es, dónde está y qué hacer. **Detalle técnico del escaneo** y **Descargar el informe completo (JSON)** muestran lo que dijo el motor, sin traducir |
| 6. Corregir y comparar | **Apagar el servidor de pruebas** → **Escanear de nuevo** | El informe baja de 8 hallazgos a 1 |

Resultado esperado del primer escaneo (`2 altos, 1 medio, 5 bajos`):

| Hallazgo | Gravedad | Dónde |
|---|---|---|
| Una base de datos está accesible desde la red | alto | servidor de pruebas, puerto 3306 |
| El certificado de seguridad no es válido | alto | servidor de pruebas |
| El acceso remoto (SSH) está abierto a la red | medio | servidor de pruebas, puerto 22 |
| El servidor anuncia su versión exacta | bajo | servidor de pruebas |
| Faltan tres protecciones del navegador (política de contenido, protección contra incrustación, obligación de usar HTTPS) | bajo (3) | servidor de pruebas |
| Falta la política de contenido | bajo | la tienda |

Con el servidor de pruebas apagado queda **un solo hallazgo bajo** (el de la tienda). **Reiniciar el recorrido** (pide confirmación) borra el dominio y los escaneos y deja todo listo para empezar de nuevo; la cuenta de práctica se conserva.

> El motor informa el certificado vencido como «no es válido», sin fechas: cuando un certificado no pasa la validación, el motor no llega a leer sus datos. La consola no inventa lo que el motor no dijo.

## Direcciones y puertos

| Qué | Dirección | Variable para cambiar el puerto |
|---|---|---|
| Consola guiada | http://localhost:4100 | `DEMO_CONSOLE_PORT` |

Es el único puerto que se publica, y solo en `127.0.0.1`. Si está ocupado, elegir otro **antes de encender**:

```powershell
# PowerShell
$env:DEMO_CONSOLE_PORT = 4200
docker compose up --build
```

```bash
# bash / zsh
DEMO_CONSOLE_PORT=4200 docker compose up --build
```

## Apagar, reiniciar y empezar de cero

| Comando | Efecto |
|---|---|
| `Ctrl + C` (en primer plano) o `docker compose down` | Apaga todo. La base vive en memoria: la próxima vez empieza vacía (hay que crear la cuenta otra vez). |
| `docker compose down -v` | Además borra las credenciales y los certificados generados; la próxima vez se crean otros. |
| `docker compose up` (sin `--build`) | Vuelve a encender sin reconstruir. |
| `docker compose restart engine` | Reinicia el motor sin perder la cuenta ni los escaneos. Pone en cero el contador de escaneos (ver abajo). |

El motor permite **10 escaneos por hora** por cuenta (es un límite del producto, no de la demo). Alcanza para muchas pasadas; si hiciera falta más, `docker compose restart engine` lo pone en cero.

## Prueba de aceptación en Docker Desktop

Lo que sigue confirma que la demo anda en una computadora real. Lleva unos 15 minutos la primera vez.

1. **Encender.** `cd demo` y `docker compose up --build`. Esperar `Consola de la demo lista` y abrir http://localhost:4100: arriba debe decir **Sistema listo**.
2. **Estado de los servicios.** En otra terminal, `docker compose ps -a`: `init` termina con código 0 (`Exited (0)`) y `postgres`, `engine` y `console` figuran como `healthy`.
3. **Prueba de humo automática.** Desde la carpeta `demo`:

   ```bash
   python tests/smoke.py          # en Windows también sirve:  python tests\smoke.py   (o py tests\smoke.py)
   ```

   Necesita solo Python 3.8 o más nuevo (sin instalar nada). Recorre los seis pasos contra el motor verdadero y debe terminar con `RESULTADO: todo en orden (11 comprobaciones...)`. Si el puerto no es el 4100, agregar `--port 4200`. Si falla, dice en qué paso y qué esperaba, y deja la demo reiniciada.

   **Aviso:** la prueba acepta los términos de la demo *en nombre de quien la corre*, y reinicia la demo al empezar y al terminar (borra el dominio y los escaneos de práctica). Está pensada para que la corra el dueño de la demo, en su computadora.
4. **Recorrido a mano.** En el navegador, seguir los seis pasos de la tabla de arriba. Debe verse `2 altos, 1 medio, 5 bajos` y, después de apagar el servidor de pruebas, `1 bajo`.
5. **Comprobaciones de seguridad.**
   - El motor no tiene salida a internet: este comando **debe terminar con un error** (no con una página):

     ```bash
     docker compose exec engine python -c "import urllib.request; urllib.request.urlopen('http://example.com', timeout=5)"
     ```
   - Solo la consola publica un puerto: en `docker compose ps`, únicamente la consola figura con una flecha, `127.0.0.1:4100->8080/tcp`. Los demás, como mucho, muestran un puerto sin flecha (por ejemplo `5432/tcp`), que es solo informativo y no está publicado.
   - Los contenedores propios corren sin root: `docker compose exec console id -u` debe imprimir `10002`.
6. **Apagar.** `docker compose down` (o `docker compose down -v` para empezar de cero).

Si algo de esto no da lo esperado, pasar la salida de `docker compose ps` y de `docker compose logs --tail 80 console engine`.

## Seguridad de la demo

- **Solo local y sin salida.** La red `lab` es `internal: true`: el motor, la base y los sitios de práctica no pueden hablar con internet ni con la red local. Es lo que permite que el motor acepte las direcciones privadas de los sitios de práctica (`ALLOW_PRIVATE_TARGETS=true`, que en producción **tiene que ser `false`**) sin riesgo: no tiene a dónde ir fuera de la demo. Solo la consola se publica, y solo en `127.0.0.1`.
- **Los únicos objetivos posibles son los sitios de práctica.** Los nombres `.test` están reservados para pruebas (RFC 6761): no existen en internet. El registro de certificados que consulta el motor (`crt.sh`) también es un sitio de práctica dentro de la red de la demo. La demo **no escanea nada de nadie**.
- **El motor no se modifica.** Es el de `apps/engine`, con otras variables de entorno. Sigue verificando certificados y propiedad de dominios igual que siempre: la única diferencia es que reconoce a la autoridad de certificación de la demo (`SSL_CERT_FILE`).
- **Sin credenciales en el repositorio.** La primera vez, el servicio `init` (`init.py`) genera al azar el secreto del motor, la contraseña de la base y la de la cuenta de práctica, y los guarda en un volumen de Docker. No se imprimen. La clave privada de la autoridad de certificación de la demo se descarta apenas firma los certificados: no queda forma de emitir más.
- **Servicios inertes.** Los puertos de FTP, SSH y base de datos del servidor de pruebas solo muestran el saludo con el que se anuncia cada programa: no hay archivos, ni usuarios, ni datos.
- **La consola solo atiende a su propia página.** Controla `Host` (contra rebinding de DNS) y `Origin` (otro sitio abierto en el navegador no puede dispararla), limita el tamaño de los pedidos, usa una política de contenido estricta (sin código en línea) y escribe en pantalla solo como texto.
- **Contenedores acotados.** La consola y los sitios de práctica corren sin root, con el sistema de archivos de solo lectura, sin privilegios extra y sin capacidades de Linux; el motor también va sin privilegios extra y sin capacidades. La base vive en memoria.
- Esto es una demo en una computadora personal: no está pensada para exponerse en una red ni en internet.

## Problemas frecuentes

| Síntoma | Qué hacer |
|---|---|
| `Cannot connect to the Docker daemon` | Abrir Docker Desktop y esperar a que indique que el motor de Docker está en ejecución. |
| El puerto 4100 está ocupado | Elegir otro con `DEMO_CONSOLE_PORT` (ver arriba) y encender de nuevo. |
| La consola sigue en «Esperando que el motor termine de arrancar…» pasado un minuto | `docker compose ps` y `docker compose logs --tail 80 engine postgres`. |
| «La cuenta de práctica ya no existe en el motor» | Se reinició la base (vive en memoria). Crear la cuenta otra vez, paso 1. |
| «El motor limita la cantidad de escaneos» | Es el límite de 10 por hora. Esperar o `docker compose restart engine`. |
| Quedaron credenciales viejas después de reconstruir | `docker compose down -v` y volver a encender. |
| La primera construcción es lenta | Es normal (descarga imágenes y paquetes). Las siguientes usan la caché. |
| La computadora usa un proxy | La demo lo ignora a propósito (la red de la demo no sale a ningún lado). Solo la construcción necesita internet. |

## Cómo está armado

```
demo/
├── docker-compose.yml      # init, postgres, engine, shop, staging, ct y console
├── Dockerfile              # una sola imagen: init, sitios de práctica y consola
├── common.py               # nombres y archivos que comparten
├── init.py                 # genera credenciales y certificados la primera vez
├── practice.py             # los sitios de práctica: tienda, servidor de pruebas y registro de certificados
├── requirements.txt        # cryptography (solo para init.py)
├── console/
│   ├── server.py           # la consola (solo biblioteca estándar de Python)
│   ├── explain.py          # pasa los hallazgos del motor a lenguaje de cliente
│   └── static/             # la página con los botones (HTML, CSS, JS)
└── tests/
    ├── smoke.py            # prueba de humo contra la demo encendida (ver arriba)
    ├── fake_engine.py      # motor de mentira, solo para las pruebas automáticas
    └── test_*.py           # pruebas automáticas
```

## Cómo se probó

**Pruebas automáticas** (más de cien; no necesitan Docker ni el motor, usan un motor de mentira que contesta lo mismo que la API real):

```bash
pip install pytest cryptography pyyaml
python -m pytest demo/tests -q
```

Cubren la generación de credenciales y certificados, los sitios de práctica (certificados, saludos de los servicios, apagado), la consola (recorrido completo, rechazos, seguridad del servidor, textos para el cliente), las propiedades de seguridad del `docker-compose.yml` y la propia prueba de humo.

**De punta a punta con el motor verdadero.** El recorrido completo (también la prueba de humo, 11 de 11 en unos 10 segundos) se corrió contra el motor de `apps/engine` con PostgreSQL 16 reales, y la consola se recorrió con un navegador real (Chromium), sin errores en la consola del navegador y sin desbordes de pantalla en un ancho de celular. Como el entorno de desarrollo no puede descargar imágenes de Docker, esa corrida usó un laboratorio equivalente al compose: una red aislada sin salida, direcciones privadas del mismo tipo que las de Docker (172.x), el mismo comando y las mismas variables del motor (salvo que escuchaba solo en `127.0.0.1`, porque todos los procesos compartían una máquina), el `init.py` verdadero y usuarios sin privilegios para la consola y los sitios.

**Lo que todavía no se verificó:** `docker compose up --build` en Docker Desktop (Windows). Es lo que cubre la prueba de aceptación de arriba.
