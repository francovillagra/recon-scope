FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# La misma imagen sirve para tres cosas, según el comando que reciba (ver docker-compose.yml):
#   init.py              prepara credenciales y certificados (arranca como root, una sola vez por encendido)
#   practice.py          los sitios de práctica
#   console/server.py    la consola guiada
# Solo init.py necesita una biblioteca de afuera (cryptography, para firmar los certificados de práctica).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common.py init.py practice.py ./
COPY console ./console

# Todo corre sin privilegios. El servicio `init` usa esta imagen pero arranca como root, porque tiene que escribir en los volúmenes.
RUN useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin demo
USER demo

EXPOSE 8080

CMD ["python", "console/server.py"]
