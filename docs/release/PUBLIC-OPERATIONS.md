# Operación pública · instalación, configuración y recuperación

Estado de este documento: derivado del código, de `infra/` y de los artefactos del repositorio. Los pasos de instalación **no se han verificado desde cero por una persona distinta** ni se ejecutaron al redactar esto. Marcarlos como verificados exige que alguien los repita sin las credenciales del autor.

## Requisitos

- Linux con Docker Engine (el sandbox son contenedores locales). La release desplegada usó Ubuntu 24.04 y Python 3.12.3.
- Python 3.12 con `venv`.
- Para corridas reales: una clave de Vultr Serverless Inference y un modelo disponible en esa cuenta. El nombre del modelo es configuración; que `glm-5.3-flash` esté disponible para otra cuenta no está garantizado.
- Opcional en servidor: Caddy para HTTPS y systemd.
- Cgroup v2 es necesario para medir memoria; sin él la medición figura como no disponible.
- Docker requiere que el usuario del controlador pertenezca al grupo `docker`, lo cual equivale a privilegios de administrador sobre esa máquina. Usar una máquina dedicada.

## Instalación local (Linux)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r infra/requirements.lock.txt
docker pull python:3.12-slim
```

`infra/requirements.lock.txt` captura las versiones Python desplegadas. Es un inventario de versiones, **no una revisión de licencias**.

La imagen del sandbox servida en la VM es `python:3.12-slim`, fijada por `ESCAPE_DOCKER_IMAGE`; sin esa variable el código (`services/agent/runner.py`, línea 17) usa por defecto `python:3.12-alpine`, que no es la imagen desplegada ni la probada en la release.

## Configuración sin secretos

Copiar la plantilla `infra/agent-escape-room.env.example` a un archivo propio fuera del repositorio (`.env*` está excluido por `.gitignore`, salvo el ejemplo) y rellenar los valores localmente. Nunca confirmar claves en Git ni pegarlas en issues, capturas o vídeo.

| Variable | Uso |
|---|---|
| `VULTR_INFERENCE_KEY` | Clave de inferencia. Secreto. Solo la usa el controlador; no llega al navegador ni a los contenedores. |
| `ESCAPE_MODEL` | Identificador del modelo configurado. La API rechaza otro modelo. |
| `ESCAPE_OPERATOR_TOKEN` | Token largo y aleatorio. Autoriza iniciar corridas con `Authorization: Bearer`. Secreto. No es la clave de Vultr. |
| `ESCAPE_DB` | Ruta de la base SQLite (debe ser escribible). Sin esta variable se usa un archivo relativo. |
| `ESCAPE_DOCKER_IMAGE` | Imagen del sandbox. Se registra su identificador, no solo la etiqueta. |
| `ESCAPE_MAX_RUNS`, `ESCAPE_MAX_CALLS`, `ESCAPE_MAX_OUTPUT_TOKENS` | Topes de los contadores acumulados. Valores de la plantilla: 10, 40, 40960. |
| `ESCAPE_RATE_LIMIT_PER_MINUTE` | Límite por IP para iniciar corridas (plantilla: 5). |
| `ESCAPE_TRUSTED_PROXIES` | Redes de proxy de confianza para la IP del cliente. Solo debe contener el proxy local. |
| `ESCAPE_CLEANUP_ON_STARTUP` | Con `1`, al arrancar y apagar se eliminan los recursos Docker que lleven la etiqueta de propiedad del controlador; si no se puede confirmar el inventario, el arranque falla. |
| `ESCAPE_USAGE_RATE_JSON` | Opcional. Tarifa explícita (modelo, precio de entrada y salida por millón, fecha efectiva y fuente) para estimar USD. Sin ella no hay estimación de costo. No hay precios en el código. |

Con la clave o el modelo ausentes, `/api/config` indica que no está configurado y no se crean corridas inventadas. La interfaz sigue permitiendo leer el reporte histórico guardado.

## Arranque local

Cargar las variables y arrancar un único worker (la concurrencia y el límite de tasa viven en memoria de un solo proceso):

```bash
set -a; . /ruta/a/su/archivo.env; set +a
uvicorn services.agent.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers
```

Abrir `http://127.0.0.1:8000`. Para iniciar una corrida desde la interfaz o con `POST /api/runs` hace falta el token de operador. Ejemplo de cuerpo: `{"model": "<ESCAPE_MODEL>", "levels": ["secret"]}`. Respuesta `202` con `{id, status}`. Consultar `GET /api/runs/{id}`, `GET /api/runs/{id}/events` (SSE) y `GET /api/runs/{id}/report?format=json|md`.

Cada corrida real consume cuota y llamadas al proveedor. Un intento fallido también consume reserva.

## Servidor (resumen de `infra/`)

Detalle en `infra/README.md`. Resumen: cuenta de sistema dedicada con acceso a Docker, release en un directorio versionado con enlace `current`, entorno en `/etc/agent-escape-room.env` con permisos 0600 solo en la máquina, `infra/agent-escape-room.service` para systemd y `infra/Caddyfile` para HTTPS. El backend escucha solo en loopback; el firewall expone SSH, 80 y 443. Caddy debe servir HTTPS antes de introducir el token de operador. Un dominio temporal tipo `sslip.io` no es un dominio definitivo.

Comprobaciones recomendadas tras desplegar: `/healthz`, certificado TLS, `/api/config`, rechazo de un `POST /api/runs` sin autorización, rechazo de cuerpos mayores de 16 KiB, rutas privadas no servidas, limpieza de recursos Docker y registros sin secretos.

## Pruebas

Comando documentado en el repositorio:

```bash
python -m pytest tests/backend tests/integration tests/evaluation -q
```

Las pruebas con Docker real requieren activación explícita (`ESCAPE_RUN_DOCKER_SMOKE=1`) y la imagen indicada en `ESCAPE_DOCKER_IMAGE`; sin ella se omiten. Sus proveedores son simulados, no inferencia real. La suite web se ejecuta con Node y Python/Playwright mediante los comandos del README.

Resultados registrados para esta release: 380 pruebas Python aprobadas en Linux, 14 de ellas con Docker real; 41 pruebas web aprobadas (19 de contrato y 22 de navegador). Son registros de la ejecución del mantenedor; este documento no las repite.

## Presupuesto operativo y límites de uso

Los límites son contadores acumulados en SQLite, no un tope monetario. No cubren costo de la máquina, red ni una factura de inferencia. No reiniciar ni ampliar topes de forma automática. Antes de ampliar, comprobar saldo, cuotas y tarifa en la cuenta del proveedor.

## Copia y restauración del estado

El estado se copia y restaura con `scripts/backup_state.py` (solo archivos locales; nunca sobrescribe; imprime JSON):

```bash
python scripts/backup_state.py backup    --db ACTIVA.sqlite --out COPIA.sqlite
python scripts/backup_state.py verify    --backup COPIA.sqlite
python scripts/backup_state.py restore   --backup COPIA.sqlite --to NUEVA.sqlite
python scripts/backup_state.py status    --db NUEVA.sqlite
python scripts/backup_state.py counters  --db ACTIVA.sqlite
python scripts/backup_state.py reconcile --db NUEVA.sqlite --block-id ID --evidence "texto" --current-db OTRA.sqlite
```

- `backup` usa la API de respaldo de SQLite y escribe un manifiesto con hash, integridad y contadores.
- `restore` crea una base nueva y la deja **bloqueada para nuevas corridas**.
- `reconcile` solo acepta contadores actuales no inferiores a los de la copia (desde `--current-db` o explícitos con `--runs`, `--calls` y `--output-tokens`). No existe un comando que quite el bloqueo sin conciliar.
- Copiar manualmente un archivo sobre la base activa elude este procedimiento y puede devolver presupuesto ya gastado. No hacerlo.
- Esto recupera **estado**, no una VM, imágenes ni contenedores. Las copias son privadas y no se publican; lo que se comparte son reportes saneados.

Ensayo registrado: tras restaurar, la admisión quedó bloqueada hasta conciliar y las cuotas se preservaron. En el ensayo local observado, el punto de recuperación fue de 0.045 s y el tiempo de restauración de 31 ms sobre una copia pequeña; son observaciones de ese ensayo, no garantías.

## Reversión

Detener el servicio, apuntar `current` a la release anterior revisada y arrancar de nuevo, conservando la base y el entorno. La reversión no deshace el gasto del proveedor. Recursos Docker anteriores a la etiqueta de propiedad requieren inspección manual.

Reversión SC2: detener sólo `agent-escape-room-sc2-controller`, apuntar `/opt/agent-escape-room/sc2-current` a la release anterior registrada en la custodia `<release_id>/before.json`, arrancar el controlador y comprobar `GET /healthz` y `/api/config`. Caddy, actor y guard no se reinician; la base SQLite no se restaura.

## Qué no hace esta operación

Sin cancelación por el usuario en el contrato v1. Sin concurrencia ampliada. Sin segundo modelo. Sin garantías de disponibilidad. Sin reconstrucción de infraestructura automatizada.

Las instrucciones actuales de pruebas web están en el README raíz: Node ejecuta `tests/web/contract.test.cjs` y Python con Playwright ejecuta `tests/web/dom.test.py`. El wrapper PowerShell interno no se distribuye ni se necesita. Para ejecutar las pruebas Docker, active `ESCAPE_RUN_DOCKER_SMOKE=1` en un entorno Linux con Docker disponible. Use la plantilla de entorno: fija explícitamente `ESCAPE_DOCKER_IMAGE=python:3.12-slim`; el valor por defecto en código sin esa variable es alpine.
