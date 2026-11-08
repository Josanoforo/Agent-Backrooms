# Paquete público revisable · ola5

**Candidato para revisión humana. No es una publicación.** No hay `git push`, GitHub, red, despliegue ni claves implicadas. Que el paquete se construya no significa que esté aprobado: licencia, procedencia y revisión final siguen pendientes.

Estado: central ejecutó el CLI, verificó ZIP, hashes y enlaces, y probó el paquete por separado. La publicación y la licencia permanecen pendientes.

## Comandos

Desde la raíz del repositorio, solo biblioteca estándar de Python:

```
python scripts/build_public_release.py plan                 # simulacro: selección, exclusiones, escaneo, enlaces
python scripts/build_public_release.py build                # crea release/ola5-public/ y release/ola5-public.zip
python scripts/build_public_release.py verify               # revisa release/ola5-public (y su .zip si existe)
```

Opciones relevantes:

- `--version ETIQUETA` o `--new-dest` (sello UTC): construir en otro destino, `release/ola5-public-<etiqueta>`.
- `--force`: reemplazar un destino existente **solo si** verifica como build íntegro anterior de esta herramienta (manifiesto propio, hashes y sin archivos extra; el ZIP debe pertenecerle). El anterior se **mueve** a `<nombre>.replaced-<UTC>`, nunca se borra, y solo tras superar la nueva construcción todas las comprobaciones.
- `--scan-allow ARCHIVO.json`: lista revisada de `{path, rule, reason}` para dobles de prueba o fixtures que no admiten comentarios. Su SHA-256 queda en el manifiesto.
- `--strict-links`: los enlaces relativos rotos pasan a bloquear (por defecto solo se documentan).
- `--evidence none`: omitir los cuatro reportes de evidencia pública.
- `plan --list-files`: lista cada ruta seleccionada con su regla.
- `--override PKG=SRC` (repetible; `plan` y `build`): embarca el archivo del repositorio `SRC` en la ruta del paquete `PKG`. `PKG` debe estar ya seleccionada por una regla y conservar el sufijo; `SRC` debe ser un archivo plano del repositorio, no denegado, sin enlaces simbólicos en su cadena y de 2 MiB como máximo. El manifiesto registra `"source": "override:<SRC>"`. Se usa para embarcar variantes del `README.md` y de `scripts/evaluation/README.md` cuyos enlaces resuelven dentro del paquete, sin tocar los originales del árbol de trabajo.

Sin ninguna opción de destino, si `release/ola5-public` o su `.zip` (o `.zip.sha256`) ya existen, el build **se niega** (salida 2) y no toca nada. Salida 3: bloqueado por regla, escaneo o verificación; no se deja nada en el destino. Se construye en `release/.stage-*` y se renombra al final.

## Qué entra (lista explícita)

| Regla | Contenido |
|---|---|
| `services_agent` | `services/agent/**/*.py` |
| `web_assets` | `apps/web/**` con extensiones de activos web (html, css, js, svg, imágenes, json, etc.) |
| `python_requirements` | `requirements.txt`, `infra/requirements.lock.txt` |
| `infra_public` | bajo `infra/`: `*.template`, `*.tmpl`, `*.example`, `*.md`, `Caddyfile*`, `Dockerfile*`, `*.service`; **excluye el prefijo `infra/p2/`** (bitácora de una activación concreta en la VM del operador) |
| `evaluation_scripts` | `scripts/evaluation/**/*.py` y su `README.md` |
| `state_backup_cli` | `scripts/backup_state.py` |
| `external_connectors` | 11 scripts exactos del conector de agentes externos (obligatorios): `scripts/external_agent_mcp.py`, `external_runtime.py`, `external_client_lifecycle.py`, `connect_external_agent.ps1`, `connect_external_claude.py`, `connect_external_codex.ps1`, `connect_external_ollama.py`, `connect_external_vm_ollama.py`, `run_external_campaign.py`, `build_external_ledger.py`, `publish_external_trace.py` |
| `release_support` | `docs/release/PUBLIC-DEPENDENCIES.json`, `docs/evaluacion/ola4/comparison.md`, `comparison.json`, `scripts/build_public_release.py`. **Excluido desde el 2026-11-08:** `docs/release/LICENSE-PROPOSAL.txt` (propuesta MIT anterior a `LICENSE`; superada según `PUBLIC-PROVENANCE.md`); figura en el plan como `excluded_by_rule` con motivo `superseded` (constante `SUPERSEDED_EXCLUDE_FILES`) |
| `tests` | `tests/backend`, `tests/integration`, `tests/evaluation`, `tests/web` (sin cachés ni SQLite) |
| `public_release_docs`, `public_package_doc` | `docs/release/PUBLIC-*.md` |
| `readme`, `env_example` | `README.md`, `.env.example` |
| `license`, `third_party_notices` | solo si existen (`LICENSE[.md/.txt]`, `THIRD_PARTY_NOTICES[.md/.txt]`) |
| `pytest_support` | solo si existen: `services/__init__.py`, `tests/__init__.py`, `tests/conftest.py`, `pytest.ini`, `conftest.py` (añadido para que pytest pueda ejecutarse en el paquete; quitar de la lista si Central no lo quiere) |
| `public_evidence_reports` | `docs/evidencia/ola4/public/run-1.json`, `run-2.json`, `docs/evidencia/ola3/report.json`, `docs/evidencia/ola1-live-cierre/report.json`, copiados **byte a byte** |

Los reportes no se reescriben, re-firman ni re-hashean. Si Central necesitara una versión saneada distinta, debe ser un archivo derivado etiquetado con hash y procedencia del original; esta herramienta no lo genera. Que estén ya en estado público lo afirma el encargo; el script solo comprueba que su contenido supere el escaneo y que la copia sea idéntica.

Se genera además un `.gitignore` propio y seguro (no copia el de trabajo), `PUBLIC-MANIFEST.json` y `SHA256SUMS`. El ZIP es determinista en orden y marcas de tiempo, con una sola carpeta raíz igual al nombre del destino; junto a él se escribe `<nombre>.zip.sha256`.

## Qué nunca entra

`.git` (historial), `.private/`, `.env` y `.env.*` salvo `.env.example`, `development/`, `claude/`, `attachments/`, dossiers internos, `dashboard/`, `tablero/`, capturas y registros de facturación, registros operativos, bases SQLite/`.db`, cachés y bytecode, logs, material de claves (`*.pem`, `*.key`, `id_rsa*`…), archivos de credenciales, y bajo `infra/` y `scripts/` cualquier nombre con admin, upload, credential, password, private, billing, ssh o api-key. No se copia `docs/` completo. Los enlaces simbólicos y *junctions* se detectan (también en directorios padre) y bloquean; no se siguen.

## Escaneo de secretos

Reglas por patrón (clave privada, claves tipo Anthropic/OpenAI/GitHub/AWS/Slack/Google, JWT, hashes de contraseña, `Bearer`, credenciales en URL, asignaciones genéricas `*_KEY/SECRET/TOKEN/PASSWORD` con valor largo) más un aviso no bloqueante de rutas locales absolutas. Se informa **por ruta, regla y línea**, nunca con el valor.

Permitido sin ruido: placeholders evidentes (vacío, `changeme`, `<...>`, `your-...`, `xxxx`) y valores de claves cuyo nombre indica hash/digest. Un doble de prueba o fixture se admite solo con marcador explícito `public-scan: allow <regla> -- <motivo>` (misma línea o anterior, o `allow-file` en las primeras 30 líneas) o mediante `--scan-allow`. La lista vigente es `docs/entrega/PUBLIC-SCAN-ALLOW-20261108.json` (superconjunto de la anterior `docs/release/PUBLIC-SCAN-ALLOW-C5.json`; añade el token fijo de prueba `local-actor-service-test` que las pruebas de contenedor envían como cabecera de autorización, y los comandos de inspección de `mountinfo` de las pruebas de contenedor). Cada permiso aparece listado con su ruta y regla; no hay exención por palabras como "canary" o "test". Si un secreto sintético de prueba salta el escaneo, hay que marcarlo en su archivo (propiedad de otro carril) o listarlo en el JSON de permisos tras revisarlo.

Límite: es un filtro de patrones local, no una auditoría. Valores secretos sin forma reconocible no se detectan; la revisión humana sigue siendo necesaria.

## Enlaces relativos

Se revisan los enlaces de todos los `.md` incluidos (README incluido). Los faltantes se documentan en la salida y en el manifiesto con su motivo: `exists_in_repo_not_in_package` (existe pero está fuera de la lista), `absent_in_repo`, `outside_package`. Los enlaces faltantes bloquean el build con `--strict-links`. Central corrigió la selección y los documentos: no se copian documentos privados para resolver enlaces.

## Manifiesto

`PUBLIC-MANIFEST.json`: para cada archivo ruta, tamaño, SHA-256, regla de origen, si se generó, y que la copia es idéntica al origen; resumen de exclusiones y ausencias, hallazgos del escaneo sin valores, resultado de enlaces, estado de licencia (`pending` mientras no exista `LICENSE`), `content_digest_sha256` y el estado `review_candidate_not_published`. No se auto-hashea; `SHA256SUMS` cubre todo lo demás incluyendo el manifiesto. Un hash acredita integridad, no autenticidad ni aprobación.

## Límites

- **Licencia.** Desde el 2026-11-08 existen `LICENSE` (MIT) y `THIRD_PARTY_NOTICES.md` y viajan en el paquete; el manifiesto los marca `present_unreviewed` porque el script no evalúa su texto. Si faltaran, el paquete saldría sin licencia y el manifiesto lo marcaría. Los términos del evento piden compatibilidad con MIT salvo excepción; elegir licencia y revisar procedencia/avisos (`THIRD_PARTY_NOTICES`) es decisión humana previa a publicar.
- El README lo edita otro agente. Para el paquete del hackathon se embarca con `--override` la variante `docs/entrega/README-PAQUETE-PUBLICO.md`, generada a partir del README del árbol de trabajo: los enlaces a documentos que no viajan pasan a texto con el símbolo † y su ruta original. Lo mismo para `scripts/evaluation/README.md` (`docs/entrega/README-EVALUACION-PAQUETE.md`).
- Central ejecutó build y verify con enlaces estrictos, escaneo y hashes de ZIP. Desde el paquete: 366 Python aprobadas, 14 Docker omitidas en Windows y 41 web aprobadas.
- La lista de activos `apps/web`, los patrones de `infra/` y las extensiones de tests se redactaron sin inventariar el árbol; si `plan` muestra archivos necesarios fuera de la lista (`skipped_by_suffix`, `excluded_by_rule`) o ausencias, se corrige la lista de forma explícita, no se relaja el filtro.
- Los reportes de evidencia pueden contener identificadores de corrida y valores sintéticos de canary; no son secretos reales, pero siguen sujetos al escaneo.
- El paquete no certifica seguridad ni envía nada al hackathon.

La revisión central añadió comparación pública, propuesta de licencia, inventario de dependencias, script constructor y pruebas web a la lista explícita. Se corrigieron los enlaces: cero enlaces relativos faltantes en la verificación. Las alertas de rutas locales corresponden a dos fixtures ficticios de pruebas.

## Construcción `agent-backrooms-hackathon-20261108`

Decisión del titular aplicada: «Solo lo que pide el hackathon, no más no menos, no env, no secrets, no nuestros protocolos internos». Comando:

```
python -I scripts/build_public_release.py build --name agent-backrooms --version hackathon-20261108 --force --strict-links --scan-allow docs/entrega/PUBLIC-SCAN-ALLOW-20261108.json --override README.md=docs/entrega/README-PAQUETE-PUBLICO.md --override scripts/evaluation/README.md=docs/entrega/README-EVALUACION-PAQUETE.md
```

Destino `release/agent-backrooms-hackathon-20261108/` y su `.zip` (la construcción anterior `release/ola5-public-hackathon-20261108` queda superada). El producto se llama **Agent Backrooms** desde el 2026-11-08 (decisión del titular); el repositorio destino es `Josanoforo/agent-backrooms`, rama `main`. Los identificadores internos (unidades systemd `agent-escape-room*`, archivos `escape-room.env*`, variables `ESCAPE_*`, hostname) conservan el nombre de trabajo `escape-room`. Fuera, además de lo que nunca entra: `submission/` (vídeo, diapositivas, portada y textos van al formulario de lablab.ai), `docs/evidencia/` salvo los cuatro reportes públicos, `docs/mesas/`, `AGENTS.md`, `.claude/`, `infra/p2/`. Cifras, hashes y pasos de publicación para el titular: `docs/entrega/PAQUETE-PUBLICO-2026-11-08.md` (árbol de trabajo, no viaja en el paquete).
