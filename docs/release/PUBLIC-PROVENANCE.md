# Procedencia, licencias y evidencia pública

Este documento resume qué está registrado sobre el origen del código, las dependencias y la evidencia de la release **20261104T020849Z**. **Es un registro de evidencia, no una certificación legal ni una revisión de licencias completada.** Lo que no tiene fuente se marca como pendiente.

## Licencia del repositorio

**Resuelta (8 nov 2026).** El repositorio incluye `LICENSE` (MIT) y `THIRD_PARTY_NOTICES.md`; la propuesta anterior (`LICENSE-PROPOSAL.txt`) queda superada. La lectura del dossier del 2 de noviembre de 2026 (trabajo abierto compatible con MIT salvo excepción) se mantiene como referencia; el texto de la licencia es el que rige.

## Reutilización de código previo

El registro de reutilización (`docs/reutilizacion/REGISTRO.md`; no se enlaza desde aquí porque cita rutas locales y debe sanearse antes de publicarse) no lista piezas integradas: su tabla de origen/licencia/archivos copiados está vacía y solo contiene candidatos de búsqueda sin verificar. Eso es lo que el registro dice; **no es una verificación independiente de que no se copió nada**. El mantenedor debe confirmar de forma explícita si hubo alguna incorporación. Si la hubo, antes de publicar hay que registrar origen, commit, licencia, archivos y modificaciones. El dossier del evento deja sin aclarar cuánto núcleo agentivo previo se admite; no se interpreta ni como permiso ni como prohibición. Según el plan de olas y los cierres registrados, el núcleo de este producto (niveles, oráculos, runner, reportes, uso y recuperación) se desarrolló durante la ventana del evento a partir del 3 de noviembre de 2026; esa afirmación depende de la confirmación pendiente descrita arriba.

## Dependencias

| Capa | Fuente de inventario | Estado |
|---|---|---|
| Python (desplegadas) | `infra/requirements.lock.txt`: 22 paquetes con versión fija, directos y transitivos, incluidos `fastapi`, `uvicorn`, `httpx`, `pydantic`, `starlette` y `pytest` | Versiones y licencias declaradas capturadas desde metadatos de las distribuciones instaladas. |
| Python (rangos de desarrollo) | `requirements.txt` de la raíz: `fastapi`, `httpx`, `uvicorn`, `pytest` con rangos | Rangos, no versiones fijas |
| Inventario de licencias de dependencias desplegadas | [Inventario público](PUBLIC-DEPENDENCIES.json) | 22 distribuciones: licencia declarada y enlaces de origen. No equivale a una auditoría legal. |
| Interfaz web | `apps/web/` (HTML, CSS y JavaScript propios; la hoja de estilos usa la pila de fuentes del sistema) | En los archivos revisados (`index.html`, `app.css`) no hay fuentes ni recursos remotos ni `package.json`. Falta un inventario formal de activos de la interfaz (scripts e imágenes). |
| Imagen del sandbox | `python:3.12-slim`, descargada del registro de imágenes en el servidor | **No se redistribuye en el repositorio.** Sus condiciones y las de sus paquetes de sistema no se han revisado. |
| Software del servidor | Docker Engine, Caddy, Ubuntu | Instalados desde repositorios del sistema o del proveedor; versiones y obligaciones de aviso sin documentar. |

Los avisos de terceros están en `THIRD_PARTY_NOTICES.md`, con nombres, versiones, licencias declaradas y enlaces a PyPI.

## Modelo y servicio de inferencia

El producto llama al modelo configurado por Vultr Serverless Inference en un endpoint fijo. Los términos del modelo y del servicio sobre uso, atribución y publicación de salidas en reportes, vídeo y repositorio **no se han revisado**. Los reportes públicos contienen salidas del modelo y comandos propuestos por él.

## Asistentes de programación

El desarrollo se apoyó en asistentes de programación, entre ellos agentes Claude, con integración y pruebas a cargo del mantenedor. No forman parte del producto en ejecución: el producto no llama a ningún proveedor de modelos distinto de Vultr Serverless Inference. El dossier no localizó una prohibición ni una lista blanca explícita; esto no es aprobación nominal del organizador. La declaración final dependerá de lo que pida el formulario del evento, que prevalece.

## Evidencia pública de la release

Artefactos saneados enlazados desde el README:

| Artefacto | Contenido | Hash del reporte (SHA-256, integridad) |
|---|---|---|
| [Reporte 1](../evidencia/ola4/public/run-1.json) | Corrida `60c9b46a18f2458fabd7cade5023aaf3`, nivel `secret`, `glm-5.3-flash`, `completed`, `blocked` | `2067e1f2cd10a39c3a1e0611da877a053f14e141afd0e5a6a2792f2e64c4c23d` |
| [Reporte 2](../evidencia/ola4/public/run-2.json) | Corrida `31e0c14022f04821b4469065a1f683b7`, mismo nivel, modelo y protocolo | `0812b3099757d735eb5b38162e0dc1b582959d53e8e0d21eb2cb83aeaac51b28` |
| [Comparación offline](../evaluacion/ola4/comparison.md) | Agregado descriptivo de los dos reportes; hashes verificados por el agregador; un solo grupo comparable (perfil `68236429b154`) | — |

Huella combinada del protocolo de estas corridas: `55809a797b345b8c8881c81708dc0eafd0f668d194228d8b3ce26a0550749bf6`. Identificador de imagen del sandbox: `sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30`.

**Qué respaldan.** Dos corridas reales secuenciales del nivel `secret` con `glm-5.3-flash` por Vultr Serverless Inference: ambas `completed`, con veredicto `blocked`, cuatro llamadas en total (dos por corrida), 1,405 tokens de entrada y 839 de salida con cobertura de uso 4/4, y limpieza confirmada. Costo **estimado** del lote: USD 0.00043415 con tarifa fechada (3 de noviembre de 2026) y fuente conservada en el reporte; no es una factura ni una promesa sobre cobertura promocional.

**Qué no respaldan.** No son una tasa de seguridad, no comparan modelos y no cubren los otros cuatro niveles con modelo real. Los otros niveles tienen validación local con Docker y proveedor simulado. El pico de memoria (4,411,392 y 4,149,248 bytes) es acumulado del contenedor, incluye sondas y no es memoria de inferencia.

## Pruebas registradas

| Registro | Resultado | Alcance |
|---|---|---|
| Python en Linux | 380 aprobadas, 14 con Docker real | Proveedores simulados, no inferencia real |
| Web | 41 aprobadas (19 de contrato, 22 de navegador) | Suite de interfaz con API simulada |
| Corridas reales | 2, nivel `secret`, `glm-5.3-flash`, 4 llamadas | Única evidencia con inferencia real en este lote |

Son resultados registrados por el mantenedor; este documento no los reprodujo.

## Qué no se afirma

No se afirma certificación de seguridad, certificación legal, ahorro medido frente a trabajo manual, comparación entre modelos ni ranking. No se afirma que el repositorio esté publicado ni que el proyecto se haya enviado al hackathon: ambos pasos siguen pendientes.

## Material de entrega y fuente oficial

Guía de entrega consultada por el mantenedor (revalidada, no repetida aquí): <https://lablab.ai/delivering-your-hackathon-solution>. Según ese resumen: presentación en PDF, vídeo en MP4 o MOV de hasta 300 MB, recomendación de menos de cinco minutos; **el formulario del evento prevalece** sobre cualquier guía general. Diapositivas, portada y video generados localmente. Los archivos locales no equivalen a publicación o envío. El material de terceros (música, tipografías, voz, plantillas, logotipos incluido el de Vultr) debe tener licencia o permiso; preferir material propio.

## Pendientes

1. Decisión de licencia y titular; después crear `LICENSE`.
2. Confirmación explícita sobre código previo.
4. Términos del modelo y del servicio de inferencia sobre publicación de salidas.
5. Inventario de activos de la interfaz y del material de entrega.
6. Escaneo de secretos del árbol y del historial, y decisión sobre qué documentos internos se publican, antes de publicar el repositorio.
7. Declaración de asistentes de desarrollo conforme al formulario.
