# Agregador offline de reportes (scripts/evaluation)

> Copia para el paquete público: los enlaces a documentos de evidencia interna aparecen como texto con el símbolo † y su ruta en el árbol de trabajo del titular, porque esos documentos no viajan en el paquete. El módulo de custodia local `scripts.d2a_local_custody` (DPAPI del operador en Windows) tampoco se incluye; los verificadores offline de `scripts/evaluation/` sí.

`aggregate_reports.py` compara reportes JSON **ya existentes** (formato de `GET /api/runs/{id}/report?format=json`) por modelo, nivel y perfil. Solo biblioteca estándar; no usa red, no llama a ningún proveedor, no ejecuta herramientas y abre las entradas en solo lectura.

## Uso

```
python scripts/evaluation/aggregate_reports.py --real R1.json R2.json --fixture F1.json \
    --out-json salida/agregado.json --out-md salida/agregado.md
python scripts/evaluation/aggregate_reports.py --real R1.json --format md      # a stdout
```

- Cada archivo se declara `--real` o `--fixture`. Un fixture debe contener `"synthetic_fixture": true`; un `--real` con ese marcador se rechaza. Los dos tipos salen en grupos separados y nunca se suman.
- Perfil = bloque `experiment` (sin el texto `limitations`) + `sandbox` completo. Cada combinación tipo/perfil es un grupo; perfil ausente o incompleto → grupo `unknown`. Nunca se mezclan perfiles.
- Por modelo y nivel: conteos `blocked/escaped/exhausted/error/not_run` por separado (veredicto de `run.summary[nivel].outcome`), más `invalid` (valor no válido) y `missing` (nivel solicitado sin resumen). Los resultados por recibo se cuentan aparte (`receipt_outcomes_step_level`).
- En D2B, `receipt.room.provisional=true` identifica un recibo emitido mientras la sesión sigue abierta. Su `outcome` sigue contando como resultado del paso. La limpieza final se lee de `run.summary[nivel].witness.cleanup` y el veredicto final de `run.summary[nivel].outcome`.
- Tiempo: suma de `duration_ms` de los recibos del nivel (tiempo de herramientas, no de pared). Es `null` si falta algún recibo o duración; nunca 0.
- Memoria: `memory_peak_bytes` y `memory_observed_max_bytes` del resumen; `null` con motivo (`value_null`, `measurement_unavailable`, `no_summary`...). Mediciones de distinta fuente/alcance/tipo se agregan por separado.
- Fuentes: cada observación lleva archivo, id de corrida y punteros JSON; cada entrada aceptada lleva SHA-256 del archivo.
- Hash: se informa `verified`/`not_reproduced`/`absent`/`invalid_format`. `verified` exige únicamente la serialización canónica del **reporte completo** que usa `services/agent/main.py`: todos los campos salvo `sha256` (`run`, `experiment`, etc.), `json.dumps(sort_keys=True, ensure_ascii=False, separators=(",", ":"))` en UTF-8 (método `report_without_sha256/sorted/utf8/compact`). No se acepta el hash de un subconjunto (p. ej. solo `run`) ni otras serializaciones (con espacios, `indent`, ASCII escapado, sin ordenar): permitirían alterar `experiment` sin detección. Acredita integridad, no autenticidad; `not_reproduced` no prueba manipulación, solo que esa serialización no lo reprodujo. `--strict-hash` rechaza `--real` no verificados (motivo `hash_not_verified`). Un reporte antiguo cuyo hash use otra serialización sale `not_reproduced` y solo entra sin `--strict-hash`.
- Códigos de salida: 0 correcto; 1 hubo entradas rechazadas (salvo `--allow-rejected`) o ninguna aceptada; 2 uso/salida inválidos. Las rechazadas siempre se listan con motivo.
- Seguridad: rechaza URLs, rutas `.env*`/`.private`, archivos > 20 MiB; no sobrescribe entradas, no escribe en directorios llamados `evidencia`, no reemplaza salidas existentes sin `--force`. La salida es determinista (sin marcas de tiempo) y el Markdown escapa el contenido.

## Límites

Descriptivo; no es ranking de seguridad ni certificación. Las muestras son pequeñas. No valida los veredictos: agrega lo que dice cada reporte (señala anomalías como `blocked` sin evidencia).

Pruebas: `python -m pytest tests/evaluation` (fixtures sintéticos rotulados generados en `tests/evaluation/conftest.py`).

## D2A · Verificación de dos controles de red

Desde la raíz del paquete, usa Python 3.12 y un manifiesto esperado obtenido de una fuente confiable. El manifiesto de esta entrega tiene SHA-256 `0d061e1edaedf3be479d7f3d2ff9e107573c52def74bc4c374b2481995dee26f`.

```text
python scripts/evaluation/d2a_evidence.py verify --expected apps/web/evidence/d2a/expected.json --bundle apps/web/evidence/d2a/records
```

La salida indica `effect_detected` para el control de la sonda y `block_verified` para la denegación con perfil endurecido. Ambos casos se ejecutaron por operador privado. El verificador funciona offline y comprueba integridad respecto del manifiesto. Los registros saneados conservan un subconjunto de cada reporte original y la autenticidad del manifiesto depende de su procedencia.

### D2A · Verificación con firma separada

Operador Windows: la custodia local DPAPI y firma en memoria (`../../docs/evidencia/K-MINIMO-CUSTODIA-LOCAL.md`†) ya está implementada y comprobada con identidad dedicada. Usa `python -B -m scripts.d2a_local_custody status` o `sign`; los comandos OpenSSH de abajo describen un archivo privado OpenSSH convencional, no el blob DPAPI. La pública exportada sigue requiriendo entrega confiable separada antes de atribuir autenticidad externa. No autentica el tar P1 ni reportes P2.

El modo firmado usa Python y una instalación local confiable de OpenSSH con soporte `ssh-keygen -Y`. El firmante autorizado puede producir `MANIFEST.sig` con una clave Ed25519 bajo su custodia.

```text
ssh-keygen -Y sign -f SIGNING_KEY -n agent-escape-room-d2a/v1 MANIFEST
```

El revisor obtiene la clave pública OpenSSH `TRUSTED_KEY.pub` por un canal independiente de la evidencia y la mantiene fuera de `RECORDS`. Desde una copia confiable del código, verifica offline.

```text
python -B -S -m scripts.evaluation.d2a_signed_evidence --expected MANIFEST --signature MANIFEST.sig --trusted-key TRUSTED_KEY.pub --bundle RECORDS
```

El resultado global es correcto si `authenticity` e `integrity` quedan en `verified`. Las modificaciones al manifiesto, incluida su representación JSON, invalidan la firma. El código de salida es 0 cuando ambas comprobaciones pasan, 1 ante rechazo de evidencia y 2 ante un fallo de entrada o de herramienta. El verificador original de D2A sigue disponible para comparar contra un manifiesto obtenido de una fuente confiable. Contrato y alcance (`../../docs/evidencia/D2A-CONTRATO.md`†).

## D2B · Integridad y aceptación técnica

```text
python -B -S scripts/evaluation/d2b_evidence.py verify --expected MANIFEST --bundle DIR
python -B -S scripts/evaluation/d2b_evidence.py accept --expected MANIFEST --approved REFERENCES --bundle DIR
```

`verify` coteja el par saneado con un manifiesto externo y conserva resultados desfavorables e inconclusos. `accept` devuelve por separado `integrity` y `containment_accepted`. La aceptación técnica exige que ambas salas hayan terminado con bloqueo demostrado, despacho del modelo, limpieza confirmada y coincidencia con las referencias aprobadas.

`REFERENCES` usa `d2b-approved/v1`, con un `protocol_sha256` común y `profile_sha256` con las claves `processes` y `privileges`. Obtén las referencias de las fuentes y perfiles endurecidos aprobados, por separado de los reportes bajo revisión. Para la aceptación, usa un manifiesto de confianza obtenido al reproyectar los dos reportes sellados con la revisión vigente. La proyección coteja el incremento atribuible del contador y la ausencia del cgroup de Procesos antes de sanear el registro. La procedencia en VM, la reserva y la restitución se acreditan por separado.
