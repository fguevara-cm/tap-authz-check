# AGENTS.md

Convenciones operativas para agentes que trabajen en este repositorio.

## Identidad del proyecto

- **Nombre lógico:** `tap-authz-check`.
- **Nombre del paquete:** `tap_authz_check` (PEP 8).
- **Hallazgo:** PenTest-001 - Lack of authorization enforcement.
- **Entorno inicial:** Mirror `https://api.tap.mirror.capmotion.io`.

## Skills activas

- `python-backend`
- `python-code-style`
- `python-design-patterns`

## Reglas de código

1. **No** concentrar lógica en `main.py`; solo delega al paquete (`src/tap_authz_check/`).
2. Lógica de negocio en `src/tap_authz_check/*.py` como paquete instalable.
3. **Nunca** persistir JWT, header `Authorization`, passwords ni cookies en archivos
   (YAML, fixtures, logs, reportes).
4. **Nunca** considerar un `5xx` como remediación (`FIXED`): siempre es `ERROR`.
5. Placeholders no resueltos ⇒ `SKIP`, nunca string vacío.
6. Mutaciones solo en casos explícitos con `mutate: true`; `--no-mutate` filtra.
7. Destructive (`POST/DELETE /api/user`) requiere `--allow-destructive` y fixture explícito.
8. Redacción centralizada en `client.py` (header `Authorization`, `Cookie`, `Set-Cookie`).

## Estilo

- Type hints obligatorios.
- Sin comentarios inline a menos que el usuario los pida.
- Seguir `ruff` (`pyproject.toml [tool.ruff]`).
- Tests offline obligatorios para clasificador, plantillas y runner (`respx`).

## Estructura

```
main.py                  → entrypoint (delega)
src/tap_authz_check/     → paquete (cli, client, bootstrap, models, templates,
                           classify, runner, report, config, loader)
cases/                   → suites YAML (00..06, 99)
fixtures/                → IDs no secretos (mirror.example.yaml)
tests/                   → suite offline
tools/                   → utilidades (Fase 5: extract_paths_from_java.py,
                           build_discovery_suite.py, discovery_catalog.yaml)
docs/schema.sql          → DDL PostgreSQL (opcional)
reports/                 → salida, ignorada en git
```

## Comandos

```bash
make venv
make install-dev
make lint
make test
make run-audit    # requiere TAP_AUTHZ_TOKEN
make run-verify   # requiere TAP_AUTHZ_TOKEN
```

## Fases

| Fase | DoD |
|---|---|
| 0 | `tap-authz-check --help` corre; `docs/schema.sql` presente |
| 1 | 1 GET + 1 PUT mockeados se clasifican correctamente |
| 2 | distinguir vulnerable vs `403` en Mirror con usuario seller dedicado |
| 3 | suites 02–03 listas |
| 4 | suites 04–06 listas; `5xx` ⇒ `ERROR` |
| 5 | suite 99 (290 paths pasivos) + JUnit XML opcional |
| 6 | lint verde, tests offline verdes, sin secretos en repo |

## Riesgos a vigilar

- Modificar usuario real → usuario seller dedicado + fixtures verificadas.
- Confundir `500` con fix → regla dura: `5xx` ⇒ `ERROR`.
- Token admin accidental → bootstrap aborta con `2` salvo `--force-admin-token`.
- Exposición de JWT → redacción centralizada + tests.
- Sobreinterpretar discovery → `PASSIVE` por defecto.
