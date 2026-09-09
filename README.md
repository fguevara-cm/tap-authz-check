# tap-authz-check

Standalone authorization testing tool for **TAP API**.

**Hallazgo:** PenTest-001 - Lack of authorization enforcement allows system-wide privilege escalation.
**Entorno inicial:** Mirror `https://api.tap.mirror.capmotion.io`.

> ⚠️ **Uso autorizado únicamente.** Esta herramienta ejecuta requests contra APIs con datos reales.
> Usar exclusivamente contra entornos mirror y con cuentas de prueba dedicadas.

## 1. Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verificación:

```bash
tap-authz-check --help
python main.py --help
```

## 2. Configuración

Copiar `.env.example` a `.env` y completar:

```bash
cp .env.example .env
```

> ⚠️ **Nunca** pegues un `session_token`, JWT o cookie real en `.env`, chats, issues,
> logs o commits. Obtén el session_token dinámicamente desde un secret manager
> (1Password CLI, Vault, Doppler) y expórtalo como variable de entorno:
> `export TAP_AUTHZ_SESSION_TOKEN=$(op read ...)`.

La herramienta intercambia el `session_token` contra `POST /api/public/auth/session`
y reutiliza las cookies resultantes (`TAP_SESSION_JWT`, `TAP_REFRESH_TOKEN`,
`XSRF-TOKEN`) en todas las llamadas. Si la sesión expira, se reintenta
automáticamente una vez vía `POST /api/public/auth/refresh-token`.

Variables:

| Variable | Descripción |
|---|---|
| `TAP_AUTHZ_BASE_URL` | URL base de la API |
| `TAP_AUTHZ_SESSION_TOKEN` | Session token de Stitch (usuario de bajo privilegio) |
| `TAP_AUTHZ_ADMIN_SESSION_TOKEN` | Session token admin opcional para controles positivos |
| `TAP_AUTHZ_FIXTURE_FILE` | Path a fixtures (IDs no secretos) |
| `TAP_AUTHZ_TIMEOUT_SECONDS` | Timeout HTTP por request |
| `TAP_AUTHZ_MODE` | `audit` o `verify` |
| `TAP_AUTHZ_DELAY_MS` | Espera entre requests |

Aliases: `SESSION_TOKEN` ≡ `TAP_AUTHZ_SESSION_TOKEN`,
`ADMIN_SESSION_TOKEN` ≡ `TAP_AUTHZ_ADMIN_SESSION_TOKEN`.

El `session_token`, las cookies y el JWT **nunca** se almacenan en YAML, fixtures
ni reportes (la redacción centralizada en `client.py` cubre headers `Authorization`,
`Cookie`, `Set-Cookie` y `X-XSRF-TOKEN`).

## 3. Fixtures

`fixtures/mirror.example.yaml` documenta los IDs requeridos. Copiar a `fixtures/mirror.yaml`
(ignorado por git) y rellenar con valores válidos:

```yaml
environment: mirror
foreign_provider_id: provider-not-assigned-to-test-user
victim_user_id: victim-test-user@example.test
trade_id: test-trade-id
invoice_id: test-invoice-id
settlement_id: test-settlement-id
```

El runner **valida** que `foreign_provider_id` no esté asignado al actor y que `victim_user_id`
difiera del actor. Si falla la validación, el caso se marca `SKIP`.

## 4. Modos

| Modo | Propósito | Exit code `0` cuando |
|---|---|---|
| `audit` | Reconoce vulnerabilidades; no rompe el pipeline | La ejecución finaliza y se genera reporte |
| `verify` | Regresión post-fix | No hay `VULNERABLE` ni `ERROR` críticos |

## 5. Ejemplos

```bash
tap-authz-check --mode audit --report reports/audit.json
tap-authz-check --mode verify --report reports/verify.json
tap-authz-check --only '01_*' --mode audit
tap-authz-check --cases cases/01_user_privilege_escalation.yaml
tap-authz-check --no-mutate
tap-authz-check --allow-destructive --victim-user "$TEST_VICTIM_USER"
tap-authz-check --dry-run
```

## 6. Códigos de salida

| Código | Significado |
|---|---|
| `0` | OK; en `verify` sin vulns ni errores críticos |
| `1` | En `verify` hay al menos un `VULNERABLE` |
| `2` | Config inválida / token ausente / bootstrap fallido |
| `3` | `ERROR` indeterminados por encima del umbral |

## 7. Clasificaciones

- `VULNERABLE` — operación privilegiada aceptada o mutación no autorizada.
- `FIXED` — política aplicada (`401`, `403` o `404` según el caso).
- `ERROR` — timeout, red, `5xx`, schema inesperado. **Un `5xx` nunca es `FIXED`.**
- `SKIP` — fixtures ausentes, destructive sin flag, guardrail violado.
- `PASSIVE` — discovery; respuesta informativa sin conclusión de autorización.

## 8. Procedimiento de restauración

1. Antes de la primera mutación, el runner guarda un snapshot del actor (`/api/user/me`).
2. El cleanup (`restore_user_snapshot`) se ejecuta en `finally`.
3. Si el fix bloquea self-update, intentar restaurar con `--admin-token`.
4. Sin admin token, se registra `WARN` y se documenta la restauración manual.

## 9. Política de casos destructivos

`POST /api/user` y `DELETE /api/user` requieren:
- `--allow-destructive`
- fixture explícito
- IDs verificados como cuentas de prueba

Cleanup ambiguo → se omite y se registra como `SKIP`.

## 10. Limitaciones de discovery

`cases/99_discovery_catalog.yaml` solo ejecuta `GET`/`HEAD`/`OPTIONS`. Las mutaciones nunca
se infieren automáticamente; cada caso requiere curación manual.

## 11. Reporte sanitizado (ejemplo)

```json
{
  "meta": {
    "finding": "PenTest-001",
    "mode": "verify",
    "base_url": "https://api.tap.mirror.capmotion.io",
    "actor": "seller@example.test",
    "tool_version": "0.1.0"
  },
  "summary": { "vulnerable": 0, "fixed": 10, "error_count": 0, "skip": 2 },
  "results": [
    {
      "id": "PUT-user-isAdmin-escalation",
      "classification": "FIXED",
      "request": { "method": "PUT", "path": "/api/user" },
      "response": { "status": 403, "body_snippet": "Insufficient permissions" },
      "evidence": "Privilege escalation denied"
    }
  ]
}
```

Los campos `Authorization`, JWT completo, passwords, cookies y payloads con secretos
nunca se serializan. Use `--redact-bodies` para desactivar snippets de body.

## 12. Estructura del proyecto

```
pentest-001-authz/                   # nombre del directorio (proyecto: tap-authz-check)
├── main.py                          # ejecutable principal (delega al paquete)
├── src/tap_authz_check/             # paquete instalable
│   ├── cli.py                      # argparse
│   ├── config.py                   # pydantic-settings (TAP_AUTHZ_*)
│   ├── client.py                   # httpx.Client wrapper, CSRF, refresh hook
│   ├── session.py                  # exchange Stitch → cookies + refresh
│   ├── bootstrap.py                # GET /api/user/me snapshot + guardrail admin
│   ├── runner.py                   # orquestación de suites
│   ├── classify.py                 # status → Classification
│   ├── models.py / loader.py / templates.py / report.py
├── cases/                           # suites YAML
│   ├── 00_baseline.yaml             # GET /api/user/me
│   ├── 01_user_privilege_escalation.yaml  # PoC 1:1 + flags + horizontal
│   ├── 02_user_admin_crud.yaml      # POST/DELETE/search/findById/IDOR
│   ├── 03_clients_and_configurations.yaml  # horizontal cross-tenant
│   ├── 04_distribution_treasury_payments.yaml
│   ├── 05_analytics_and_reports.yaml
│   ├── 06_trades_invoices_settlements.yaml
│   └── 99_discovery_catalog.yaml    # 290 paths pasivos (GET/HEAD/OPTIONS)
├── tools/
│   ├── extract_paths_from_java.py   # extrae mappings de controllers
│   ├── build_discovery_suite.py     # genera 99_discovery_catalog.yaml
│   └── discovery_catalog.yaml       # cache del catálogo
├── fixtures/                        # IDs no secretos
├── tests/                           # suite offline (respx)
└── docs/schema.sql                  # DDL PostgreSQL
```

## 13. Regenerar discovery

```bash
.venv/bin/python tools/extract_paths_from_java.py \
    --src /path/to/tap-api/src/main/java \
    --out tools/discovery_catalog.yaml

.venv/bin/python tools/build_discovery_suite.py \
    --catalog tools/discovery_catalog.yaml \
    --out cases/99_discovery_catalog.yaml
```

## 8. Comandos Make

```bash
make venv           # crear .venv
make install-dev    # instalar deps editables
make lint           # ruff
make secrets-scan   # escanear archivos por JWTs / secretos
make test           # pytest offline (34 tests)
make discover       # regenerar suite 99 desde tap-api
make run-audit      # TAP_AUTHZ_SESSION_TOKEN=... tap-authz-check --mode audit
make run-verify     # post-fix
make clean          # limpia reports/ y caches
```

`make secrets-scan` falla con exit `1` si detecta un JWT o patrón secret-like
en archivos de texto trackeados. Úsalo en CI antes de subir cambios.
