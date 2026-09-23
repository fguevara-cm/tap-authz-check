# Generar Suite De Casos De Prueba De Autorizaciónd

> Actúa como especialista en pruebas de autorización de APIs y genera una suite YAML para el proyecto tap-authz-check a
> partir del archivo de entrada indicado.

## Parámetros Reutilizables

Sustituye estos valores antes de usar el prompt. No asumas valores por defecto:

| Parámetro         | Descripción                                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `INPUT_FILE`      | Archivo con el inventario, plan o documentación de endpoints. Puede ser un plan de remediación: no lo trates como contrato de API. |
| `OUTPUT_FILE`     | Ruta del YAML de salida (por ejemplo `cases/<nombre_de_suite>.yaml`).                                                              |
| `PROJECT_ROOT`    | Raíz del proyecto de pruebas tap-authz-check.                                                                                      |
| `API_SOURCE_ROOT` | Raíz opcional del código fuente de la API objetivo.                                                                                |
| `FIXTURE_FILE`    | Fixture permitida para el entorno de prueba (por ejemplo `fixtures/mirror.example.yaml`).                                          |

valores:

- `INPUT_FILE` = `/Users/guedaf/CapMotion/repositories/tap/tap-api/docs/pentest/plan/plan-configuraciones-02.md`
- `OUTPUT_FILE` = `/Users/guedaf/CapMotion/sandbox/security/pentest-001-authz/cases/05_plan-configuraciones-02.yaml`
- `PROJECT_ROOT` = `/Users/guedaf/CapMotion/sandbox/security/pentest-001-authz/`
- `API_SOURCE_ROOT` = `/Users/guedaf/CapMotion/repositories/tap/tap-api/`
- `FIXTURE_FILE` = `/Users/guedaf/CapMotion/sandbox/security/pentest-001-authz/fixtures/mirror.yaml`

Reglas sobre los parámetros:

1. `INPUT_FILE` aporta como mucho método, ruta y objetivo de autorización. No garantiza bodies, DTOs, query params, IDs,
   enums ni respuestas contractuales.
2. Si `API_SOURCE_ROOT` no está disponible o no permite verificar un contrato, los endpoints afectados van
   a `PENDIENTES`. No generes bodies por aproximación.
3. Si `FIXTURE_FILE` no resuelve un placeholder, el caso terminará en `SKIP` por diseño. Decláralo en el informe; no
   fabriques el valor.
4. no todos los campos deben ser placeholders, trata de usar el menor número de variables placeholder posible, crear el
   caso de prueba con los valores de los campos acorder a valores que el campo puede recibir.

## Contexto Del Proyecto

Antes de generar la salida, estudia:

- Las suites vigentes en `cases/` (patrones de formato, expectativas y placeholders).
- `src/tap_authz_check/models.py` (schema real: `CaseSuite`, `TestCase`, `Expectation`, `PostCheck`, `CleanupSpec`).
- `src/tap_authz_check/templates.py` (placeholders disponibles y `build_context`).
- `src/tap_authz_check/client.py` (modelo de sesión: cookies, CSRF, redacción).
- `src/tap_authz_check/classify.py` (clasificación VULNERABLE / FIXED / ERROR / SKIP / PASSIVE).
- `src/tap_authz_check/runner.py` (renderizado de path, headers y body; SKIP por placeholder ausente).
- `AGENTS.md` (reglas operativas y de seguridad).
- `FIXTURE_FILE` (IDs y placeholders disponibles).

## Objetivo

Generar `OUTPUT_FILE` con casos de autorización para los endpoints descubiertos en `INPUT_FILE`, más un informe textual
con trazabilidad y pendientes. No inventes contratos, cuerpos, IDs, permisos ni resultados: todo dato debe provenir
de `INPUT_FILE`, del código fuente verificado o de `FIXTURE_FILE`.

## Fase Obligatoria: Descubrimiento

Ejecútala antes de escribir YAML y sin emitir requests:

1. Lee `INPUT_FILE` y extrae cada combinación de método HTTP y ruta.
2. Conserva la referencia de origen de cada endpoint (número de entrada, sección o línea) para la trazabilidad.
3. Normaliza y deduplica por método y path, sin perder las referencias de origen.
4. Cuando `INPUT_FILE` no incluya el contrato del request, verifica el endpoint en `API_SOURCE_ROOT`:
    - localiza el handler por su anotación de
      mapping (`@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@RequestMapping` o equivalentes del
      framework);
    - sigue el tipo del `@RequestBody` (o equivalente) hasta sus DTOs, tipos anidados, validaciones, enums y valores por
      defecto;
    - documenta los campos obligatorios y opcionales con sus tipos.
5. Busca en tests, fixtures, snapshots o documentación de la API los IDs y valores válidos demostrados.
6. Determina la política de autorización solo con evidencia explícita de la fuente. Sin evidencia, la política
   es `unknown` y limita el endpoint a probe pasivo o pendiente.

Prohibido:

- Inferir un body por similitud con otro endpoint (solo sirve como referencia de estilo, nunca como contrato).
- Inventar IDs, roles, enums, relaciones ni valores de configuración.
- Escribir YAML ejecutable antes de completar la fase de descubrimiento.

## Reglas Del Schema YAML

El YAML solo puede usar los campos soportados por el modelo:

- Suite: `version`, `suite`, `finding`, `defaults`, `cases`.
- `defaults`: `auth`, `required`, `headers`, `mutate`, `destructive`.
-

Caso: `id`, `name`, `category`, `method`, `path`, `headers`, `body`, `mutate`, `destructive`, `required`, `mark_vulnerable_if`, `expect_when_fixed`, `post_checks`, `cleanup`.

- Expectativas: `status_in`, `must_equal`, `must_remain`, `must_change`.
- `post_checks`: `method`, `path`, `assert_json`.
- `cleanup`: `strategy` (`restore_user_snapshot` o `none`).

Prohibido escribir en el YAML (solo valen para el informe
textual): `purpose`, `authorization`, `scope`, `fixture`, `query`, `notes` y cualquier campo que `models.py` no soporte.

Reglas:

1. Estructura mínima de la suite: `version: 1`, `suite`, `finding: PenTest-001`, `defaults`
   con `auth: low_priv`, `required: true` y `Content-Type: application/json`, y `cases`.
2. `id` único, estable y descriptivo: método + recurso normalizado + variante, por
   ejemplo `GET-clients-configurations-foreign`.
3. Usa el método HTTP y el path de la fuente verificada. Los query params van embebidos en `path`, porque el runner no
   tiene un campo `query` separado.
4. Placeholders con doble llave; solo se resuelven con `templates.build_context` o con `extra` de la fixture:
    - `{{actor_email}}`, `{{actor_name}}`, `{{actor_company}}`, `{{foreign_provider_id}}`
5. Parámetros de ruta: sustituye `{param}` por `{{placeholder}}` solo cuando exista un mapeo demostrado a la fixture.
   Una ruta con parámetros sin resolver nunca entra en `cases`: va a `PENDIENTES` indicando el parámetro, la fixture
   requerida y la razón.
6. Nunca uses strings vacíos para simular IDs. Un placeholder ausente debe terminar en `SKIP`, nunca en una request con
   valor vacío.
7. providerId, client, cli, son equivalentes, para estas variables se debe usar `{{foreign_provider_id}}`
8. owner, investor, investorId, son equivalentes, para estas variables usar `{{foreign_investor_id}}`
9. poolId, capacitiesPollsId, son equivalentes, para estas variables usar el placeholder `{{foreign_pool_id}}`

## Reglas De Construcción Del Body

1. Genera `body` únicamente cuando el contrato del request esté demostrado por código fuente, especificación o test
   fiable.
2. Incluye todos los campos obligatorios y respeta tipos, enums, restricciones y estructuras anidadas.
3. Usa placeholders solo para valores existentes en la fixture. No conviertas `null`, `""`, `false`, `0` ni `[]` en
   valores por defecto salvo que el contrato demuestre su validez para ese campo.
4. Si falta cualquier dato obligatorio, registra el endpoint en `PENDIENTES`. No generes una mutación ejecutable ni
   presentes un body vacío o parcial como caso completo.
5. `must_change` y `must_remain` requieren un valor inicial y una comprobación posterior verificables. Un status 200 por
   sí solo no prueba que un flag o una relación haya cambiado.

## Reglas De Autorización

1. Usa `auth: low_priv` (actor seller no administrador) salvo que la fuente indique otro actor.
2. Distingue las dos expectativas:
    - `mark_vulnerable_if` refleja lo que la fuente indica que ocurre hoy (el vector es aceptado por el endpoint).
    - `expect_when_fixed` refleja la política objetivo declarada explícitamente en `INPUT_FILE` (por ejemplo, restringir
      el endpoint a administradores) o demostrada en el código. Sin política explícita, no inventes la expectativa.
3. Para un endpoint que el actor no debe poder usar:
    - lectura de datos protegidos: `mark_vulnerable_if.status_in: [200]`;
    - escritura: `mark_vulnerable_if.status_in: [200, 201, 204]`, salvo que el contrato indique otro resultado;
    - `expect_when_fixed.status_in` puede incluir `[401, 403, 404]`; `404` solo si se acepta la ocultación del recurso;
    - no marques `200` como vulnerable si el endpoint está explícitamente autorizado para el actor.
4. Para un endpoint autorizado al actor, usa expectativas de éxito y no lo marques como vulnerable.
5. Si solo se conoce un endpoint de lectura con política desconocida, genera como máximo un probe
   pasivo (`mutate: false`, `required: false`, sin `mark_vulnerable_if`). Si necesita un ID sin fixture, va
   a `PENDIENTES`.
6. `post_checks` solo con una ruta de lectura y una aserción concreta que confirme el efecto o su ausencia. Ten presente
   que el runner recopila `assert_json` como evidencia; no la evalúa como aserción automática.
7. `cleanup.strategy: restore_user_snapshot` solo cuando el mecanismo de restauración esté justificado por los casos
   existentes. No inventes rollback para recursos sin cleanup conocido.

## Reglas De Mutación Y Seguridad

1. GET, HEAD y OPTIONS siempre con `mutate: false`.
2. POST, PUT, PATCH y DELETE solo con `mutate: true` cuando existan contrato, fixtures, política y autorización
   operacional suficientes. No conviertas una mutación desconocida en un probe `mutate: false` para inflar la suite.
3. Un caso destructivo lleva `destructive: true`, queda separado de los casos de lectura y
   requiere `--allow-destructive` con fixture explícita. No lo marques destructivo solo por usar POST.
4. No generes casos que creen, borren o modifiquen datos reales; usa solo fixtures de prueba existentes.
5. No incluyas session_token, TAP_SESSION_JWT, TAP_REFRESH_TOKEN, JWT, Authorization, Cookie, X-XSRF-TOKEN, passwords ni
   secretos en el YAML, cuerpos de ejemplo ni comentarios.
6. Nunca incluyas 5xx en `expect_when_fixed`: un 5xx siempre es `ERROR` y no demuestra una denegación correcta.

## Plantilla Genérica De Caso

```yaml
  - id: METHOD-recurso-normalizado-variante
    name: Vector de autorización que se comprueba
    category: vertical_privilege|horizontal_privilege|enumeration|baseline
    method: GET|POST|PUT|PATCH|DELETE
    path: /api/recurso/{{placeholder}}
    mutate: false
    # body: solo si el contrato del request está demostrado
    mark_vulnerable_if:
      status_in: [ 200 ]
    expect_when_fixed:
      status_in: [ 401, 403, 404 ]
```

Para el formato vigente completo, consulta las suites existentes en `cases/`.

## Cobertura Y Pendientes

- Suite completa significa: cada endpoint único descubierto termina como caso ejecutable, probe pasivo permitido o
  pendiente documentado. No significa un caso por cada aparición en `INPUT_FILE`.
- Las repeticiones de la entrada se conservan en la tabla de trazabilidad, pero no generan requests duplicadas salvo que
  exista una diferencia de vector demostrada.
- El schema actual no soporta pendientes dentro del YAML: repórtalos en el informe textual, o solicita antes ampliar
  formalmente `models.py`.

## Salida Exigida

Entrega dos partes:

1. Contenido de `OUTPUT_FILE`: YAML válido contra el schema real, sin casos inventados.
2. Informe textual con:
    - endpoints procesados, normalizados y deduplicados;
    - tabla de trazabilidad hacia `INPUT_FILE`;
    - casos ejecutables generados y su justificación de contrato, fixture y política;
    - pendientes con: método, path, datos faltantes, fuente a consultar y condición para volverlo ejecutable;
    - placeholders no resolubles;
    - supuestos rechazados por falta de evidencia;
    - pasos concretos para completar la suite.

Declara explícitamente si no puedes crear ningún caso ejecutable. Una suite con pocos casos válidos y pendientes bien
explicados es correcta; una suite numerosa con bodies inventados no lo es.

## Validación Posterior (Opcional Y Separada)

Ejecuta solo tras generar y validar el YAML, y solo con un entorno controlado:

1. Valida primero el YAML contra el modelo y en modo `--dry-run`, antes de cualquier request.
2. Ejecuta con el runner del proyecto y su modelo de sesión real (cookies + CSRF del cliente). No uses un curl
   con `Authorization: Bearer` si el proyecto no usa Bearer.
3. Nunca solicites, imprimas ni registres tokens, cookies, JWT ni headers sensibles. Usa `<REDACTED>`.
4. Clasifica cada respuesta:
    - 2xx: vector válido; en mutaciones verifica persistencia con snapshot antes/después. Un 2xx sin efecto no es
      VULNERABLE real.
    - 400/422: body inválido o error de validación; no es evidencia de autorización correcta. Ajusta el YAML solo con
      datos del contrato o del snapshot real.
    - 401: sesión expirada; renueva con el mecanismo del proyecto y reintenta.
    - 404: verifica el path contra la fuente antes de darlo por inexistente.
    - 5xx: `ERROR`; escala y reporta de inmediato, nunca lo declares como remediación.
    - `SKIP` y `PASSIVE` se informan por separado y nunca se cuentan como `FIXED`.
5. Nunca modifiques un usuario real que no sea el actor de prueba. Si un caso persistiría un cambio sensible, avisa al
   operador antes de continuar para que decida el rollback.
6. Un endpoint sensible descubierto durante la validación y ausente de la suite se anota como candidato
   para `tools/build_discovery_suite.py` (suite 99); no se ejecuta.