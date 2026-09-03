# fixtures

Este directorio contiene fixtures **sin secretos**: solo IDs no sensibles usados
por las suites YAML para referenciar recursos en el entorno mirror.

## Uso

```bash
cp fixtures/mirror.example.yaml fixtures/mirror.yaml
# editar fixtures/mirror.yaml con IDs válidos del entorno
```

El archivo real `fixtures/mirror.yaml` está excluido por `.gitignore`. Nunca
incluya JWT, passwords, cookies ni datos personales en fixtures.

## Validaciones del runner

- `foreign_provider_id` no debe estar asignado al actor (snapshot `/api/user/me`).
- `victim_user_id` no debe coincidir con el actor.

Cualquier violación marca el caso como `SKIP`.
