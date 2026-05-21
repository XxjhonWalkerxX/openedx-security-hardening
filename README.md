# openedx-security-hardening

Plugin de Open edX (Tutor v21+) que aplica medidas de hardening en respuesta al dictamen **TICDEFENSE Cybersecurity del 4 de mayo de 2026** sobre el aplicativo *Cursos @prende.mx*, atendiendo el oficio DGTIC **UAF/713/DGTIC/DSIyPR/324/2026**.

## Vulnerabilidades cubiertas

| # | Vulnerabilidad del dictamen | Severidad | Mecanismo aplicado |
|---|---|---|---|
| 1 | Weak Lock Out Mechanism | Medio | (a) `LoginFailures` upstream para login web `/login_ajax`; (b) `django-axes` para OAuth2 password grant `/oauth2/access_token`. Ambos: 5 intentos / 30 min lockout |
| 3 | Asignación masiva de parámetros (defensa profundidad) | Medio (falso positivo según verificación) | Monkey-patch a `update_account_settings` con allowlist explícito |
| 4 | Activación de cuentas sin necesidad de correo | Medio | Override de `ACCOUNT_VISIBILITY_CONFIGURATION["admin_fields"]` para remover `activation_key` y `pending_name_change` |

## Vulnerabilidades NO cubiertas

| # | Vulnerabilidad | Razón |
|---|---|---|
| 2 | Bypass SSL Pinning | Vive en el cliente Android, no en el backend |
| 5 | Permisos en imágenes de perfil | Vive en la capa de infraestructura (MinIO bucket policy o reverse proxy frente al storage) |

## Requisitos

- Tutor v21.0.0 o superior
- Open edX Ulmo o superior
- Python 3.8+

## Instalación

### Desarrollo (dev)

```bash
# Si estás en el server (cursos-dev) con el código del plugin montado:
tutor local exec lms pip install -e /openedx/extra/openedx-security-hardening

# Si estás instalando desde un repo git:
tutor local exec lms pip install git+https://github.com/aprendemx/openedx-security-hardening.git@main

# Habilitar el plugin Tutor
tutor plugins enable security_hardening

# Regenerar config y reiniciar LMS
tutor config save
tutor local restart lms
```

### Producción (prod)

Mismo procedimiento. Recomendado: incluir el plugin en `OPENEDX_EXTRA_PIP_REQUIREMENTS` o construir una imagen custom con `tutor images build openedx` para que el plugin persista a través de reinicios y nuevos despliegues.

```bash
# Agregar como pip requirement persistente
tutor config save --append 'OPENEDX_EXTRA_PIP_REQUIREMENTS=openedx-security-hardening@git+https://github.com/aprendemx/openedx-security-hardening.git@main'

# Rebuild de la imagen openedx (incluye el plugin)
tutor images build openedx

# Habilitar y aplicar
tutor plugins enable security_hardening
tutor local launch
```

## Configuración opcional

Las siguientes variables se pueden personalizar vía `tutor config save`:

| Variable | Default | Descripción |
|---|---|---|
| `SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS` | `5` | Número de intentos fallidos antes de bloquear la cuenta (#1) |
| `SECURITY_HARDENING_LOCKOUT_PERIOD_SECS` | `1800` (30 min) | Duración del bloqueo en segundos (#1) |
| `SECURITY_HARDENING_REMOVE_ACTIVATION_KEY` | `True` | Si `True`, quita `activation_key` y `pending_name_change` de la API. En Tutor >= 21.0.4 es redundante pero idempotente (#4) |

Ejemplo:
```bash
tutor config save \
  --set SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS=10 \
  --set SECURITY_HARDENING_LOCKOUT_PERIOD_SECS=900
tutor local restart lms
```

## Validación post-instalación

### Validar #1 (lockout)

Desde una máquina externa o WSL:
```bash
API="https://dev.mexicox.gob.mx"
CID="<OAUTH_CLIENT_ID>"
USER="<usuario_de_prueba>"

for i in $(seq 1 10); do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/oauth2/access_token" \
        -d "grant_type=password&client_id=$CID&username=$USER&password=wrong_$i")
    echo "Intento $i: HTTP $code"
done
```

**Esperado tras la instalación:** los primeros 5 intentos devuelven HTTP 400 (`invalid_grant`), los siguientes 5 devuelven HTTP 403 con cuerpo `user_locked_out`.

### Validar #3 (mass assignment defensa)

```bash
TOKEN="<JWT del usuario_de_prueba>"
USER="<su_username>"

# Intentar cambiar campos peligrosos
curl -X PATCH "$API/api/user/v1/accounts/$USER" \
    -H "Authorization: JWT $TOKEN" \
    -H "Content-Type: application/merge-patch+json" \
    -d '{"is_staff": true, "is_superuser": true, "bio": "test"}'

# Verificar en el log del LMS:
tutor local logs lms --tail 50 | grep "SecurityHardening"
```

**Esperado:** ver la línea `[SecurityHardening] Mass assignment bloqueado. user_id=... campos_rechazados=['is_staff', 'is_superuser']` en logs. El campo `bio` sí debe cambiar (es legítimo).

### Validar #4 (activation_key)

```bash
curl "$API/api/user/v1/accounts/$USER" \
    -H "Authorization: JWT $TOKEN" | python -m json.tool | grep activation_key
```

**Esperado:** sin salida (el campo no existe en la respuesta) o `"activation_key": null`.

## Estructura del paquete

```
openedx-security-hardening/
├── pyproject.toml
├── README.md
└── security_hardening/
    ├── __init__.py
    ├── apps.py            # AppConfig + monkey-patch para #3
    └── tutor_plugin.py    # Tutor plugin con settings para #1 y #4
```

## Mecanismo técnico

### #1 — Settings de LoginFailures

Open edX ya incluye el código de lockout (`LoginFailures` model + middleware en `common.djangoapps.student.views.login`), pero viene desactivado por default. Este plugin solo activa las flags:

```python
FEATURES["ENABLE_MAX_FAILED_LOGIN_ATTEMPTS"] = True
MAX_FAILED_LOGIN_ATTEMPTS_ALLOWED = 5
MAX_FAILED_LOGIN_ATTEMPTS_LOCKOUT_PERIOD_SECS = 1800
```

El conteo se realiza por username, persistido en BD (tabla `student_loginfailures`). El lockout se resetea automáticamente tras `MAX_FAILED_LOGIN_ATTEMPTS_LOCKOUT_PERIOD_SECS` segundos o tras un login exitoso.

### #3 — Monkey-patch al api de cuentas

El `apps.py` reemplaza `openedx.core.djangoapps.user_api.accounts.api.update_account_settings` en `ready()` con un wrapper que:

1. Detecta si el `requesting_user` es staff/superuser. Si es admin, no filtra (admin conserva control total).
2. Si NO es admin, filtra `update_data` para conservar solo claves del allowlist `ALLOWED_PROFILE_FIELDS`.
3. Loggea en `WARNING` los campos rechazados con `user_id`, `username`, lista de campos.
4. Si algo del patch falla, hace fallback al comportamiento original (failsafe).

Esto es defensa en profundidad. Open edX upstream **ya bloquea** los campos críticos del sistema (`is_staff`, `is_superuser`, `id`, `username`, `is_active`, `date_joined`). Este plugin agrega una capa extra de filtrado antes del serializer.

### #4 — Override de admin_fields

El campo `activation_key` está incluido por defecto en `ACCOUNT_VISIBILITY_CONFIGURATION["admin_fields"]` de Open edX (`lms/envs/common.py`). El serializer `UserReadOnlySerializer.to_representation()` lo emite cuando el requester es el propio usuario.

Este plugin filtra esa lista quitando `activation_key` y `pending_name_change`. Idéntico efecto funcional al fix upstream `ad342ae` de Axim Collaborative.

## Rollback

Para deshabilitar el plugin sin desinstalar:

```bash
tutor plugins disable security_hardening
tutor local restart lms
```

Esto revierte el lockout (#1) y el override de admin_fields (#4) instantáneamente. El monkey-patch del AppConfig (#3) NO se ejecuta porque sin el plugin Tutor activo, las settings del plugin no se aplican — pero si el paquete sigue instalado, el AppConfig se ejecuta al arrancar el LMS. Para revertir completamente #3, también:

```bash
tutor local exec lms pip uninstall -y openedx-security-hardening
tutor local restart lms
```

## Referencias

- Dictamen TICDEFENSE Cybersecurity, 4 de mayo de 2026.
- Oficio DGTIC UAF/713/DGTIC/DSIyPR/324/2026, 6 de mayo de 2026.
- Fix upstream `activation_key`: https://github.com/openedx/edx-platform/commit/ad342ae
- CHANGELOG Tutor v21.0.4 (10-abril-2026): https://github.com/overhangio/tutor/blob/release/CHANGELOG.md
- Open edX `LoginFailures`: `common/djangoapps/student/models/user.py`
- OWASP Top 10 2021: A07 (Auth Failures), A04 (Insecure Design), A01 (Broken Access Control)

## Licencia

MIT. Ver `LICENSE` (por crear).

## Autor

EMI / Cursos @prende.mx
nicolas.1im9.09@gmail.com
