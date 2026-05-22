# openedx-security-hardening

Plugin de Open edX (Tutor v21+) que aplica medidas de hardening en respuesta al dictamen **TICDEFENSE Cybersecurity del 4 de mayo de 2026** sobre el aplicativo *Cursos @prende.mx*, atendiendo el oficio DGTIC **UAF/713/DGTIC/DSIyPR/324/2026**.

## Vulnerabilidades cubiertas

| # | Vulnerabilidad del dictamen | Severidad | Mecanismo aplicado |
|---|---|---|---|
| 1 | Weak Lock Out Mechanism | Medio | (a) `LoginFailures` upstream para login web `/login_ajax` (5 intentos / 30 min); (b) `RATELIMIT_RATE` global bajado de `120/m` a `30/m` (limita fuerza bruta por IP en endpoints API); (c) `@ratelimit(key="post:username", rate="5/30m")` aplicado por monkey-patch a `AccessTokenView.dispatch` para el endpoint `/oauth2/access_token` que usa la app móvil |
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
- `django-ratelimit` (incluido como dependencia)

## Instalación

> **Importante:** este plugin se debe instalar en **dos lugares**:
>
> 1. El **venv del host** donde corre el comando `tutor` (para que Tutor lea el entry point `tutor.plugin.v1` y aplique el `ENV_PATCHES` al renderear settings).
> 2. La **imagen openedx** del contenedor LMS (para que Django pueda importar el AppConfig y aplicar los monkey-patches al arranque).

### Paso 1 — Instalar en el host

```bash
# En cursos-dev:
/opt/tutor/venv/bin/pip install --no-cache-dir \
    git+https://github.com/XxjhonWalkerFXxX/openedx-security-hardening.git@master

# Verifica
/opt/tutor/venv/bin/pip show openedx-security-hardening | grep Version
tutor plugins list | grep security_hardening
```

### Paso 2 — Habilitar y renderear settings

```bash
tutor plugins enable security_hardening
tutor config save

# Confirma que el patch llego al settings renderizado
grep -nE "RATELIMIT_RATE|SECURITY_HARDENING_OAUTH2_USER_RATELIMIT|MAX_FAILED_LOGIN_ATTEMPTS_ALLOWED" \
    $(tutor config printroot)/env/apps/openedx/settings/lms/production.py
```

### Paso 3 — Incluir en la imagen openedx

Agrega al `config.yml` de tutor (vía `tutor config save --append` o editando directamente):

```yaml
OPENEDX_EXTRA_PIP_REQUIREMENTS:
  - git+https://github.com/aprendemx/openedx-security-hardening.git@master
```

Y reconstruye:

```bash
tutor images build openedx
tutor local launch     # o `tutor local restart lms` si ya estaba corriendo
```

### Paso 4 — Verificación

```bash
# El paquete debe estar dentro del contenedor LMS
tutor local exec lms pip show openedx-security-hardening

# Los logs deben mostrar ambos patches aplicados al arranque
tutor local logs lms --tail 200 2>&1 | grep -i SecurityHardening
# Esperado:
#   [SecurityHardening] Patch aplicado a update_account_settings. Campos permitidos: [...]
#   [SecurityHardening] Rate-limit por username aplicado a /oauth2/access_token: 5/30m
```

## Configuración opcional

| Variable | Default | Descripción |
|---|---|---|
| `SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS` | `5` | Intentos fallidos antes de bloquear (LoginFailures de `/login_ajax`) |
| `SECURITY_HARDENING_LOCKOUT_PERIOD_SECS` | `1800` (30 min) | Duración del bloqueo en segundos |
| `SECURITY_HARDENING_GLOBAL_RATELIMIT` | `"30/m"` | Rate-limit global por IP aplicado a `RATELIMIT_RATE` (afecta a todos los endpoints API protegidos con `@ratelimit`) |
| `SECURITY_HARDENING_OAUTH2_USER_RATELIMIT` | `"5/30m"` | Rate-limit por **username** específico para `/oauth2/access_token` (cierra el gap del password grant para la app móvil) |
| `SECURITY_HARDENING_REMOVE_ACTIVATION_KEY` | `True` | Quita `activation_key` y `pending_name_change` de la API. En Tutor >= 21.0.4 ya viene upstream — idempotente |

Ejemplo:
```bash
tutor config save \
  --set SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS=10 \
  --set SECURITY_HARDENING_OAUTH2_USER_RATELIMIT="3/30m"
tutor local restart lms
```

## Validación post-instalación

### Validar #1 — lockout del OAuth2 password grant

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

**Esperado:** intentos 1–5 → HTTP 400 (`invalid_grant`); intentos 6+ → HTTP 429 (`Too Many Requests`) por el ratelimit por username. El bloqueo dura 30 minutos.

### Validar #1 — lockout del login web

```bash
for i in $(seq 1 10); do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/user_api/v1/account/login_session/" \
        -d "email=$USER@example.com&password=wrong_$i")
    echo "Intento $i: HTTP $code"
done
```

**Esperado:** primeros 5 HTTP 403 normales; intento 6 en adelante HTTP 403 con cuerpo `user_locked_out`.

### Validar #3 — mass assignment defensa

```bash
TOKEN="<JWT del usuario_de_prueba>"
USER="<su_username>"

curl -X PATCH "$API/api/user/v1/accounts/$USER" \
    -H "Authorization: JWT $TOKEN" \
    -H "Content-Type: application/merge-patch+json" \
    -d '{"is_staff": true, "is_superuser": true, "bio": "test"}'

tutor local logs lms --tail 50 | grep "SecurityHardening"
```

**Esperado:** ver la línea `[SecurityHardening] Mass assignment bloqueado. user_id=... campos_rechazados=['is_staff', 'is_superuser']`. El campo `bio` sí debe cambiar.

### Validar #4 — activation_key

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
    ├── apps.py            # AppConfig + monkey-patches (#3 mass assignment, #1 oauth2 ratelimit)
    └── tutor_plugin.py    # Tutor plugin con settings (#1 LoginFailures + RATELIMIT, #4 admin_fields)
```

## Mecanismo técnico

### #1 (a) — LoginFailures de Open edX

Open edX ya incluye el código de lockout (`LoginFailures` model + middleware en `common.djangoapps.student.views.login`), pero viene desactivado por default. Este plugin solo activa las flags:

```python
FEATURES["ENABLE_MAX_FAILED_LOGIN_ATTEMPTS"] = True
MAX_FAILED_LOGIN_ATTEMPTS_ALLOWED = 5
MAX_FAILED_LOGIN_ATTEMPTS_LOCKOUT_PERIOD_SECS = 1800
```

El conteo se realiza por username, persistido en BD (tabla `student_loginfailures`). Se resetea automáticamente tras el periodo o tras un login exitoso. Cubre `/login_ajax` y `/user_api/v1/account/login_session/`.

### #1 (b) — RATELIMIT_RATE global

Open edX trae `django-ratelimit` configurado con `RATELIMIT_RATE = "120/m"` por default. Lo bajamos a `30/m`. Esto aplica a varios endpoints API que usan el decorador `@ratelimit(rate=settings.RATELIMIT_RATE)` — entre ellos `oauth_dispatch/views.py:AccessTokenView`. Sirve como primera barrera contra fuerza bruta por IP.

### #1 (c) — Rate-limit por username en `/oauth2/access_token`

Sin esto, un atacante que rote IPs (proxies, datos móviles) evade el rate-limit por IP. Aplicamos un segundo decorador `@ratelimit(key="post:username", rate="5/30m", block=True)` sobre el método `dispatch` de `AccessTokenView` mediante monkey-patch en `apps.py`. Esto bloquea por usuario víctima sin importar la IP de origen.

> Nota histórica: las versiones 1.0.0 y 1.0.1 de este plugin usaban `django-axes` para esta capa. Se removió en 1.0.2 porque `AxesStandaloneBackend.authenticate()` exige el argumento `request` que `django-oauth-toolkit` no pasa en el password grant, lo que producía HTTP 500 sistemáticamente en todos los intentos al endpoint.

### #3 — Monkey-patch al api de cuentas

El `apps.py` reemplaza `openedx.core.djangoapps.user_api.accounts.api.update_account_settings` en `ready()` con un wrapper que:

1. Detecta si el `requesting_user` es staff/superuser. Si es admin, no filtra.
2. Si NO es admin, filtra `update_data` para conservar solo claves del allowlist `ALLOWED_PROFILE_FIELDS`.
3. Loggea en `WARNING` los campos rechazados con `user_id`, `username`, lista de campos.
4. Si algo del patch falla, hace fallback al comportamiento original (failsafe).

Esto es defensa en profundidad. Open edX upstream **ya bloquea** los campos críticos del sistema (`is_staff`, `is_superuser`, `id`, `username`, `is_active`, `date_joined`).

### #4 — Override de admin_fields

El campo `activation_key` está incluido por defecto en `ACCOUNT_VISIBILITY_CONFIGURATION["admin_fields"]` de Open edX (`lms/envs/common.py`). El serializer `UserReadOnlySerializer.to_representation()` lo emite cuando el requester es el propio usuario.

Este plugin filtra esa lista quitando `activation_key` y `pending_name_change`. Idéntico efecto funcional al fix upstream `ad342ae` de Axim Collaborative.

## Rollback

Para deshabilitar el plugin sin desinstalar:

```bash
tutor plugins disable security_hardening
tutor local restart lms
```

Esto revierte los settings de lockout (#1) y el override de admin_fields (#4) instantáneamente. Los monkey-patches del AppConfig (#3 mass assignment y #1 oauth2 ratelimit) **se siguen aplicando** si el paquete está instalado en el contenedor, porque Django carga la app via entry point `lms.djangoapp`. Para revertir completamente:

```bash
tutor local exec lms pip uninstall -y openedx-security-hardening
tutor local restart lms
```

O en imagen permanente: quita la línea del `OPENEDX_EXTRA_PIP_REQUIREMENTS` y `tutor images build openedx`.

## Referencias

- Dictamen TICDEFENSE Cybersecurity, 4 de mayo de 2026.
- Oficio DGTIC UAF/713/DGTIC/DSIyPR/324/2026, 6 de mayo de 2026.
- Fix upstream `activation_key`: https://github.com/openedx/edx-platform/commit/ad342ae
- CHANGELOG Tutor v21.0.4 (10-abril-2026): https://github.com/overhangio/tutor/blob/release/CHANGELOG.md
- Open edX `LoginFailures`: `common/djangoapps/student/models/user.py`
- Open edX OAuth2 dispatch view: `openedx/core/djangoapps/oauth_dispatch/views.py`
- `django-ratelimit` docs: https://django-ratelimit.readthedocs.io/
- OWASP Top 10 2021: A07 (Auth Failures), A04 (Insecure Design), A01 (Broken Access Control)

## Licencia

MIT.

## Autor

EMI / Cursos @prende.mx
nicolas.1im9.09@gmail.com
