"""
Tutor plugin para openedx-security-hardening.

Inyecta settings de Django en el LMS para cerrar:
  #1 Weak Lock Out Mechanism: activa LoginFailures de Open edX upstream
  #4 Activation key exposure: quita el campo de admin_fields
       (solo es necesario en Tutor < 21.0.4 — en versiones >= 21.0.4 el
       fix esta upstream pero el override es idempotente)

Configurar opcionalmente con:

    tutor config save \
      --set SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS=5 \
      --set SECURITY_HARDENING_LOCKOUT_PERIOD_SECS=1800

    tutor local restart lms

Para deshabilitar el plugin:

    tutor plugins disable security_hardening
    tutor local restart lms
"""
from tutor import hooks

# Defaults sensatos. Pueden sobreescribirse desde tutor config.
hooks.Filters.CONFIG_DEFAULTS.add_items([
    ("SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS", 5),
    ("SECURITY_HARDENING_LOCKOUT_PERIOD_SECS",       1800),   # 30 minutos
    ("SECURITY_HARDENING_REMOVE_ACTIVATION_KEY",     True),
    # django-axes: cubre el endpoint /oauth2/access_token (password grant)
    # que LoginFailures de Open edX upstream NO cubre.
    ("SECURITY_HARDENING_AXES_ENABLED",              True),
])


# Patch a settings del LMS - SOLO LMS, NO CMS (Studio no necesita estos cambios).
hooks.Filters.ENV_PATCHES.add_item((
    "openedx-lms-common-settings",
    """
# ============================================================
# openedx-security-hardening - remediacion dictamen TICDEFENSE
# Oficio DGTIC UAF/713/DGTIC/DSIyPR/324/2026 (06-may-2026)
# ============================================================

# --------------------------------------------------------------
# Vulnerabilidad #1 - Weak Lock Out Mechanism (parte A: login web)
# --------------------------------------------------------------
# Activa el mecanismo nativo LoginFailures de Open edX que bloquea
# temporalmente cuentas tras N intentos fallidos consecutivos en el
# login web/MFE (/login_ajax). Tras alcanzar el umbral, los intentos
# siguientes devuelven HTTP 403 con error 'user_locked_out' aunque la
# contrasena sea correcta.
FEATURES["ENABLE_MAX_FAILED_LOGIN_ATTEMPTS"] = True
MAX_FAILED_LOGIN_ATTEMPTS_ALLOWED = {{ SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS }}
MAX_FAILED_LOGIN_ATTEMPTS_LOCKOUT_PERIOD_SECS = {{ SECURITY_HARDENING_LOCKOUT_PERIOD_SECS }}

# --------------------------------------------------------------
# Vulnerabilidad #1 - Weak Lock Out Mechanism (parte B: OAuth2)
# --------------------------------------------------------------
# LoginFailures de Open edX NO cubre el endpoint /oauth2/access_token
# (password grant) que usa la app movil. django-axes hookea a las
# signals de Django auth (user_login_failed / user_logged_in) por lo
# que intercepta TODOS los flujos de autenticacion: web, OAuth2 password
# grant, social auth, etc.
{% if SECURITY_HARDENING_AXES_ENABLED -%}
INSTALLED_APPS.append("axes")

MIDDLEWARE.append("axes.middleware.AxesMiddleware")

# AxesStandaloneBackend debe ir al inicio para que intercepte primero.
AUTHENTICATION_BACKENDS = ["axes.backends.AxesStandaloneBackend"] + list(AUTHENTICATION_BACKENDS)

# Parametros de bloqueo
AXES_FAILURE_LIMIT       = {{ SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS }}
AXES_COOLOFF_TIME        = {{ SECURITY_HARDENING_LOCKOUT_PERIOD_SECS }} / 3600.0   # axes espera horas
AXES_LOCKOUT_PARAMETERS  = ["username"]    # bloquea por username (no por IP, que es de CDN)
AXES_RESET_ON_SUCCESS    = True            # login exitoso resetea contador
AXES_LOCKOUT_CALLABLE    = None            # usa default (403 con JSON)
AXES_DISABLE_ACCESS_LOG  = False           # mantiene audit trail en BD
AXES_ENABLE_ADMIN        = True            # ver intentos desde Django admin
{%- endif %}

# --------------------------------------------------------------
# Vulnerabilidad #4 - Activacion de cuentas sin necesidad de correo
# --------------------------------------------------------------
# Quita 'activation_key' y 'pending_name_change' del listado de
# campos visibles para staff y para el propio usuario via
# /api/user/v1/accounts/{username}. Esto evita que un usuario obtenga
# su propio token de activacion via la API y se active sin acceso al
# correo electronico de verificacion.
#
# En Tutor >= 21.0.4 este fix ya viene upstream (commit ad342ae de
# edx-platform). Este override es idempotente: filtrar una lista que
# ya no contiene el campo no tiene efecto colateral.
{% if SECURITY_HARDENING_REMOVE_ACTIVATION_KEY -%}
ACCOUNT_VISIBILITY_CONFIGURATION["admin_fields"] = [
    _field for _field in ACCOUNT_VISIBILITY_CONFIGURATION.get("admin_fields", [])
    if _field not in ("activation_key", "pending_name_change")
]
{%- endif %}

# --------------------------------------------------------------
# Logger para los warnings del monkey-patch de mass assignment (#3)
# --------------------------------------------------------------
# El AppConfig SecurityHardeningConfig escribe a este logger cada vez
# que detecta un PATCH que intenta modificar campos fuera del allowlist.
LOGGING['loggers'].setdefault('security_hardening', {
    'handlers': ['console'],
    'level':    'INFO',
    'propagate': True,
})
"""
))
