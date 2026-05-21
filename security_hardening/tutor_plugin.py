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
# Vulnerabilidad #1 - Weak Lock Out Mechanism
# --------------------------------------------------------------
# Activa el mecanismo nativo LoginFailures de Open edX que bloquea
# temporalmente cuentas tras N intentos fallidos consecutivos.
# Tras alcanzar el umbral, los intentos siguientes devuelven HTTP 403
# con error 'user_locked_out' aunque la contrasena sea correcta.
FEATURES["ENABLE_MAX_FAILED_LOGIN_ATTEMPTS"] = True
MAX_FAILED_LOGIN_ATTEMPTS_ALLOWED = {{ SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS }}
MAX_FAILED_LOGIN_ATTEMPTS_LOCKOUT_PERIOD_SECS = {{ SECURITY_HARDENING_LOCKOUT_PERIOD_SECS }}

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
