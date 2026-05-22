"""
Tutor plugin para openedx-security-hardening.

Inyecta settings de Django en el LMS para cerrar:
  #1 Weak Lock Out Mechanism:
     (a) LoginFailures de Open edX upstream (login web /login_ajax)
     (b) RATELIMIT_RATE global mas estricto + ratelimit por username en
         /oauth2/access_token aplicado via monkey-patch en apps.py
  #4 Activation key exposure: quita el campo de admin_fields
       (solo es necesario en Tutor < 21.0.4 - en versiones >= 21.0.4 el
       fix esta upstream pero el override es idempotente)

Configurar opcionalmente con:

    tutor config save \\
      --set SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS=5 \\
      --set SECURITY_HARDENING_LOCKOUT_PERIOD_SECS=1800 \\
      --set SECURITY_HARDENING_GLOBAL_RATELIMIT="30/m" \\
      --set SECURITY_HARDENING_OAUTH2_USER_RATELIMIT="5/30m"

    tutor local restart lms

Para deshabilitar el plugin:

    tutor plugins disable security_hardening
    tutor local restart lms

Nota historica: la version 1.0.0/1.0.1 de este plugin usaba django-axes
para cubrir el endpoint /oauth2/access_token. Se removio en 1.0.2 porque
AxesStandaloneBackend.authenticate() exige `request` y django-oauth-toolkit
no lo pasa en el password grant -> HTTP 500. Ahora se usa django-ratelimit
(que ya esta integrado en oauth_dispatch/views.py de Open edX) con un
ratelimit adicional por username via monkey-patch.
"""
from tutor import hooks

# Defaults sensatos. Pueden sobreescribirse desde tutor config.
hooks.Filters.CONFIG_DEFAULTS.add_items([
    ("SECURITY_HARDENING_MAX_FAILED_LOGIN_ATTEMPTS", 5),
    ("SECURITY_HARDENING_LOCKOUT_PERIOD_SECS",       1800),   # 30 minutos
    ("SECURITY_HARDENING_REMOVE_ACTIVATION_KEY",     True),
    # Rate limit global (por IP) aplicado a todos los endpoints API
    # protegidos con @ratelimit en Open edX. Default Open edX = "120/m".
    # Lo bajamos para limitar fuerza bruta desde una sola IP.
    ("SECURITY_HARDENING_GLOBAL_RATELIMIT",          "30/m"),
    # Rate limit especifico por username para /oauth2/access_token.
    # Aplicado via monkey-patch en apps.py. Esto cierra el gap del
    # dictamen #1 (Weak Lock Out) para la app movil que NO pasa por
    # /login_ajax sino por el OAuth2 password grant.
    ("SECURITY_HARDENING_OAUTH2_USER_RATELIMIT",     "5/30m"),
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
# El endpoint /oauth2/access_token (password grant) usado por la app
# movil NO pasa por LoginFailures. En su lugar:
#   1. Open edX ya tiene @ratelimit(key='real_ip', rate=RATELIMIT_RATE)
#      en oauth_dispatch/views.py:AccessTokenView. Bajamos el rate
#      global desde 120/m (default Open edX) a 30/m para limitar
#      fuerza bruta desde una sola IP.
#   2. Adicionalmente, apps.py aplica un @ratelimit por username via
#      monkey-patch sobre el mismo view. Esto evita evasion via rotacion
#      de IPs (proxies, datos moviles, etc.).
RATELIMIT_ENABLE = True
RATELIMIT_RATE   = "{{ SECURITY_HARDENING_GLOBAL_RATELIMIT }}"
SECURITY_HARDENING_OAUTH2_USER_RATELIMIT = "{{ SECURITY_HARDENING_OAUTH2_USER_RATELIMIT }}"

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
# y para los avisos del patch de oauth2 ratelimit (#1)
# --------------------------------------------------------------
LOGGING['loggers'].setdefault('security_hardening', {
    'handlers': ['console'],
    'level':    'INFO',
    'propagate': True,
})
"""
))
