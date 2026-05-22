"""
AppConfig que aplica los monkey-patches del plugin de hardening:

1. Patch a `update_account_settings` para defensa en profundidad contra
   mass assignment (#3 del dictamen TICDEFENSE).
2. Patch a `AccessTokenView.dispatch` para agregar un rate-limit por
   username en /oauth2/access_token (#1 del dictamen, parte OAuth2).

Notas:
- Open edX upstream YA bloquea campos del sistema (is_staff, is_superuser,
  id, username, is_active, date_joined). Este plugin agrega una capa extra
  con un allowlist explicito de campos editables.
- El patch de mass assignment solo aplica a usuarios NO staff/superuser.
  Los admins conservan su capacidad completa de modificar cualquier campo.
- Intentos rechazados se registran en log para evidencia/auditoria.
"""
import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


# Lista blanca de campos que un usuario normal puede modificar via PATCH
# /api/user/v1/accounts/. Cualquier otro campo en el payload sera descartado
# antes de llegar al serializer.
#
# Si necesitas agregar un campo nuevo (porque el MFE o la app movil lo usa),
# agrega aqui. Si necesitas QUITAR algo, asegurate de probar el flujo
# afectado en el MFE antes de desplegar.
ALLOWED_PROFILE_FIELDS = frozenset({
    "account_privacy",
    "bio",
    "country",
    "email",                 # Open edX maneja el cambio via PendingEmailChange
    "extended_profile",
    "gender",
    "goals",
    "language_proficiencies",
    "level_of_education",
    "mailing_address",
    "name",                  # Open edX registra audit trail en auth_userprofile.meta
    "phone_number",
    "secondary_email",
    "social_links",
    "state",
    "time_zone",
    "year_of_birth",
})


class SecurityHardeningConfig(AppConfig):
    """
    AppConfig que aplica los patches al cargar el LMS.
    """
    name = "security_hardening"
    verbose_name = "Open edX Security Hardening"
    _patched_account = False
    _patched_oauth2 = False

    def ready(self):
        try:
            self._patch_update_account_settings()
        except Exception:
            logger.exception(
                "[SecurityHardening] Error al aplicar patch de update_account_settings"
            )
        try:
            self._patch_oauth2_username_ratelimit()
        except Exception:
            logger.exception(
                "[SecurityHardening] Error al aplicar patch de oauth2 ratelimit"
            )

    def _patch_update_account_settings(self):
        """
        Reemplaza `openedx.core.djangoapps.user_api.accounts.api.update_account_settings`
        por una version que filtra el payload con `ALLOWED_PROFILE_FIELDS` cuando
        el requesting_user no tiene privilegios de staff/superuser.
        """
        if SecurityHardeningConfig._patched_account:
            return

        try:
            from openedx.core.djangoapps.user_api.accounts import api as accounts_api
        except ImportError:
            logger.warning(
                "[SecurityHardening] No se pudo importar accounts.api - patch NO aplicado"
            )
            return

        original_update = accounts_api.update_account_settings

        def safe_update_account_settings(requesting_user, update_data, username=None):
            """
            Wrapper que filtra `update_data` para usuarios no privilegiados.
            """
            try:
                is_privileged = bool(
                    getattr(requesting_user, "is_staff", False) or
                    getattr(requesting_user, "is_superuser", False)
                )

                if not is_privileged and update_data:
                    incoming_keys = set(update_data.keys())
                    rejected = incoming_keys - ALLOWED_PROFILE_FIELDS
                    if rejected:
                        logger.warning(
                            "[SecurityHardening] Mass assignment bloqueado. "
                            "user_id=%s username=%s campos_rechazados=%s",
                            getattr(requesting_user, "id", "?"),
                            username or getattr(requesting_user, "username", "?"),
                            sorted(rejected),
                        )
                        update_data = {
                            k: v for k, v in update_data.items()
                            if k in ALLOWED_PROFILE_FIELDS
                        }
            except Exception:
                # Nunca rompemos el flujo legitimo si algo del patch falla.
                # Loggeamos y dejamos pasar al comportamiento original.
                logger.exception(
                    "[SecurityHardening] Error en safe_update_account_settings - "
                    "fallback al comportamiento original"
                )

            return original_update(requesting_user, update_data, username=username)

        accounts_api.update_account_settings = safe_update_account_settings
        SecurityHardeningConfig._patched_account = True
        logger.info(
            "[SecurityHardening] Patch aplicado a update_account_settings. "
            "Campos permitidos para usuarios no-staff: %s",
            sorted(ALLOWED_PROFILE_FIELDS),
        )

    def _patch_oauth2_username_ratelimit(self):
        """
        Envuelve `openedx.core.djangoapps.oauth_dispatch.views.AccessTokenView.dispatch`
        con un @ratelimit adicional con `key="post:username"`. Esto cierra el gap del
        dictamen #1 (Weak Lock Out) para el endpoint /oauth2/access_token usado por la
        app movil (OAuth2 password grant).

        Open edX upstream ya aplica @ratelimit con key='real_ip' en este view; eso
        limita fuerza bruta desde una sola IP pero NO desde un atacante que rote IPs
        (proxies, redes moviles, etc.). El ratelimit por username aplica el lockout
        sobre el usuario victima sin importar desde donde venga.
        """
        if SecurityHardeningConfig._patched_oauth2:
            return

        try:
            from django.conf import settings
            from django.http import JsonResponse
            from django_ratelimit.core import is_ratelimited
            from openedx.core.djangoapps.oauth_dispatch import views as oauth_views
        except ImportError as exc:
            logger.warning(
                "[SecurityHardening] No se pudo importar dependencias para "
                "oauth2 ratelimit: %s - patch NO aplicado",
                exc,
            )
            return

        target_cls = getattr(oauth_views, "AccessTokenView", None)
        if target_cls is None:
            logger.warning(
                "[SecurityHardening] AccessTokenView no encontrada en oauth_dispatch.views "
                "- patch oauth2 ratelimit NO aplicado"
            )
            return

        rate = getattr(settings, "SECURITY_HARDENING_OAUTH2_USER_RATELIMIT", "5/30m")
        original_dispatch = target_cls.dispatch

        if getattr(original_dispatch, "_security_hardening_patched", False):
            SecurityHardeningConfig._patched_oauth2 = True
            return

        # En lugar de usar @ratelimit como decorador (que espera `request` como
        # primer argumento y se rompe cuando se aplica a un metodo de clase
        # que ya esta envuelto por otro method_decorator de Open edX), llamamos
        # directamente a is_ratelimited() dentro del wrapper. Asi controlamos
        # exactamente que objeto se pasa al rate-limiter y evitamos confusion
        # entre `self` y `request`.
        def patched_dispatch(self, request, *args, **kwargs):
            if request.method == "POST":
                try:
                    ratelimited = is_ratelimited(
                        request=request,
                        group="security_hardening.oauth2_user",
                        fn=patched_dispatch,
                        key="post:username",
                        rate=rate,
                        method="POST",
                        increment=True,
                    )
                except Exception:
                    # No bloquees el login legitimo si el rate-limit falla.
                    logger.exception(
                        "[SecurityHardening] Error en is_ratelimited - fallback a permitir"
                    )
                    ratelimited = False

                if ratelimited:
                    username = request.POST.get("username", "")
                    logger.warning(
                        "[SecurityHardening] /oauth2/access_token rate-limited "
                        "username=%s rate=%s",
                        username,
                        rate,
                    )
                    return JsonResponse(
                        {
                            "error": "too_many_attempts",
                            "error_description": (
                                "Demasiados intentos fallidos de inicio de sesion. "
                                "Intente de nuevo en unos minutos."
                            ),
                        },
                        status=429,
                    )
            return original_dispatch(self, request, *args, **kwargs)

        patched_dispatch._security_hardening_patched = True
        target_cls.dispatch = patched_dispatch
        SecurityHardeningConfig._patched_oauth2 = True
        logger.info(
            "[SecurityHardening] Rate-limit por username aplicado a "
            "/oauth2/access_token: %s",
            rate,
        )
