"""
AppConfig que aplica el monkey-patch a `update_account_settings` para
implementar defensa en profundidad contra mass assignment (#3 del
dictamen TICDEFENSE).

Notas:
- Open edX upstream YA bloquea campos del sistema (is_staff, is_superuser,
  id, username, is_active, date_joined). Este plugin agrega una capa extra
  con un allowlist explicito de campos editables.
- El patch solo aplica a usuarios NO staff/superuser. Los admins conservan
  su capacidad completa de modificar cualquier campo.
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
    AppConfig que aplica el patch al cargar el LMS.
    """
    name = "security_hardening"
    verbose_name = "Open edX Security Hardening"
    _patched = False

    def ready(self):
        try:
            self._patch_update_account_settings()
        except Exception:
            logger.exception(
                "[SecurityHardening] Error al aplicar patch de update_account_settings"
            )

    def _patch_update_account_settings(self):
        """
        Reemplaza `openedx.core.djangoapps.user_api.accounts.api.update_account_settings`
        por una version que filtra el payload con `ALLOWED_PROFILE_FIELDS` cuando
        el requesting_user no tiene privilegios de staff/superuser.
        """
        if SecurityHardeningConfig._patched:
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
        SecurityHardeningConfig._patched = True
        logger.info(
            "[SecurityHardening] Patch aplicado a update_account_settings. "
            "Campos permitidos para usuarios no-staff: %s",
            sorted(ALLOWED_PROFILE_FIELDS),
        )
