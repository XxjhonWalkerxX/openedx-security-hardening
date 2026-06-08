"""
AppConfig que aplica los monkey-patches del plugin de hardening:

1. Patch a `update_account_settings` para defensa en profundidad contra
   mass assignment (#3 del dictamen TICDEFENSE).
2. Patch a `AccessTokenView.dispatch` para agregar un rate-limit por
   username en /oauth2/access_token (#1 del dictamen, parte OAuth2).
3. Patch a `_get_profile_image_urls` para mover el cache-buster `v` de
   las URLs de foto de perfil ya firmadas (S3v4) a un fragmento `#v=`,
   que rompia la firma contra MinIO si iba en el query (#5 del dictamen,
   Camino A: bucket privado). El fragmento no se envia al servidor pero
   el cliente lo usa para invalidar su cache al cambiar la foto.

Notas:
- Open edX upstream YA bloquea campos del sistema (is_staff, is_superuser,
  id, username, is_active, date_joined). Este plugin agrega una capa extra
  con un allowlist explicito de campos editables.
- El patch de mass assignment solo aplica a usuarios NO staff/superuser.
  Los admins conservan su capacidad completa de modificar cualquier campo.
- Intentos rechazados se registran en log para evidencia/auditoria.
"""
import logging
import re

from django.apps import AppConfig

logger = logging.getLogger(__name__)


# --- Helpers para el patch #5 (cache-buster v en URLs firmadas) ---------------
#
# edx-platform agrega `&v=<profile_image_uploaded_at>` al final de la URL de la
# foto de perfil DESPUES de que django-storages la firma (SigV4). Con un bucket
# privado (`querystring_auth=True`) ese parametro queda FUERA de la firma: AWS S3
# poda el query no firmado antes de validar, pero MinIO no -> recalcula la firma
# incluyendo `v` -> SignatureDoesNotMatch -> HTTP 403 en todos los clientes.
#
# NO basta con borrar el `v`: el nombre del objeto en Open edX es estable por
# usuario (`<hash>_<size>.jpg`), asi que sin un token que cambie al subir una
# foto nueva, los clientes (la app Android con Coil, sobre todo) mostrarian la
# foto vieja cacheada. Por eso MOVEMOS el `v` del query a un FRAGMENTO (#v=...):
# el fragmento no viaja en la peticion HTTP (MinIO valida la firma sin el extra),
# pero el cliente SI lo ve en la URL y lo usa como cache-buster.
#
# Estas regex quitan el `v` del query preservando el resto byte-a-byte (sin
# re-encodear los `X-Amz-*`, para no invalidar la firma).
_V_PARAM_VALUE_RE = re.compile(r"[?&]v=([^&#]*)")
_V_PARAM_NOT_FIRST = re.compile(r"&v=[^&]*")
_V_PARAM_FIRST_WITH_REST = re.compile(r"\?v=[^&]*&")
_V_PARAM_FIRST_ALONE = re.compile(r"\?v=[^&]*$")


def _relocate_version_to_fragment_if_signed(url):
    """
    En URLs ya firmadas (contienen `X-Amz-Signature`), MUEVE el cache-buster `v`
    del query a un fragmento `#v=...`. MinIO valida la firma sin el parametro
    extra (el fragmento no se envia en la peticion) y el cliente conserva el
    token para invalidar su cache al cambiar la foto. Las URLs no firmadas
    (bucket publico) se devuelven intactas, con su `?v=` original.
    """
    if not isinstance(url, str) or "X-Amz-Signature" not in url:
        return url
    match = _V_PARAM_VALUE_RE.search(url)
    if not match:
        # URL firmada pero sin `v` (p.ej. ya pasada por aqui): nada que mover.
        return url
    version = match.group(1)
    # Quitar el `v` del query, preservando los X-Amz-* byte-a-byte.
    cleaned = _V_PARAM_NOT_FIRST.sub("", url)            # caso real: `...&v=123`
    cleaned = _V_PARAM_FIRST_WITH_REST.sub("?", cleaned)  # defensivo: `?v=123&...`
    cleaned = _V_PARAM_FIRST_ALONE.sub("", cleaned)       # defensivo: `?v=123`
    # Re-adjuntar como fragmento (no transmitido al servidor).
    return f"{cleaned}#v={version}"


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
    _patched_profile_image = False

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
        try:
            self._patch_profile_image_signed_urls()
        except Exception:
            logger.exception(
                "[SecurityHardening] Error al aplicar patch de profile image signed urls"
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

    def _patch_profile_image_signed_urls(self):
        """
        Quita el cache-buster `v` que edx-platform agrega a las URLs de foto de
        perfil DESPUES de firmarlas (SigV4), y que rompia la firma contra MinIO.

        Contexto (#5, Camino A): las fotos de perfil se aislaron en un bucket
        privado MinIO (`openedxprofiles`) con `querystring_auth=True`, asi que la
        API entrega URLs prefirmadas S3v4. Pero `image_helpers._get_profile_image_urls`
        agrega `&v=<profile_image_uploaded_at>` al final de la URL ya firmada. Ese
        parametro queda FUERA de la firma: AWS S3 poda el query no firmado antes
        de validar, pero MinIO no -> recalcula la firma incluyendo `v` ->
        SignatureDoesNotMatch -> HTTP 403 en web y en la app movil. La foto no se
        muestra. Verificado con curl: misma firma y ventana, quitando `&v=` -> 200.

        Este patch envuelve `_get_profile_image_urls` y mueve `v` a un fragmento
        `#v=` SOLO en las URLs ya firmadas (contienen `X-Amz-Signature`). El
        fragmento no se envia al servidor (la firma queda valida) pero el cliente
        lo usa como cache-buster: sin el, como el nombre del objeto es estable por
        usuario, la app mostraria la foto vieja cacheada tras subir una nueva.
        Las URLs no firmadas (bucket publico) conservan su `?v=` original. Se
        parchea el helper interno (no el publico `get_profile_image_urls_for_user`)
        porque este lo invoca via global del modulo, asi el patch surte efecto sin
        importar como se haya importado la funcion publica en los callers.
        """
        if SecurityHardeningConfig._patched_profile_image:
            return

        try:
            from openedx.core.djangoapps.user_api.accounts import image_helpers
        except ImportError:
            logger.warning(
                "[SecurityHardening] No se pudo importar accounts.image_helpers - "
                "patch de profile image NO aplicado"
            )
            return

        original_get_urls = getattr(image_helpers, "_get_profile_image_urls", None)
        if original_get_urls is None:
            logger.warning(
                "[SecurityHardening] _get_profile_image_urls no encontrada en "
                "image_helpers - patch de profile image NO aplicado"
            )
            return

        if getattr(original_get_urls, "_security_hardening_patched", False):
            SecurityHardeningConfig._patched_profile_image = True
            return

        def signed_safe_get_profile_image_urls(*args, **kwargs):
            urls = original_get_urls(*args, **kwargs)
            try:
                if isinstance(urls, dict):
                    return {
                        size: _relocate_version_to_fragment_if_signed(url)
                        for size, url in urls.items()
                    }
            except Exception:
                # Nunca rompemos el flujo si algo del patch falla: devolvemos
                # las URLs originales.
                logger.exception(
                    "[SecurityHardening] Error al reubicar el parametro v de las "
                    "URLs de profile image - fallback a las URLs originales"
                )
            return urls

        signed_safe_get_profile_image_urls._security_hardening_patched = True
        image_helpers._get_profile_image_urls = signed_safe_get_profile_image_urls
        SecurityHardeningConfig._patched_profile_image = True
        logger.info(
            "[SecurityHardening] Patch aplicado a _get_profile_image_urls: el "
            "cache-buster `v` se mueve a un fragmento `#v=` en las URLs "
            "prefirmadas S3v4 (#5)."
        )
