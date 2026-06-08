"""
openedx-security-hardening
==========================

Open edX plugin que cierra las vulnerabilidades de backend reportadas
en el dictamen TICDEFENSE Cybersecurity del 04-mayo-2026 (oficio DGTIC
UAF/713/DGTIC/DSIyPR/324/2026) para el aplicativo Cursos @prende.mx.

Vulnerabilidades cubiertas:
  #1 - Weak Lock Out Mechanism
       (a) LoginFailures upstream para login web /login_ajax
       (b) RATELIMIT_RATE global bajado + ratelimit por username en
           /oauth2/access_token via django-ratelimit (que ya esta
           presente en Open edX nativo)
  #3 - Asignacion masiva de parametros (defensa en profundidad)
  #4 - Activacion de cuentas sin necesidad de correo (solo en
       Tutor < 21.0.4 que no incluye el fix upstream ad342ae)
  #5 - Imagenes de perfil accesibles sin autenticacion (Camino A:
       bucket privado MinIO con URLs firmadas). El aislamiento del
       bucket vive en el plugin de Tutor minio_profile_isolation; este
       plugin agrega el patch que quita el cache-buster `v` de las URLs
       firmadas (sin el, MinIO devuelve 403 SignatureDoesNotMatch).

Vulnerabilidades NO cubiertas por este plugin:
  #2 - Bypass SSL Pinning  -> se resuelve en el cliente Android
"""

__version__ = "1.0.6"
