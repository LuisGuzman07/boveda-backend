import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


def send_recovery_email(
    to_email: str,
    reset_token: str,
    expires_in_minutes: int = 15,
) -> bool:
    """Envía el correo de recuperación con plantilla HTML estilizada y enlace seguro.
    
    Retorna True si el correo se despachó exitosamente vía SMTP, o False si está
    en modo simulación o si falló la conexión con el servidor de correo.
    """
    reset_url = f"{settings.FRONTEND_URL.rstrip('/')}/reset-password#token={reset_token}"
    from_email = settings.SMTP_FROM_EMAIL or settings.SMTP_USER

    if not settings.SMTP_ENABLED or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.error("Recovery email delivery is unavailable because SMTP is not configured.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Recuperación de Contraseña — Bóveda Híbrida"
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{from_email}>"
        msg["To"] = to_email

        # Texto plano alternativo
        text_content = (
            f"Hola,\n\n"
            f"Has solicitado restablecer la contraseña de tu cuenta en Bóveda Híbrida.\n"
            f"Para continuar, ingresa al siguiente enlace seguro:\n\n"
            f"{reset_url}\n\n"
            f"Este enlace tiene una vigencia de {expires_in_minutes} minutos.\n\n"
            f"Aviso de Seguridad (Cero Conocimiento): Restablecer tu contraseña no compromete "
            f"ni altera las claves maestras de tus bóvedas cifradas, las cuales se gestionan "
            f"exclusivamente en tu dispositivo local.\n\n"
            f"Si no solicitaste este cambio, puedes ignorar este mensaje."
        )

        # Plantilla HTML con el diseño y colores de Bóveda Híbrida (#0a0e17, #121826, #3b82f6)
        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recuperación de Contraseña</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0a0e17; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f1f5f9;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0a0e17; padding: 40px 15px;">
    <tr>
      <td align="center">
        <!-- Tarjeta Principal -->
        <table role="presentation" width="100%" style="max-width: 520px; background-color: #121826; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
          <!-- Header -->
          <tr>
            <td style="padding: 30px 30px 20px 30px; text-align: center; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
              <div style="font-size: 36px; margin-bottom: 8px;">🛡️</div>
              <h1 style="margin: 0; font-size: 20px; font-weight: 700; color: #f1f5f9; letter-spacing: -0.02em;">
                Bóveda Híbrida
              </h1>
              <p style="margin: 6px 0 0 0; font-size: 13px; color: #94a3b8;">
                Seguridad Criptográfica & Cero Conocimiento
              </p>
            </td>
          </tr>

          <!-- Cuerpo -->
          <tr>
            <td style="padding: 30px;">
              <h2 style="margin: 0 0 14px 0; font-size: 17px; font-weight: 600; color: #f1f5f9;">
                Solicitud de Restablecimiento de Contraseña
              </h2>
              <p style="margin: 0 0 20px 0; font-size: 14px; line-height: 1.55; color: #cbd5e1;">
                Hemos recibido una solicitud para recuperar el acceso a la cuenta asociada al correo <strong style="color: #38bdf8;">{to_email}</strong>.
              </p>

              <!-- Botón CTA -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
                <tr>
                  <td align="center">
                    <a href="{reset_url}" target="_blank" style="display: inline-block; background-color: #3b82f6; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 600; padding: 13px 28px; border-radius: 6px; box-shadow: 0 4px 14px rgba(59, 130, 246, 0.35);">
                      Restablecer mi Contraseña →
                    </a>
                  </td>
                </tr>
              </table>

              <p style="margin: 0 0 20px 0; font-size: 12px; line-height: 1.4; color: #94a3b8; text-align: center;">
                Este enlace tiene una vigencia temporal de <strong>{expires_in_minutes} minutos</strong>.<br>
                Si el botón no funciona, copia y pega esta URL en tu navegador:<br>
                <span style="display: inline-block; margin-top: 6px; font-family: monospace; color: #93c5fd; word-break: break-all; font-size: 11px;">{reset_url}</span>
              </p>

              <!-- Caja de Garantía Cero Conocimiento -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; margin-top: 25px;">
                <tr>
                  <td style="padding: 14px 16px;">
                    <div style="font-size: 12px; font-weight: 600; color: #6ee7b7; margin-bottom: 4px;">
                      🔒 Principio de Cero Conocimiento (Zero-Knowledge)
                    </div>
                    <div style="font-size: 12px; line-height: 1.45; color: #94a3b8;">
                      Cambiar la contraseña de la cuenta te devuelve el acceso sin comprometer tus bóvedas cifradas. Las claves maestras nunca salen de tu dispositivo local.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 20px 30px; background-color: rgba(6, 9, 15, 0.6); border-top: 1px solid rgba(255, 255, 255, 0.05); text-align: center;">
              <p style="margin: 0; font-size: 11px; color: #64748b;">
                Si tú no solicitaste este cambio, puedes ignorar este mensaje con total tranquilidad.<br>
                © 2026 Bóveda Híbrida — Sistema de Archivos Cifrados.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

        msg.attach(MIMEText(text_content, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        # Conectar al servidor SMTP con STARTTLS
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(from_email, [to_email], msg.as_string())
        server.quit()

        logger.info("Recovery email delivered.")
        return True

    except Exception:
        logger.error("Recovery email delivery failed.")
        return False
