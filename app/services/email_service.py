import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage

from app.config import settings


EmailSender = Callable[[str, str], None]


class EmailDeliveryError(Exception):
    pass


def send_registration_otp(recipient: str, otp: str) -> None:
    if not settings.smtp_host or not settings.smtp_from_email:
        raise EmailDeliveryError(
            "SMTP_HOST and SMTP_FROM_EMAIL must be configured"
        )

    if bool(settings.smtp_username) != bool(settings.smtp_password):
        raise EmailDeliveryError(
            "SMTP_USERNAME and SMTP_PASSWORD must be configured together"
        )

    message = EmailMessage()
    message["Subject"] = "Your registration verification code"
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(
        f"Your verification code is {otp}.\n\n"
        f"It expires in {settings.registration_otp_expire_minutes} minutes. "
        "If you did not request this code, you can ignore this email."
    )

    try:
        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=settings.smtp_timeout_seconds
        ) as smtp:
            smtp.ehlo()

            if settings.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()

            if settings.smtp_username and settings.smtp_password:
                smtp.login(settings.smtp_username, settings.smtp_password)

            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("Unable to send verification email") from exc


def get_email_sender() -> EmailSender:
    return send_registration_otp
