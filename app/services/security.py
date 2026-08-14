import hmac


class AuthenticationError(ValueError):
    pass


def verify_webhook_token(received: str | None, expected: str) -> None:
    if not expected:
        raise RuntimeError("WEBHOOK_TOKEN n'est pas configure.")
    if not received or not hmac.compare_digest(received, expected):
        raise AuthenticationError("X-Webhook-Token invalide ou manquant.")

