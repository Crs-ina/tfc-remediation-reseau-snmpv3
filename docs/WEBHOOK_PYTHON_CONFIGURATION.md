# OKAPI Python webhook configuration

This document concerns the **OKAPI receiver only**. Zabbix sender/action setup
is intentionally outside this change.

Set the following values in the untracked `.env` file:

```dotenv
WEBHOOK_TOKEN=<long random shared secret>
WEBHOOK_BIND_HOST=127.0.0.1
WEBHOOK_BIND_PORT=5000
WEBHOOK_ALLOWED_SOURCE_IPS=127.0.0.1,::1
WEBHOOK_MAX_CONTENT_LENGTH=65536
```

The receiver endpoint is `POST /api/v1/incidents/zabbix`; it requires the
`X-Webhook-Token` header, accepts JSON validated against the existing v1.0
schema, rejects non-local sources by default, and remains idempotent through
the Zabbix event identifier. No secret is logged or returned by the endpoint.

For Gunicorn, bind with the same configured address, for example:

```bash
gunicorn --bind 127.0.0.1:5000 "run:app"
```

Do not expose the port publicly. If a reverse proxy is added later, explicitly
document its source address in `WEBHOOK_ALLOWED_SOURCE_IPS` before allowing it.
