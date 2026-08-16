# Ubuntu deployment

The checked-in unit runs one Gunicorn worker on `127.0.0.1:5000`. Copy
`.env.example` to the ignored `.env`, fill local secrets, install the package
in `.venv`, then run `sudo bash deploy/install.sh` from the documented
`/home/exauceeadm/tfc-remediation-reseau-snmpv3` deployment.

Verify with:

```bash
systemctl is-enabled okapi-backend
systemctl is-active okapi-backend
ss -ltnp | grep 127.0.0.1:5000
curl --fail http://127.0.0.1:5000/health
okapi
```

Application rollback is a normal Git operation: switch to the preserved
checkpoint/commit, reinstall with `.venv/bin/pip install -e .`, run migrations
appropriate to that revision, and restart the service. Never delete
`data/remediation.db`; take a SQLite backup before changing revision.
