Ce dossier contient la migration initiale Alembic utilisee par Flask-Migrate.

Commandes principales :

```text
flask --app run.py db upgrade
flask --app run.py db migrate -m "description"
flask --app run.py db check
```

Toute migration generee automatiquement doit etre relue avant application.

