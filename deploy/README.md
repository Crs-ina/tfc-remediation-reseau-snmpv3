# Ubuntu deployment

The supported Ubuntu 24.04 amd64 deployment is the Debian package prepared
under `packaging/debian`. The former home-directory service is retired.

```bash
bash packaging/debian/build-deb.sh
bash deploy/install.sh
```

Complete `/etc/okapi/secrets.env`, then start and verify the backend:

```bash
sudo systemctl enable --now okapi
sudo systemctl status okapi
curl --fail http://127.0.0.1:5000/health
okapi
```

The complete procedure is installed as `/usr/share/doc/okapi/INSTALL.md` and
is also available in `packaging/debian/INSTALL.md`.
