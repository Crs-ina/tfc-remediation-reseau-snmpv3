# Procédure d’installation d’OKAPI sur Ubuntu 24.04 LTS

Ce guide décrit l’installation du paquet Debian d’OKAPI sur un serveur neuf ou
existant. Le paquet produit actuellement cible uniquement l’architecture
`amd64`.

## Réponse courte pour un serveur totalement neuf

Oui, l’installation fonctionne même si Python n’est pas encore installé. La
commande suivante demande à `apt` d’installer automatiquement Python et les
autres dépendances système déclarées par le paquet :

```bash
sudo apt install ./okapi_1.0.0_amd64.deb
```

Il ne faut donc installer manuellement ni Python, ni `pip`, ni un environnement
virtuel sur le serveur cible. Le paquet crée lui-même l’environnement virtuel
dans `/opt/okapi/venv` et y installe les dépendances Python embarquées.

Attention : le fichier `.deb` embarque les bibliothèques Python, mais pas
l’interpréteur Python ni les paquets système Ubuntu. Un serveur neuf doit avoir
accès aux dépôts Ubuntu configurés pour que `apt` puisse récupérer `python3`,
`python3-venv`, `sudo`, `adduser` et `tzdata`. Pour une installation totalement
hors ligne, ces paquets et leurs dépendances doivent être placés au préalable
dans un dépôt APT local ou dans le cache de la machine.

## 1. Prérequis du serveur cible

### Système

- Ubuntu Server 24.04 LTS 64 bits ;
- architecture `amd64`/x86-64 ;
- un compte ayant le droit d’utiliser `sudo` ;
- une heure système correcte et synchronisée ;
- suffisamment d’espace pour le paquet, l’environnement Python, les journaux
  système et la base SQLite ;
- accès aux dépôts Ubuntu, sauf si toutes les dépendances APT sont déjà
  disponibles hors ligne.

Vérifier le système avant l’installation :

```bash
lsb_release -ds
dpkg --print-architecture
sudo apt update
```

La deuxième commande doit afficher `amd64`. Le paquet actuel ne doit pas être
installé sur `arm64`.

### Réseau et laboratoire

- une route du serveur OKAPI vers les équipements administrés ;
- UDP/161 autorisé du serveur OKAPI vers ces équipements ;
- un utilisateur SNMPv3 `authPriv` existant, avec SHA-256 et AES-256 ;
- les informations Zabbix nécessaires au webhook ;
- le VLAN de quarantaine déjà créé et réellement isolé ;
- une whitelist complète des uplinks, trunks, ports de management, points
  d’accès critiques, routeurs, pare-feu, passerelles et serveurs ;
- pour toute écriture réelle, le laboratoire validé Arista vEOS 4.29.2F dans
  EVE-NG et toutes les validations prévues par la politique du projet.

OKAPI ne crée ni VLAN ni utilisateur SNMP. Le paquet crée uniquement le compte
de service Linux système `okapi`.

Le service HTTP écoute volontairement sur `127.0.0.1:5000`. Si Zabbix se trouve
sur une autre machine, placer un reverse proxy HTTPS devant OKAPI et limiter
l’accès à l’adresse de Zabbix. Ne pas exposer directement le serveur Flask sur
Internet.

## 2. Obtenir le paquet

Le fichier attendu est :

```text
okapi_1.0.0_amd64.deb
```

Il peut être téléchargé depuis l’emplacement de livraison GitHub ou copié
depuis la machine de construction. Exemple depuis le poste qui détient le
paquet :

```bash
scp okapi_1.0.0_amd64.deb administrateur@serveur:/tmp/
```

## 3. Installer sur un serveur neuf ou existant

Sur le serveur cible :

```bash
cd /tmp
sudo apt update
sudo apt install ./okapi_1.0.0_amd64.deb
```

`apt` résout les dépendances système, y compris Python si nécessaire. Le script
d’installation crée ensuite :

- le compte et le groupe système `okapi` ;
- `/opt/okapi/venv` avec les bibliothèques Python embarquées ;
- `/etc/okapi/secrets.env`, vide et protégé par les droits `0640` ;
- `/var/lib/okapi` et la base SQLite migrée ;
- le service systemd `okapi.service` ;
- la commande `/usr/bin/okapi`.

Vérifier le paquet et le Python réellement installés :

```bash
dpkg-query -W -f='${Status} ${Version}\n' okapi
/opt/okapi/venv/bin/python --version
```

## 4. Configurer OKAPI avant le premier démarrage

### Secrets

Consulter le modèle puis ouvrir le fichier réel :

```bash
cat /etc/okapi/secrets.env.example
sudoedit /etc/okapi/secrets.env
```

Renseigner les quatre variables sans ajouter les valeurs dans Git :

```text
WEBHOOK_TOKEN=
SNMP_USERNAME=
SNMP_AUTH_KEY=
SNMP_PRIV_KEY=
```

### Paramètres non sensibles

```bash
sudoedit /etc/okapi/okapi.env
sudoedit /etc/okapi/remediation.json
sudoedit /etc/okapi/whitelist.json
sudoedit /etc/okapi/automation_schedule.json
sudoedit /etc/okapi/snmp_capabilities.json
```

Contrôler au minimum :

- `WEBHOOK_ALLOWED_SOURCE_IPS` ;
- `SNMP_HOST` et `SNMP_PORT` ;
- `SNMP_AUTH_PROTOCOL=SHA256` ;
- `SNMP_PRIV_PROTOCOL=AES256` ;
- `quarantine_vlan_id` dans `remediation.json` ;
- l’exhaustivité de la whitelist ;
- l’existence et l’isolement réel du VLAN de quarantaine.

Conserver lors de la première installation :

```text
SNMP_WRITE_ENABLED=false
DRY_RUN=false
QUARANTINE_VLAN_EXISTS=false
QUARANTINE_VLAN_ISOLATED=false
```

Ne passer les confirmations VLAN et `SNMP_WRITE_ENABLED` à `true` qu’après les
vérifications du laboratoire. Le seul SET actuellement validé est
`Q-BRIDGE-MIB::dot1qPvid` sur Arista vEOS 4.29.2F dans EVE-NG. Les autres SET
restent bloqués.

## 5. Démarrer et vérifier le service

```bash
sudo systemctl enable --now okapi.service
sudo systemctl --no-pager --full status okapi.service
curl -fsS http://127.0.0.1:5000/health
```

En cas d’échec :

```bash
sudo journalctl -u okapi.service -n 100 --no-pager
sudo systemctl restart okapi.service
```

Le point `/health` doit notamment permettre de contrôler l’état du backend,
de la base, de la configuration MIB et de SNMP.

## 6. Donner l’accès CLI à un administrateur

Ajouter chaque administrateur Linux autorisé au groupe `okapi` :

```bash
sudo usermod -aG okapi NOM_DU_COMPTE
```

L’administrateur doit fermer complètement sa session SSH puis en ouvrir une
nouvelle. Il peut ensuite lancer :

```bash
okapi
```

OKAPI utilise l’UID Linux réel du processus pour la traçabilité. Les actions
critiques demandent une réauthentification `sudo`/PAM et les décisions sont
journalisées sous ce compte.

## 7. Réinstaller sur un autre serveur

Une installation sans ancienne base crée un OKAPI propre, avec un historique
vide. Pour conserver les incidents et l’historique, sauvegarder avant de
supprimer l’ancien serveur :

- `/var/lib/okapi/remediation.db` ;
- `/etc/okapi/`, en protégeant particulièrement `secrets.env` ;
- tout certificat et toute configuration du reverse proxy, s’ils existent.

Sur le nouveau serveur :

1. installer d’abord le même paquet `.deb` ou une version plus récente ;
2. arrêter le service ;
3. restaurer la configuration et la base ;
4. remettre les propriétaires et permissions ;
5. exécuter les migrations ;
6. redémarrer et vérifier le service.

Exemple après avoir copié la base sauvegardée dans `/tmp` :

```bash
sudo systemctl stop okapi.service
sudo cp /tmp/remediation.db /var/lib/okapi/remediation.db
sudo chown okapi:okapi /var/lib/okapi/remediation.db
sudo chmod 0660 /var/lib/okapi/remediation.db
sudo -u okapi /opt/okapi/bin/migrate-database
sudo systemctl start okapi.service
curl -fsS http://127.0.0.1:5000/health
```

Restaurer les fichiers de `/etc/okapi` uniquement depuis une sauvegarde sûre,
puis vérifier que `/etc/okapi/secrets.env` appartient à `root:okapi` et conserve
le mode `0640`.

## 8. Mettre à jour une installation

Copier le nouveau paquet sur le serveur puis lancer :

```bash
sudo apt install ./okapi_NOUVELLE_VERSION_amd64.deb
```

Les conffiles Debian modifiés localement et `/var/lib/okapi` sont conservés.
Lire attentivement toute question d’APT concernant une nouvelle version d’un
fichier de configuration, puis vérifier le service et `/health`.

## 9. Désinstaller

```bash
sudo apt remove okapi
```

Cette commande conserve l’état de `/var/lib/okapi`. Même avec
`sudo apt purge okapi`, la base SQLite et le fichier local `secrets.env` sont
volontairement conservés afin d’éviter une perte accidentelle. Les sauvegarder,
puis les supprimer manuellement uniquement si leur destruction est réellement
souhaitée.

## 10. Emplacements utiles

- code et environnement Python : `/opt/okapi` ;
- configuration : `/etc/okapi` ;
- secrets : `/etc/okapi/secrets.env` ;
- base SQLite : `/var/lib/okapi/remediation.db` ;
- commande CLI : `/usr/bin/okapi` ;
- unité systemd : `/lib/systemd/system/okapi.service` ;
- guide installé : `/usr/share/doc/okapi/INSTALL.md`.

## 11. Construire le paquet depuis les sources

Cette section concerne seulement la machine de construction, pas le serveur
cible. Sur Ubuntu 24.04 `amd64` avec accès à Internet :

```bash
sudo apt update
sudo apt install git ca-certificates python3 python3-pip dpkg-dev
git clone URL_DU_DEPOT_OKAPI
cd tfc-remediation-reseau-snmpv3
git checkout feat/snmpv3-arista-remediation
bash packaging/debian/build-deb.sh
```

Le résultat est `dist/okapi_1.0.0_amd64.deb`. La construction télécharge les
roues Python puis les embarque dans le paquet. L’installation sur le serveur
cible ne lance ensuite aucun téléchargement `pip`.
