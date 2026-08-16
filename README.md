# OKAPI — SNMPv3 network remediation

**OKAPI** (Orchestrateur de Kimwenza Automatisé pour la Protection et
l’Automatisation) is a CLI-only administrator interface for the existing
SNMPv3 remediation engine. It keeps the Flask/SQLite architecture, local MIB
package, calendar policy and guarded Arista laboratory write path intact.

## Administrator interface

Install the package and run the interactive interface directly:

```bash
python -m pip install -e .
okapi
```

It displays the ASCII OKAPI banner, offers protected account creation and
login, then retains the authenticated administrator only for that CLI process.
The normal menu uses numbered incident selections rather than internal IDs.
Approve/Refuse decisions and requested rollbacks are linked to the logged-in
administrator in `audit_logs`. Passwords are stored only as Werkzeug password
hashes.

Advanced maintenance commands remain available separately. Incident and audit
searches support `--from "YYYY-MM-DD HH:MM"` and `--to "YYYY-MM-DD HH:MM"`,
interpreted in `Africa/Kinshasa`.

Prototype Flask de traitement d’incidents réseau avec découverte SNMPv3 en
lecture seule et remédiation VLAN strictement contrôlée.

## Périmètre

Le projet traite exactement sept routes fonctionnelles :

- `network_loop` → `PB-LOOP-001` ;
- `ip_address_conflict` → `PB-IP-CONFLICT-001` ;
- `physical_disconnection` → `PB-PHYSICAL-DOWN-001` ;
- `interface_admin_down` → `PB-INTERFACE-DOWN-001` ;
- `port_flapping` → `PB-PORT-FLAPPING-001` ;
- `vlan_policy_violation` → `PB-VLAN-POLICY-001` ;
- tout autre type → `PB-UNKNOWN-001`.

Les chemins d'écriture implémentés utilisent :

```text
Q-BRIDGE-MIB::dot1qPvid.<bridge_port>
IF-MIB::ifAdminStatus.<ifIndex>
```

Seul `dot1qPvid` est marqué `LAB_VALIDATED`, uniquement pour **Arista vEOS 4.29.2F**
dans EVE-NG, avec SNMPv3 `authPriv`, SHA-256 et AES-256. UniFi reste
`TO_BE_VALIDATED` et toute écriture y est bloquée. Les SET `ifAdminStatus`
down/up sont implémentés derrière le capability gate mais restent également
`TO_BE_VALIDATED` : ils ne sont donc pas envoyés tant qu'un essai réel ne les
qualifie pas.

## Politique de sécurité

- La découverte utilise uniquement le client `SnmpReadClient`.
- Aucune communauté SNMPv1/SNMPv2c n’est acceptée.
- De 08:00 à 17:00 (`Africa/Kinshasa`), toute action disruptive attend une
  décision humaine. Hors plage, seuls `SHUTDOWN_PORT` et `QUARANTINE_VLAN`
  peuvent être préautorisés par le calendrier ; `REACTIVATE_PORT` reste
  toujours supervisé et une attente existante ne se convertit jamais.
- `SNMP_WRITE_ENABLED=false` par défaut.
- Le modèle, l’objet et les protocoles doivent correspondre exactement au
  profil `LAB_VALIDATED` de `config/snmp_capabilities.json`.
- La whitelist est vérifiée avant l’approbation puis de nouveau juste avant
  le SET.
- Le PVID est relu après l’approbation et doit encore correspondre au snapshot
  pré-action.
- Le SET vers le VLAN 18 n’est déclaré réussi qu’après un GET égal à 18.
- Deux tentatives maximum sont permises, un cooldown de 60 secondes et un
  verrou inter-processus sérialisent les actions sur un même port.
- `DRY_RUN=true` exécute le parcours sans aucun SNMP SET.
- Le rollback n’est jamais automatique : un administrateur doit le demander,
  puis un SET remet le `previous_pvid` et un GET le vérifie.
- Les clés d’authentification et de confidentialité sont masquées dans les
  représentations de configuration et expurgées des détails d’audit.

## Paquet MIB préinstallé

Les définitions compilées sont fournies par `pysnmp-mibs==0.1.6`. Au
démarrage, l’application vérifie que ce paquet existe, charge les modules
obligatoires et résout les noms symboliques dans un cache local :

- `SNMPv2-MIB` ;
- `IF-MIB` ;
- `BRIDGE-MIB` ;
- `Q-BRIDGE-MIB` ;
- `IP-MIB` reste optionnelle pour la découverte.

Il n’y a aucun téléchargement Internet dans le chemin d’un incident. Si le
paquet ou un répertoire MIB configuré manque, `/health` expose
`mib_ready=false` et les préparations/écritures sont bloquées explicitement.
Le code métier ne maintient pas de registre d’OID numériques : il utilise des
références comme `Q-BRIDGE-MIB::dot1qPvid`, résolues localement au démarrage.

## Identification et chemin rapide « port connu »

La première identification suit cette chaîne en lecture seule :

```text
MAC normalisée
  → WALK Q-BRIDGE-MIB::dot1qTpFdbPort
  → bridge_port
  → BRIDGE-MIB::dot1dBasePortIfIndex
  → IF-MIB::ifDescr
  → Q-BRIDGE-MIB::dot1qPvid
```

Le résultat est persisté sans modifier le MLD :

- `SwitchPort.port_index` contient le `bridge_port` SNMP ;
- `SwitchPort.port_name` contient `ifDescr` ;
- `SwitchPort.vlan_id` contient le PVID observé ;
- `NetworkHost` mémorise la MAC et son port ;
- `Remediation.previous_vlan_id` sauvegarde le PVID pré-action.

Lors d’un incident ultérieur concernant la même MAC, un GET ciblé de
`dot1qTpFdbPort.<vlan_connu>.<mac>` revalide d’abord le port mémorisé. S’il
correspond, le WALK complet de la FDB est évité. Si le cache est obsolète ou
illisible, le système revient automatiquement au WALK complet. Il ne suppose
jamais que la cible se trouve forcément dans le VLAN 10.

La préparation complète est effectuée avant l’attente de l’administrateur.
Après approbation, le chemin critique ne fait plus que : relecture du PVID,
SET vers 18, puis GET de vérification.

## Installation

Python 3.10 ou plus récent :

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Remplacer les valeurs `CHANGE_ME` dans `.env`. Le profil attendu est :

```text
SNMP_AUTH_PROTOCOL=SHA256
SNMP_PRIV_PROTOCOL=AES256
SNMP_MIB_PACKAGE=pysnmp_mibs
SNMP_WRITE_ENABLED=false
```

Pour un test d’écriture dans le laboratoire validé seulement, confirmer aussi
que le VLAN 18 existe et est isolé, puis activer explicitement :

```text
QUARANTINE_VLAN_EXISTS=true
QUARANTINE_VLAN_ISOLATED=true
SNMP_WRITE_ENABLED=true
```

## Base et démarrage

```powershell
flask --app run.py db upgrade
flask --app run.py run --host 127.0.0.1 --port 5000
```

Pour une initialisation locale rapide seulement :

```powershell
flask --app run.py init-db
```

Points d’entrée :

- `GET /health` ;
- `POST /api/v1/incidents/zabbix` avec l’en-tête `X-Webhook-Token`.

## Interface et maintenance

L'interface quotidienne est `okapi`. Elle couvre les incidents, décisions,
historique, audit, rollback, état du système et gestion minimale des comptes,
sans afficher les identifiants internes. Les commandes Flask suivantes restent
des outils avancés de maintenance.

La commande `prepare-snmp` effectue l’identification, les préconditions et le
snapshot avant l’approbation :

```powershell
flask --app run.py snmp discover --host 192.0.2.10

flask --app run.py remediation prepare-snmp INCIDENT_ID --switch-id SWITCH_ID --target-mac 00:50:79:66:68:03 --target-ip 192.0.2.50
flask --app run.py remediation approve INCIDENT_ID --administrator admin-ulc-icam
flask --app run.py remediation execute INCIDENT_ID
```

Refus et rollback explicites :

```powershell
flask --app run.py remediation refuse INCIDENT_ID --administrator admin-ulc-icam
flask --app run.py remediation rollback INCIDENT_ID --administrator admin-ulc-icam
```

Une remédiation préparée manuellement avec l’ancienne commande `evaluate`,
sans audit `SNMP_TARGET_PREPARED`, ne peut pas contourner le contrôle :
`execute` la bloque.

## Mesures et audit

Les audits enregistrent séparément : identification, précontrôles,
révalidation, SET, vérification et total automatisé. Le total exclut toujours
le temps passé à attendre la décision humaine. Les résultats indiquent aussi
si le cache du port connu a évité le WALK.

## Tests

```powershell
pytest -q
```

Les tests unitaires emploient des doubles SNMP et n’écrivent sur aucun
équipement. Les tests EVE-NG sont séparés et ignorés par défaut :

```powershell
$env:RUN_EVE_NG_SNMP_TESTS="1"
$env:EVE_NG_BRIDGE_PORT="2"
pytest -q -m integration
```

La séquence réelle 10 → 18 → 10 exige en plus les trois confirmations
explicites `RUN_EVE_NG_SNMP_WRITE_TESTS=1`, `EVE_NG_ADMIN_APPROVED=YES` et
`EVE_NG_ROLLBACK_EXPLICIT=YES`.
