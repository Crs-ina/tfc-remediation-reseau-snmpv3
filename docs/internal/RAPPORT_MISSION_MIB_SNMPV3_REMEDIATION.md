# Rapport de mission — MIB préinstallées et remédiation SNMPv3

Date : 14 août 2026

Projet : `tfc-remediation-reseau-snmpv3`

Périmètre validé : Arista vEOS 4.29.2F dans EVE-NG

## 1. Résultat

La mission est implémentée avec le profil suivant :

```text
SNMP                    v3 authPriv uniquement
Authentification        SHA-256
Confidentialité         AES-256
Objet inscriptible      Q-BRIDGE-MIB::dot1qPvid
Plateforme inscriptible Arista vEOS 4.29.2F, laboratoire EVE-NG uniquement
UniFi                   TO_BE_VALIDATED, aucun SET
```

Les MIB sont fournies par un paquet préinstallé, chargées et résolues au
démarrage. La découverte reste en lecture seule. Toute écriture disruptive
requiert une cible certaine, les préconditions du VLAN 18, une whitelist
négative, une capacité `LAB_VALIDATED`, le snapshot du PVID et une approbation
humaine explicite. Le succès d’un SET doit être confirmé par un GET.

Un chemin rapide a également été ajouté pour les cibles déjà connues. Il
revalide la MAC sur le VLAN et le `bridge_port` mémorisés par un GET ciblé. Si
la correspondance est toujours exacte, il évite le WALK complet de la FDB. Si
elle est périmée, le système revient à la découverte complète sans écrire.

## 2. Inspection et réutilisation de l’existant

Les responsabilités déjà présentes ont été conservées :

- création Flask et extensions dans `app/__init__.py` et `app/extensions.py` ;
- configuration centralisée dans `config.py` et `.env.example` ;
- client et découverte SNMP dans `app/snmp/client.py` et
  `app/snmp/discovery.py` ;
- règles, approbation, refus et workflow dans `app/services/rules.py` et
  `app/services/remediation.py` ;
- whitelist externe dans `app/services/whitelist.py` et
  `config/whitelist.json` ;
- audit expurgé dans `app/services/audit.py` ;
- commandes d’administration dans `app/cli/` ;
- modèles SQLAlchemy et MLD existants dans `app/models/` ;
- quatre playbooks existants dans `playbooks/` ;
- tests existants dans `tests/`.

Les fichiers ou ensembles existants inspectés pendant la mission sont :

- le cahier de mission
  `C:\Users\ngalu\Downloads\MISSION_CODEX_MIB_SNMP_REMEDIATION.md` ;
- `README.md`, `.env.example`, `.gitignore`, `requirements-dev.txt`, `config.py` et
  `run.py` ;
- `app/__init__.py`, `app/extensions.py` et `app/routes/health.py` ;
- `app/snmp/client.py`, `app/snmp/discovery.py`,
  `app/snmp/mib_catalog.py` et `app/snmp/__init__.py` ;
- `app/services/audit.py`, `calendar_policy.py`, `identification.py`,
  `remediation.py`, `rules.py`, `security.py` et `whitelist.py` ;
- les commandes de `app/cli/` ;
- les six modèles de `app/models/` et les migrations de `migrations/versions/` ;
- `config/automation_schedule.json`, `config/whitelist.json` et les quatre
  playbooks JSON ;
- les schémas, exemples et tests existants liés au webhook, au MLD, aux règles,
  à la remédiation et à la découverte SNMP ;
- `RAPPORT_ALIGNEMENT_STRICT_MLD.txt`, utilisé pour préserver l’alignement MLD.

Aucune nouvelle table, aucune colonne et aucune migration n’ont été ajoutées.
Les six modèles du MLD restent inchangés.

À la demande explicite finale de l’utilisateur, `AGENTS.md` a été mis à jour
pour distinguer la découverte toujours read-only de l’unique écriture
`Q-BRIDGE-MIB::dot1qPvid` LAB_VALIDATED sur Arista vEOS 4.29.2F dans EVE-NG.
Les conditions de whitelist, approbation humaine, feature flag et séparation
UniFi `TO_BE_VALIDATED` y sont maintenant explicites.

## 3. Architecture retenue

### 3.1 Démarrage

```text
create_app
  → vérifier le paquet pysnmp_mibs
  → ajouter ZipMibSource et, si configuré, DirMibSource
  → charger SNMPv2-MIB, IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB
  → résoudre les objets symboliques de warm-up
  → conserver MibBuilder, MibViewController et OID résolus en mémoire
  → publier mib_ready dans /health
```

Un échec de paquet, de chemin local ou de résolution place le registre MIB en
état non prêt. L’application peut exposer son diagnostic, mais la préparation
et toute écriture sont alors bloquées.

### 3.2 Préparation avant approbation

```text
incident IP conflict
  → profil Arista/SHA256/AES256 LAB_VALIDATED
  → normalisation MAC
  → cache connu revalidé, sinon WALK dot1qTpFdbPort
  → bridge_port
  → GET dot1dBasePortIfIndex.<bridge_port>
  → GET ifDescr.<ifIndex>
  → GET dot1qPvid.<bridge_port>
  → whitelist et préconditions VLAN 18
  → persistance de la cible et du previous_pvid
  → audit SNMP_TARGET_PREPARED avec chronométrage
  → WAITING_ADMIN_APPROVAL
```

La MAC accepte les formats avec deux-points, tirets, notation Cisco avec
points ou douze chiffres hexadécimaux. Une MAC absente est recherchée deux
fois puis escaladée. Plusieurs emplacements incompatibles provoquent une
ambiguïté et aucune remédiation n’est autorisée.

### 3.3 Exécution après approbation

```text
ADMIN_APPROVED
  → SNMP_WRITE_ENABLED
  → preuve SNMP_TARGET_PREPARED
  → MIB prêtes
  → VLAN 18 existant et isolé
  → nouvelle vérification whitelist
  → capacité exacte LAB_VALIDATED
  → GET PVID == previous_pvid
  → SET dot1qPvid.<bridge_port> = 18
  → GET dot1qPvid.<bridge_port> == 18
  → succès et audit
```

L’ancienne commande générale `evaluate` ne peut pas servir de contournement :
en l’absence de l’audit de préparation SNMP, `execute` refuse tout SET.

### 3.4 Rollback

Le rollback exige un identifiant d’administrateur non vide et une remédiation
réussie. Il réutilise `previous_pvid`, jamais une valeur 10 codée en dur :

```text
demande explicite
  → vérification MIB, whitelist et capacité
  → SET dot1qPvid.<bridge_port> = previous_pvid
  → GET == previous_pvid
  → audit ROLLED_BACK
```

## 4. Chargement des MIB et ObjectIdentity

La dépendance ajoutée est :

```text
pysnmp-mibs==0.1.6
```

`MibRegistry` utilise exclusivement des sources locales :

- `ZipMibSource("pysnmp_mibs")` pour le paquet préinstallé ;
- `DirMibSource(SNMP_MIB_PATH)` pour un éventuel répertoire administré ;
- les MIB de base locales de PySNMP.

Il n’existe aucun téléchargement, appel HTTP, `snmptranslate` ou compilation
à la volée dans le chemin d’un incident.

Le catalogue métier contient des paires symboliques, par exemple :

```text
Q-BRIDGE-MIB::dot1qTpFdbPort
BRIDGE-MIB::dot1dBasePortIfIndex
IF-MIB::ifDescr
Q-BRIDGE-MIB::dot1qPvid
```

Au warm-up,
`ObjectIdentity(module, symbol).resolve_with_mib(MibViewController)` résout
chaque base. Le résultat est conservé en mémoire. Au moment d’une requête, les
index dynamiques découverts sont ajoutés à cette base et PySNMP construit
l’instance `ObjectIdentity` utilisée par GET, WALK ou SET. Aucun numéro d’OID
n’est maintenu comme source métier dans le code.

## 5. Persistance du port connu sans changer le MLD

Les champs existants sont réutilisés ainsi :

| Champ existant | Valeur SNMP persistée |
|---|---|
| `SwitchPort.port_index` | `bridge_port` |
| `SwitchPort.port_name` | `IF-MIB::ifDescr` |
| `SwitchPort.vlan_id` | PVID courant |
| `NetworkHost.mac_address` | MAC normalisée |
| `NetworkHost.switch_id/port_index` | dernier emplacement confirmé |
| `Remediation.previous_vlan_id` | `previous_pvid` pré-action |

Ce cache accélère deux moments :

1. un futur incident pour la même MAC peut remplacer le WALK FDB complet par
   un GET ciblé, tout en revalidant la donnée ;
2. pendant l’attente de l’administrateur, l’identification, les précontrôles
   et le snapshot sont déjà terminés ; après acceptation il reste un GET de
   cohérence, le SET et le GET de confirmation.

## 6. Capacités et séparation des plateformes

`config/snmp_capabilities.json` contient des capacités par modèle exact.

Pour `Arista vEOS 4.29.2F` :

- lectures IF-MIB, BRIDGE-MIB et Q-BRIDGE-MIB : `SUPPORTED` ;
- écriture `Q-BRIDGE-MIB::dot1qPvid` : `LAB_VALIDATED` ;
- sécurité obligatoire : SHA256/AES256.

Pour `UniFi` :

- `Q-BRIDGE-MIB::dot1qPvid` reste `TO_BE_VALIDATED` en lecture et écriture ;
- le service ne tente aucun SET.

Un modèle absent, inconnu ou différent, un autre objet ou d’autres protocoles
font échouer la garde de capacité avant tout accès d’écriture.

## 7. Chronométrage

Les audits séparent :

- `t_identification_seconds` ;
- `t_prechecks_seconds`, incluant la revalidation post-approbation ;
- `t_snmp_set_seconds` ;
- `t_verification_seconds` ;
- `t_total_automated_seconds`.

Le total est la somme des traitements avant et après approbation. Il ne
soustrait pas des horodatages muraux : l’attente humaine n’y entre donc jamais.
Le warm-up MIB n’y entre pas non plus.

Le test unitaire injecte volontairement de grands écarts entre segments et
vérifie que le total reste la somme des durées actives. L’objectif inférieur à
10 secondes n’est pas déclaré atteint sans mesures réelles EVE-NG.

## 8. Fichiers modifiés

- `.env.example` : SHA256/AES256, paquet/chemin MIB, capacités et feature flag ;
- `.gitignore` : exclusions Python/tests et ajout de `*.pdf`, en conservant les
  règles historiques du dépôt ;
- `AGENTS.md` : état actuel de la découverte et de la remédiation SNMPv3 ;
- `README.md` : installation, sécurité, cache, workflow et intégration ;
- `config.py` : configuration MIB et capacités ;
- `requirements-dev.txt` : paquet MIB précompilé ;
- `app/__init__.py` : warm-up du registre MIB ;
- `app/routes/health.py` : état de préparation MIB ;
- `app/cli/snmp.py` : injection du registre MIB dans la découverte ;
- `app/cli/remediation.py` : préparation, exécution et rollback ;
- `app/snmp/client.py` : client SNMPv3 GET/WALK et client SET PVID gardé ;
- `app/snmp/discovery.py` : références symboliques ;
- `app/snmp/mib_catalog.py` : catalogue de noms MIB sans OID métier ;
- `app/services/rules.py` : approbation humaine pour toute action disruptive ;
- `app/services/remediation.py` : snapshot et persistance de la cible ;
- `tests/conftest.py`, `tests/test_rules.py`,
  `tests/test_remediation_service.py`, `tests/test_snmp_discovery.py` : adaptation
  du socle de tests.

## 9. Fichiers ajoutés

- `config/snmp_capabilities.json` ;
- `app/snmp/mib_registry.py` ;
- `app/snmp/capabilities.py` ;
- `app/snmp/target_resolver.py` ;
- `app/services/snmp_preparation.py` ;
- `app/services/snmp_execution.py` ;
- `pytest.ini` ;
- `tests/test_audit_security.py` ;
- `tests/test_mib_registry.py` ;
- `tests/test_snmp_target_resolver.py` ;
- `tests/test_snmp_preparation.py` ;
- `tests/test_snmp_execution.py` ;
- `tests/integration/test_eve_ng_snmp.py` et son `__init__.py` ;
- le présent rapport.

## 10. Tests ajoutés et correspondance avec la mission

Les tests couvrent notamment :

1. les quatre formes de normalisation MAC ;
2. le parsing de l’index Q-BRIDGE ;
3. MAC vers `bridge_port` ;
4. `bridge_port` vers `ifIndex` ;
5. `ifIndex` vers interface et lecture du PVID ;
6. paquet/répertoire MIB absent ;
7. service MIB non prêt avant préparation et exécution ;
8. MAC ambiguë sans écriture ;
9. whitelist avant et après approbation ;
10. absence d’approbation sans écriture ;
11. feature flag désactivé sans écriture ;
12. SET accepté mais GET différent de 18 ;
13. SET et GET égaux à 18 ;
14. rollback sans demande interdit ;
15. rollback explicite vers `previous_pvid` ;
16. chronométrage excluant l’attente humaine ;
17. cache du port connu sans WALK complet ;
18. refus de tout autre objet SET ;
19. masquage des secrets ;
20. blocage du profil UniFi non validé ;
21. blocage d’un contournement sans préparation SNMP.

Les doubles unitaires n’ouvrent aucune connexion vers un switch.

## 11. Tests d’intégration EVE-NG

Les tests d’intégration sont marqués `integration` et ignorés par défaut. Ils
prévoient :

- warm-up local des MIB ;
- GET symbolique de `sysName` et du PVID ;
- résolution complète de la MAC de référence par WALK et mappings ;
- plusieurs mesures de durée d’identification ;
- séquence explicite 10 → 18 → 10 avec GET après chaque SET.

La partie écriture exige trois confirmations d’environnement distinctes :

```text
RUN_EVE_NG_SNMP_WRITE_TESTS=1
EVE_NG_ADMIN_APPROVED=YES
EVE_NG_ROLLBACK_EXPLICIT=YES
```

EVE-NG n’était pas configuré dans l’environnement de cette exécution. Les
tests réels et leurs temps n’ont donc pas été exécutés et aucune affirmation
de performance inférieure à 10 secondes n’est faite.

## 12. Résultat pytest

Commande utilisée dans l’environnement de travail :

```powershell
C:\X3\TFC\tfc-remediation-reseau-snmpv3\.venv\Scripts\python.exe -m pytest -q
```

Résultat final :

```text
57 passed, 3 skipped in 13.10s
```

Les trois tests ignorés sont uniquement les tests d’intégration EVE-NG opt-in.
Le processus a terminé avec le code 0. L’interpréteur Python 3.14 local a
affiché après pytest un avertissement d’environnement
`Could not find platform independent libraries <prefix>` sans effet sur la
collecte, l’exécution ou le résultat des tests.

## 13. Points restant TO_BE_VALIDATED

- toute écriture sur un équipement UniFi réel ;
- toute plateforme ou version autre que `Arista vEOS 4.29.2F` ;
- les mesures répétées EVE-NG de `T_total_automated` et l’objectif `< 10 s` ;
- la vérification externe du trafic après quarantaine et après rollback
  (échec/rétablissement du ping) dans la topologie réelle ;
- les index et noms d’interfaces propres à une autre topologie : ils restent
  volontairement dynamiques et ne sont pas généralisés depuis Ethernet2.

## 14. Références techniques

- PySNMP 7.1, API et objets MIB :
  <https://docs.lextudio.com/pysnmp/v7.1/docs/api-reference>
- PySNMP HLAPI, SNMPv3 et opérations GET/SET :
  <https://docs.lextudio.com/pysnmp/v7.1/docs/pysnmp-hlapi-tutorial>
- Navigation et chargement d’un arbre MIB :
  <https://docs.lextudio.com/pysnmp/v7.1/examples/smi/manager/browsing-mib-tree>
