# AGENTS.md — Projet TFC ULC-ICAM

## 1. Contexte du projet

Ce dépôt contient l’implémentation du TFC :

**Automatisation de la remédiation de base du réseau après détection d’incidents de sécurité à l’aide de Python et SNMPv3 : cas du réseau académique de l’ULC-ICAM.**

L’objectif est de construire un prototype de remédiation réseau prudent, traçable et testable en laboratoire.

## 2. Architecture de référence

La chaîne fonctionnelle cible est :

```text
Zabbix
  -> Webhook HTTP
  -> API Python / FastAPI
  -> validation du JSON Schema
  -> qualification de l’incident
  -> sélection du playbook
  -> vérification de la cible via SNMPv3
  -> contrôles de sécurité
  -> validation humaine si une action disruptive est prévue
  -> remédiation SNMPv3
  -> vérification
  -> journalisation SQLite
```

Zabbix détecte et transmet l’événement.  
Le système Python qualifie, vérifie, route, applique les garde-fous et exécute éventuellement l’action autorisée.

## 3. Incidents autorisés dans le prototype

Ne pas ajouter de nouveaux types d’incidents sans demande explicite.

Les seuls types reconnus sont :

- `network_loop`
- `ip_address_conflict`
- `physical_disconnection`
- tout autre type ou type absent -> playbook `unknown`

Correspondance :

```text
network_loop
  -> PB-LOOP-001

ip_address_conflict
  -> PB-IP-CONFLICT-001

physical_disconnection
  -> PB-PHYSICAL-DOWN-001

autre / absent
  -> PB-UNKNOWN-001
```

## 4. Playbooks

Les fichiers JSON des playbooks sont des sources de règles métier pour le moteur Python.

Règles globales :

- maximum 2 tentatives d’identification d’une cible ;
- maximum 2 tentatives de remédiation ;
- toute action réseau disruptive exige une validation humaine explicite ;
- la validation humaine est asynchrone ;
- il n’existe pas de timeout qui autorise automatiquement une action ;
- sans réponse de l’administrateur, conserver l’état `WAITING_ADMIN_APPROVAL` ;
- le rollback n’est jamais automatique ;
- un rollback est exécuté uniquement sur demande explicite de l’administrateur ;
- toujours sauvegarder l’état pré-action avant une modification ;
- toujours vérifier l’état réel après une action SNMP.

## 5. RACI

- **R — Responsible** : système Python de remédiation
- **A — Accountable** : administrateur réseau ULC-ICAM
- **C — Consulted** : aucun
- **I — Informed** : aucun acteur distinct défini

Ne pas inventer de nouveaux rôles organisationnels.

## 6. Whitelist obligatoire

Les catégories suivantes sont protégées :

- ports des points d’accès critiques ;
- uplinks entre commutateurs ;
- trunks ;
- ports de management ;
- ports vers routeur / pare-feu / passerelle ;
- ports vers serveurs.

Si la cible correspond à une entrée protégée :

```text
journaliser
-> escalader
-> aucune modification réseau
```

Ne jamais contourner la whitelist.

## 7. VLAN de quarantaine

Le VLAN de quarantaine du prototype est :

```text
VLAN 18
```

Il doit être configuré en laboratoire comme VLAN totalement isolé avant de pouvoir être utilisé comme remédiation.

Avant une quarantaine :

1. confirmer l’existence du VLAN 18 ;
2. confirmer son isolement ;
3. confirmer que la cible n’est pas whitelistée ;
4. obtenir l’accord explicite de l’administrateur ;
5. sauvegarder l’état du port ;
6. seulement ensuite effectuer l’action.

Ne pas supposer qu’une simple modification de PVID garantit à elle seule l’isolement réseau.

## 8. Déconnexion physique

Pour `physical_disconnection` :

- aucune remédiation réseau automatique ;
- aucune commande SNMP SET ;
- vérifier si possible `ifAdminStatus` et `ifOperStatus` ;
- journaliser ;
- escalader vers l’administrateur.

Une panne physique nécessite une intervention humaine.

## 9. SNMP

Le projet utilise **SNMPv3 authPriv**.

### Règle absolue

**Ne jamais inventer un OID.**

Les OID doivent provenir :

- d’une MIB standard vérifiée ;
- de la documentation officielle du constructeur ;
- ou de résultats observés dans le laboratoire EVE-NG.

Si le support d’un objet n’est pas confirmé, le marquer comme :

```text
UNKNOWN / UNSUPPORTED / TO_BE_VALIDATED
```

et non comme supporté.

### Phase actuelle

La phase initiale SNMP doit être **strictement read-only**.

Interdit tant que les OID et capacités ne sont pas validés dans le laboratoire :

- SNMP SET de shutdown ;
- changement de VLAN ;
- réactivation de port ;
- rollback par écriture SNMP.

## 10. MIB/OID standards de référence

Les objets standards actuellement retenus pour exploration sont notamment :

### IF-MIB

- `ifName`
- `ifDescr`
- `ifAdminStatus`
- `ifOperStatus`
- `ifLastChange`

### BRIDGE-MIB

- `dot1dTpFdbAddress`
- `dot1dTpFdbPort`
- `dot1dBasePortIfIndex`
- objets STP utiles au diagnostic

### Q-BRIDGE-MIB

- `dot1qTpFdbPort`
- `dot1qPvid`
- objets de membership VLAN

### IP-MIB

- `ipNetToPhysicalPhysAddress`
- compatibilité éventuelle avec la table historique IP-to-media si nécessaire

Le support réel doit être détecté dans EVE-NG.

## 11. Chaîne d’identification cible

Quand applicable :

```text
IP
-> MAC
-> bridge port
-> ifIndex
-> interface physique
```

Si l’identification échoue :

- refaire une seule tentative ;
- après 2 tentatives au total :
  - journaliser ;
  - escalader ;
  - ne faire aucune modification réseau.

Les informations reçues de Zabbix (`client_ip`, `client_mac`, `interface`) sont uniquement des **indices**. Elles doivent être revérifiées avant toute action.

## 12. Webhook Zabbix

Le mécanisme retenu est :

```text
Zabbix -> HTTP POST -> FastAPI
```

Le payload suit le contrat JSON v1.0 du dépôt.

Le récepteur doit :

- vérifier `schema_version` ;
- vérifier la structure avec le JSON Schema ;
- vérifier l’authentification du webhook ;
- ignorer les événements de récupération ;
- accepter uniquement le périmètre `remediation=enabled` si cette politique est activée ;
- router vers le bon playbook ;
- gérer les événements dupliqués de manière idempotente.

Ne pas exécuter une remédiation simplement parce qu’un événement a été reçu.

## 13. SQLite et audit

La journalisation doit rester exploitable pour l’audit.

Conserver au minimum quand disponibles :

- identifiant de l’incident ;
- identifiant de l’événement Zabbix ;
- horodatage ;
- type d’incident ;
- équipement ;
- IP de management ;
- IP/MAC de la cible ;
- port physique ;
- décision administrateur ;
- état pré-action ;
- action demandée ;
- nombre de tentatives ;
- résultat de vérification ;
- état final ;
- résultat d’un rollback éventuel.

Ne jamais stocker les secrets SNMPv3 ou le secret du webhook dans les journaux.

## 14. Secrets et configuration

Les secrets doivent être fournis par variables d’environnement ou fichier `.env` local.

Ne jamais committer :

- `.env`
- mots de passe SNMPv3 ;
- clés privées ;
- tokens ;
- secrets de webhook ;
- dumps contenant des identifiants sensibles.

Le `.gitignore` doit empêcher leur ajout accidentel.

Fournir `.env.example` avec des valeurs factices.

## 15. Style de développement

- Python 3.10+.
- Préférer des modules courts et spécialisés.
- Ajouter des annotations de types sur le nouveau code lorsque raisonnable.
- Utiliser des noms explicites.
- Éviter les abstractions inutiles.
- Ne pas refactoriser des parties sans rapport avec la tâche demandée.
- Préserver la compatibilité avec la structure existante du dépôt.

## 16. Tests

Toute fonctionnalité nouvelle doit être accompagnée de tests lorsque cela est raisonnablement possible.

Avant de terminer une tâche, exécuter au minimum :

```bash
pytest -q
```

Si le projet fournit d’autres vérifications documentées dans le README, les exécuter également.

Pour le code SNMP, séparer :

1. tests unitaires sans équipement réel ;
2. tests d’intégration nécessitant EVE-NG.

Ne jamais faire échouer les tests unitaires simplement parce qu’un équipement EVE-NG n’est pas disponible.

## 17. Première mission d’implémentation SNMP

La première mission SNMP est :

**Créer un module de découverte SNMPv3 strictement read-only.**

Il doit :

- charger la configuration SNMPv3 depuis l’environnement ;
- utiliser authPriv ;
- tester la connectivité SNMP ;
- tester IF-MIB ;
- tester BRIDGE-MIB ;
- tester Q-BRIDGE-MIB ;
- tester IP-MIB ;
- produire un rapport :
  - `SUPPORTED`
  - `UNSUPPORTED`
  - `ERROR`
  - `NOT_TESTED`
- ne faire aucun SNMP SET ;
- ne modifier aucune configuration réseau ;
- ne déclarer aucun OID constructeur sans preuve ;
- fournir des tests unitaires.

Exemple de rapport attendu :

```text
IF-MIB
  ifName: SUPPORTED
  ifAdminStatus: SUPPORTED
  ifOperStatus: SUPPORTED

BRIDGE-MIB
  dot1dTpFdbPort: SUPPORTED
  dot1dBasePortIfIndex: SUPPORTED

Q-BRIDGE-MIB
  dot1qPvid: UNSUPPORTED

IP-MIB
  ipNetToPhysicalPhysAddress: SUPPORTED
```

## 18. Restrictions importantes

Ne pas :

- ajouter de nouveaux incidents sans demande ;
- supprimer la validation humaine obligatoire ;
- automatiser le rollback ;
- contourner la whitelist ;
- considérer les données Zabbix comme vérité définitive sur la cible ;
- exécuter un SNMP SET avant validation en laboratoire ;
- inventer des OID ;
- inventer des capacités UniFi/Cisco/autres ;
- placer des secrets dans le dépôt ;
- transformer le projet en système de réponse à incident généraliste.

Le périmètre reste la **remédiation réseau de base** du TFC.

## 19. Quand une décision est ambiguë

Si une modification demande une décision qui n’est pas définie dans ce fichier, les playbooks ou la documentation du dépôt :

1. ne pas inventer la règle ;
2. expliquer clairement le point bloquant ;
3. proposer les options techniques ;
4. attendre une décision avant d’implémenter un comportement potentiellement disruptif.
