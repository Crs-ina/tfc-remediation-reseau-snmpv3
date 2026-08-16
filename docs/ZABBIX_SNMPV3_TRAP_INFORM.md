# SNMPv3 TRAP/INFORM through Zabbix

This integration does not add a Python trap receiver. The supported chain is:

```text
switch -> SNMPv3 TRAP or INFORM -> snmptrapd/Zabbix -> trigger -> webhook -> OKAPI
```

Install `snmptrapd` and the Zabbix trap receiver components on the Zabbix/OKAPI
host. Copy `deploy/zabbix/snmptrapd.conf.example` to the local configuration.
Create the SNMPv3 USM user locally using the platform documentation and local
secrets; do not place its keys in this repository. Configure Zabbix server with
`StartSNMPTrapper=1` and its distribution-specific `SNMPTrapperFile` path.

Create an item on the Arista lab host:

```text
Type: SNMP trap
Key:  snmptrap[OKAPI-ZABBIX]
Type of information: Log
```

Create a trigger using a controlled notification marker, for example an item
value containing `linkDown`, and map the resulting media-type payload to one of
the seven canonical `incident_type` values before POSTing the existing JSON
v1.0 contract to `/api/v1/incidents/zabbix`.

Test by sending a notification from the Arista EVE-NG agent, checking
`journalctl -u snmptrapd`, the Zabbix item/trigger, and then the OKAPI audit.
Confirm that no direct receiver or incident detector is running in OKAPI.

TRAP and INFORM are both **TO_BE_VALIDATED** end-to-end. INFORM additionally
requires confirmation that the exact laboratory agent acknowledges it. This
documentation does not claim either mode is experimentally validated.
