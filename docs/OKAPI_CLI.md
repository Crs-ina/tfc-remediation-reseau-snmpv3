# OKAPI CLI

Install the package in the deployment virtual environment and run:

```bash
okapi
```

The command obtains `system_username` from the Linux account that owns the
current SSH/session process. It finds or creates the corresponding row in
`administrators`, updates `last_seen_at`, and displays:

```text
[ OKAPI ]


Welcome, <display name or system username>.
```

Linux/SSH performs account management and primary authentication. OKAPI has no
Create/List/Disable/Delete administrator function and never stores a Linux
password or password hash.

The final menu is:

```text
Pending incidents
All incidents
Incident details
Approve remediation
Reject remediation
Remediation history
Incident & action history
Rollback
Dry-run mode
System status
Logout / Exit
```

Approving a real disruptive remediation, requesting rollback, and enabling or
disabling dry-run invoke `sudo -k` followed by `sudo -v`. The password exchange
is performed by the system PAM stack directly in the terminal and is never
read by OKAPI. Failure is audited and the action is refused.

Incident/action and remediation history display `Approved by : <username>` for
supervised actions and `Performed by : SYSTEM` for automatic actions. Dry-run
changes persist in the ignored local runtime
settings file and System status always displays the effective ON/OFF value.

The complete specification for authorization modes, executor identity,
dynamic VLAN/interface rollback, Available Rollbacks filtering and audit
events is in [REMEDIATION_ROLLBACK_CHANGES.md](REMEDIATION_ROLLBACK_CHANGES.md).

## Incident and action history filters

The submenu is exactly:

```text
[1] Latest history [2] Filter history [B] Back
```

`Filter history` guides the administrator through incident, date/period,
switch, port, remediation, mode, result, administrator and an optional free
word/phrase. Every category offers `[0] Any` (or a blank value for free-text
fields). Choosing `Any` only skips that category: OKAPI continues asking for
the remaining filters, so one small piece of information is sufficient.

The values offered for incident, switch, remediation, mode and result are built
from the history currently stored in the database. A partial value may also be
typed instead of a menu number. Ports accept `Ethernet1`, `Et1` or `1` when the
index is known.

The date is progressive: `2026` selects the whole year, `2026-08` the whole
month and `2026-08-20` the complete local day in `Africa/Kinshasa`.

The optional final phrase searches the complete business context. Spaces and
underscores are treated consistently, so `VLAN policy` can match
`VLAN_POLICY_VIOLATION`, and `port flapping` can match `port_flapping`.

The display groups technical audit events by incident/remediation. It presents
incident, detection time, severity, playbook, switch, port, readable
remediation, mode, historical result and actor. Internal event names remain in
the database but are not shown in the administrator history.

For maintenance, `flask --app run.py incidents list --from "2026-01-08 16:00"
--to "2026-01-08 17:00"` and `incidents logs` support local-time filters.
SNMP discovery remains read-only. Real writes remain behind target,
whitelist, capability, snapshot, isolation, cooldown, concurrency,
`SNMP_WRITE_ENABLED` and post-GET safeguards.
