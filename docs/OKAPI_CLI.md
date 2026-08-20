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
Audit logs
Rollback
Dry-run mode
System status
Logout / Exit
```

Approving a real disruptive remediation, requesting rollback, and enabling or
disabling dry-run invoke `sudo -k` followed by `sudo -v`. The password exchange
is performed by the system PAM stack directly in the terminal and is never
read by OKAPI. Failure is audited and the action is refused.

Audit and remediation history display `Approved by : <username>` for
supervised actions and `Executed by : SYSTEM` for automatic actions. Dry-run
changes persist in the ignored local runtime
settings file and System status always displays the effective ON/OFF value.

The complete specification for authorization modes, executor identity,
dynamic VLAN/interface rollback, Available Rollbacks filtering and audit
events is in [REMEDIATION_ROLLBACK_CHANGES.md](REMEDIATION_ROLLBACK_CHANGES.md).

## Audit log filters

`Audit logs > Filter logs` accepts these independent optional fields:

```text
Date (YYYY-MM-DD, blank = any)
Incident type (blank = any)
Action (blank = any)
Result (blank = any)
Administrator (blank = any)
Switch name (blank = any)
Port index (blank = any)
```

Text fields use a case-insensitive literal `contains` match against their own
column only. For example, `vlan`, `shut`, `exau` and `aris` match values in
`incident_type`, `action_type`, `Administrator.system_username` and
`equipment_name` respectively. Blank fields add no SQL condition. Multiple
non-blank fields are combined with `AND`.

The date represents the complete local day in `Africa/Kinshasa`; OKAPI converts
its bounds to UTC before querying `event_timestamp`. Administrator searches
also treat any matching substring of `SYSTEM` (such as `sys`) as events whose
`administrator_id` is null. Port index remains an exact integer match.

Filtered searches return all matches. `Latest logs` remains unchanged and
continues to display the latest 20 entries.

For maintenance, `flask --app run.py incidents list --from "2026-01-08 16:00"
--to "2026-01-08 17:00"` and `incidents logs` support local-time filters.
SNMP discovery remains read-only. Real writes remain behind target,
whitelist, capability, snapshot, isolation, cooldown, concurrency,
`SNMP_WRITE_ENABLED` and post-GET safeguards.
