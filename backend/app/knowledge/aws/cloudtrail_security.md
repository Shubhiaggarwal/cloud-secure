# CloudTrail Security

## Why Logging Matters
AWS CloudTrail records API activity across your account: who called which
API, when, from where, and with what parameters. Without an active trail,
there is no audit record of account activity - if a security incident
occurs (unauthorized access, data exfiltration, resource deletion), there's
no way to investigate what happened, when it started, or what else the
attacker may have touched.

## Trail Configuration
A trail can exist but not be actively logging (e.g. if logging was manually
stopped), which creates a false sense of security - the trail appears
configured but isn't recording anything. Best practice is a multi-region
trail that logs to a dedicated, access-restricted S3 bucket, ideally with
log file integrity validation enabled and log data protected from deletion
by anyone other than a small number of trusted admins.

## Remediation Steps
1. Create at least one CloudTrail trail covering all regions.
2. Confirm the trail's logging status is actively "on" (`IsLogging: true`),
   not just configured.
3. Send trail logs to a dedicated S3 bucket with restricted access and
   enable log file validation.
4. Consider enabling CloudTrail Insights or forwarding logs to a SIEM for
   anomaly detection.
