# Cyber Threat Summary

Generated: 2026-05-07 01:14:39 UTC

## Executive Snapshot

- Total events: 10
- Critical events: 2
- Unique sources: 8
- Most affected asset: vpn-gateway
- Most common signal: login_failure

## Top Incidents

- Critical (100): Phishing Campaign on mail-gateway from 203.0.113.77 [T1566 Phishing]
  Recommendation: Quarantine messages, identify clicked users, and rotate credentials where needed.
- Critical (100): Privilege Drift on domain-controller from 172.16.88.2 [T1078 Valid Accounts]
  Recommendation: Review the account change, revoke unapproved grants, and inspect adjacent identity activity.
- Critical (100): Data Exposure on data-warehouse from 203.0.113.90 [T1041 Exfiltration Over C2 Channel]
  Recommendation: Validate transfer destination, suspend suspicious sessions, and check data access logs.
- Critical (100): Malware Containment on finance-workstation from 45.155.205.233 [T1204 User Execution]
  Recommendation: Isolate the endpoint, preserve evidence, and verify containment across similar hosts.
- Critical (100): Credential Pressure on vpn-gateway from 185.220.101.4 [T1110 Brute Force]
  Recommendation: Review VPN logs, lock affected accounts, enforce MFA, and inspect successful logins from the same source.
