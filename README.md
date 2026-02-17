# Microsoft 365 Phishing Email Investigation Lab

## Overview

This project simulates a SOC investigation into a reported phishing email within a Microsoft 365 environment.

The objective was to:

- Analyse email headers
- Identify sender spoofing
- Evaluate malicious indicators
- Assess user impact
- Map activity to MITRE ATT&CK
- Recommend containment and prevention measures

This lab mirrors a real Tier 1 phishing triage and escalation workflow.

---

## Scenario

A user reported a suspicious email claiming to be from Microsoft Support requesting urgent password verification.

The email contained:

- Urgent language
- Hyperlink to external domain
- Spoofed display name
- Attachment disguised as invoice

The SOC investigation aimed to determine whether this email was malicious and whether additional users were impacted.

---

## Email Summary

Display Name: Microsoft Support  
Sender Address: support@microsoft-secure-login.com  
Reply-To: security-alert@outlook-verification.net  
Subject: Urgent: Account Verification Required  
Attachment: Invoice_02_2026.html  

Initial review suggested domain impersonation and credential harvesting attempt.

---

## Investigation Steps

### 1. Header Analysis

Key findings from email headers:

- SPF: Fail
- DKIM: None
- DMARC: Fail
- Sending IP: 45.83.112.19
- Originating server not associated with Microsoft infrastructure

This indicates spoofing and lack of domain authentication.

---

### 2. Domain Analysis

Suspicious domain:

microsoft-secure-login.com

Characteristics:

- Newly registered domain
- Not owned by Microsoft
- Hosted on low reputation IP range
- Similar naming pattern to legitimate Microsoft domains

---

### 3. URL Inspection

Embedded hyperlink:

http://microsoft-secure-login.com/verify

Landing page replicated Microsoft 365 login portal.
Credential harvesting form captured:

- Email address
- Password
- MFA token

This confirms phishing intent.

---

### 4. User Impact Assessment

Email trace in Microsoft 365 revealed:

- 12 recipients internally
- 3 users clicked link
- 1 user submitted credentials

Immediate password reset required for impacted account.

---

## MITRE ATT&CK Mapping

T1566.002 – Phishing: Spearphishing Link  
T1204 – User Execution  
T1556 – Modify Authentication Process (potential follow-on risk)  

---

## Risk Assessment

Severity: High

Justification:

- Credential harvesting confirmed
- Internal users engaged with malicious link
- Brand impersonation of trusted vendor
- Potential account compromise

---

## False Positive Considerations

- Marketing email with misconfigured authentication
- Third party vendor email routing issue

However, domain impersonation and credential harvesting confirm malicious intent.

---

## Containment Actions

- Block sender domain at Microsoft Defender
- Remove email from all mailboxes
- Reset compromised user credentials
- Enforce MFA re-registration
- Review sign-in logs for anomalous access
- Add domain to tenant block list

---

## Detection Logic Proposal

Trigger alert when:

- SPF OR DKIM fails
- Sender display name contains "Microsoft"
- Domain does not match microsoft.com
- URL contains login keywords

---

### Example KQL (Microsoft Sentinel)

EmailEvents
| where SenderFromDomain !contains "microsoft.com"
| where Subject contains "Account" or Subject contains "Verify"
| where AuthenticationDetails contains "fail"

---

## Evidence Included

- email_headers_sample.txt
- email_trace_results.txt
- phishing_landing_page_analysis.txt
- incident_report.md

---

## Skills Demonstrated

- Email header analysis
- Domain impersonation detection
- Credential harvesting identification
- Microsoft 365 investigation workflow
- MITRE ATT&CK mapping
- Detection engineering thinking
- Incident documentation

---

## Analyst Conclusion

The investigated email was a credential harvesting phishing campaign impersonating Microsoft.

User interaction confirmed compromise risk. Immediate containment and tenant wide controls were required.

This case reflects a common real world SOC scenario involving identity focused attacks within cloud environments.
