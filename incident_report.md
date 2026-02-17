Incident Report: Credential Harvesting Phishing Campaign

Summary

A phishing email impersonating Microsoft Support was delivered to 12 users. The email contained a malicious link directing users to a fake login portal.

Timeline

09:12 – Email delivered
09:20 – First user click detected
09:22 – Credential submission confirmed
09:30 – User reported suspicious activity
09:35 – SOC investigation initiated
10:05 – Domain blocked and password reset completed

Impact

One user submitted credentials.
No confirmed post-compromise activity observed.

Risk Level

High

MITRE ATT&CK

T1566.002 – Spearphishing Link
T1204 – User Execution

Recommendations

Block malicious domain
Reset impacted credentials
Enforce conditional access policies
Increase user phishing awareness training
Review similar domain lookalikes

Analyst Assessment

The attack leveraged brand impersonation and urgency to induce user interaction. Rapid reporting limited impact and prevented lateral spread.
