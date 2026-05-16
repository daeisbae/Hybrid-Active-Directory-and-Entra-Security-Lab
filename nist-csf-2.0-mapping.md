# NIST CSF 2.0 Mapping

This lab follows NIST Cybersecurity Framework 2.0 as a practical guide for governance, asset tracking, access control, monitoring, response, and recovery.

The mapping is not a formal audit. It shows which lab steps provide evidence for each CSF function.

## 1. Govern

| CSF category | Lab implementation | Evidence |
| --- | --- | --- |
| Organizational Context | The README defines the lab purpose, identity boundary, Azure subscription, and student-budget limits. | <evidence screenshot - README architecture section showing the lab goal, components, and student-budget design choices.> |
| Risk Management Strategy | The README separates implemented controls from controls blocked by licensing, such as Conditional Access and PIM. | <evidence screenshot - Entra licensing or Security Defaults page showing which identity controls are available in the tenant.> |
| Policy | Terraform assigns required-tag Azure Policy guardrails to the lab resource group. | <evidence screenshot - Azure Policy assignments showing required tag policies applied to the lab resource group.> |
| Oversight | Terraform plan and apply output show what infrastructure changed and when. | <evidence screenshot - terraform plan or apply output showing reviewed infrastructure changes for the lab.> |

## 2. Identify

| CSF category | Lab implementation | Evidence |
| --- | --- | --- |
| Asset Management | Terraform creates named resources for `dc01`, `winclient01`, VNet, Log Analytics, and Sentinel onboarding. | <evidence screenshot - Azure resource group showing tagged lab assets deployed by Terraform.> |
| Improvement | The Cloud Sync appendix records future sync design changes and limitations. | <evidence screenshot - cloud-sync-migration-notes.md showing the Connect Sync and Cloud Sync design comparison.> |
| Risk Assessment | The README documents the risk of combining Entra Connect Sync with `dc01` and explains the production-style `sync01` option. | <evidence screenshot - README section explaining why dc01 combines roles for cost and why sync01 is preferred in production.> |

## 3. Protect

| CSF category | Lab implementation | Evidence |
| --- | --- | --- |
| Identity Management, Authentication, and Access Control | AD DS users and groups sync to Microsoft Entra ID through scoped Entra Connect Sync. | <evidence screenshot - Microsoft Entra admin center showing synced users and groups from the selected AD OUs.> |
| Identity Management, Authentication, and Access Control | RBAC uses synced groups instead of direct user assignment. | <evidence screenshot - Azure IAM page showing a lab group assigned to Reader, Log Analytics Reader, Sentinel Responder, or Sentinel Contributor.> |
| Platform Security | Terraform restricts direct RDP to a provided admin source CIDR, or creates no public IPs when the value is null. | <evidence screenshot - NSG inbound rules showing RDP allowed only from the configured admin source IP or no inbound RDP rule.> |
| Platform Security | GPOs configure Windows Firewall and advanced audit policy. | <evidence screenshot - Group Policy Management showing workstation firewall and audit policy GPOs linked to the lab OUs.> |
| Technology Infrastructure Resilience | Terraform can rebuild the Azure foundation after destroy or failure. | <evidence screenshot - terraform outputs showing dc01, winclient01, and the Log Analytics workspace after deployment.> |

## 4. Detect

| CSF category | Lab implementation | Evidence |
| --- | --- | --- |
| Continuous Monitoring | Azure Monitor Agent and Data Collection Rules send selected Windows Security events to Log Analytics. | <evidence screenshot - Log Analytics query showing SecurityEvent data from dc01 or winclient01.> |
| Continuous Monitoring | Microsoft Entra audit logs are connected to Sentinel when available. | <evidence screenshot - Sentinel data connector page showing Microsoft Entra audit log connector status.> |
| Adverse Event Analysis | KQL detections cover privileged group changes, password/account activity, GPO changes, role assignments, and failed sign-in spikes where licensing allows. | <evidence screenshot - KQL query result showing one validated detection from generated lab activity.> |

## 5. Respond

| CSF category | Lab implementation | Evidence |
| --- | --- | --- |
| Incident Management | One validated KQL query is converted into a Sentinel scheduled analytics rule. | <evidence screenshot - Sentinel analytic rule or incident generated from privileged AD group membership changes.> |
| Incident Analysis | Each detection has a test action and expected log result. | <evidence screenshot - README detection section showing the test action, KQL query, and evidence placeholder for one detection.> |
| Incident Mitigation | The lab documents account disable, password reset, and privileged group removal as controlled response actions. | <evidence screenshot - KQL result showing account disable, password reset, or privileged group removal activity.> |

## 6. Recover

| CSF category | Lab implementation | Evidence |
| --- | --- | --- |
| Incident Recovery Plan Execution | Terraform provides the rebuild path for Azure infrastructure, monitoring, and Sentinel onboarding. | <evidence screenshot - Terraform README showing deploy and destroy commands for the lab foundation.> |
| Incident Recovery Communication | The README records what evidence must be saved before destroying the lab. | <evidence screenshot - README evidence checklist showing required screenshots before cleanup.> |

## 7. References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST Cybersecurity Framework 2.0](https://doi.org/10.6028/NIST.CSWP.29)
