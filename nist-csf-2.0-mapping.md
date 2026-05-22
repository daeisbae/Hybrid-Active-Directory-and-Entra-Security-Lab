# NIST CSF 2.0 Control Assessment

This document maps the Azure Hybrid Identity Security Assessment to NIST Cybersecurity Framework 2.0.

## 1. Scope

- Active Directory Domain Services on `dc01`
- DNS, OU structure, GPOs, users, groups, and domain join validation
- Microsoft Entra custom domain, Entra Connect Sync, synced users, synced groups, and hybrid device join
- Azure resource group, network, virtual machines, Log Analytics, Azure Monitor Agent, Data Collection Rules, and Microsoft Sentinel
- KQL detections for AD DS, Entra audit, and Entra sign-in activity
- Terraform definitions under `infra/terraform/`


## 2. Assessment Method

Evidence was reviewed using these checks:

- Configuration review of Terraform and documented build steps
- Screenshot review from Azure, Microsoft Entra, ADUC, GPMC, Windows client, Log Analytics, and Sentinel
- Control testing based on generated lab activity such as group membership changes, password actions, role assignment, and failed sign-ins
- Gap review for items that are designed, partially implemented, or not yet evidenced

Result types:

- Pass: Control is implemented and evidence is present.
- Partial: Control is implemented in part, or the design exists but evidence is incomplete.
- Not tested: Control is documented or planned, but no test evidence is present.

## 3. Evidence Register

| ID | Evidence | What it supports |
| --- | --- | --- |
| EV-01 | [README.md](README.md) | Assessment scope, build steps, identity design, KQL tests, and references. |
| EV-02 | [infra/terraform/main.tf](infra/terraform/main.tf) | Azure resource group, VNet, subnet, NSG, VMs, tags, and RBAC assignment logic. |
| EV-03 | [infra/terraform/monitoring.tf](infra/terraform/monitoring.tf) | Log Analytics, Sentinel onboarding, Azure Monitor Agent, DCR, and Sentinel analytics rules. |
| EV-04 | [infra/terraform/policy.tf](infra/terraform/policy.tf) | Custom Azure Policy definitions for required tags. |
| EV-05 | [Azure resource group inventory](evidence/53-azure-resource-group-inventory.png) | Azure resource inventory, deployment count, location, Log Analytics workspace, DCR, NSG, and Sentinel solution. |
| EV-06 | [AD OU creation](evidence/04-powershell-create-lab-ou-structure.png), [AD OU view](evidence/05-aduc-lab-ou-structure.png) | OU structure for synced, privileged, and service account objects. |
| EV-07 | [AD groups](evidence/07-aduc-lab-groups-created.png), [AD users](evidence/08-aduc-lab-users-alice-bob.png) | Lab users and security groups created in AD DS. |
| EV-08 | [Custom domain verified](evidence/10-entra-custom-domain-names-verified.png), [DNS TXT record](evidence/12-entra-custom-domain-dns-txt-record.png) | Verified Microsoft Entra custom domain. |
| EV-09 | [Entra Connect OU filtering](evidence/26-entra-connect-ou-filtering-lab-synced.png), [ADSync scheduler](evidence/27-powershell-adsync-scheduler-status.png) | Scoped Entra Connect Sync configuration. |
| EV-10 | [Synced users](evidence/28-entra-synced-users-lab-ou.png), [Synced groups](evidence/29-entra-synced-groups-lab-ou.png), [Entra users sync status](evidence/54-entra-users-sync-status.png) | Synced users and groups appear in Entra, with on-premises sync enabled for lab users. |
| EV-11 | [Domain sign-in](evidence/34-winclient01-domain-sign-in-lab-admin.png), [GPO result](evidence/35-winclient01-gpresult-domain-policy.png) | Domain join and GPO application on the client. |
| EV-12 | [Hybrid join status](evidence/36-winclient01-dsregcmd-hybrid-join-status.png), [Entra hybrid device](evidence/37-entra-devices-winclient01-hybrid-joined.png) | Hybrid joined Windows device validation. |
| EV-13 | [SecurityEvent data](evidence/38-sentinel-securityevent-data-dc01.png), [SecurityEvent summary](evidence/39-sentinel-securityevent-summary-dc01.png) | Windows Security events collected in Log Analytics. |
| EV-14 | [Terraform DCR and detection code](evidence/55-terraform-dcr-detection-code.png) | DCR associations and privileged group change KQL defined in Terraform. |
| EV-15 | [Privileged group test](evidence/40-powershell-privileged-group-membership-test-action.png), [Privileged group KQL](evidence/41-sentinel-privileged-group-membership-kql-results.png) | Detection for privileged AD group membership changes. |
| EV-16 | [Password/account test](evidence/42-powershell-password-account-admin-test-action.png), [Password/account KQL](evidence/43-sentinel-password-account-admin-kql-results.png) | Detection for password reset, account disable, and account deletion activity. |
| EV-17 | [GPO management](evidence/44-gpmc-lab-domain-gpo-management.png), [GPO link](evidence/45-gpmc-test-gpo-linked-lab-computers.png), [GPO KQL](evidence/46-sentinel-gpo-ad-object-modification-kql-results.png) | Detection for GPO or directory object changes. |
| EV-18 | [Role before assignment](evidence/47-entra-directory-readers-role-before-assignment.png), [Role assignment](evidence/48-entra-directory-readers-add-alice-labuser.png), [Role assignment result](evidence/49-entra-directory-readers-assignments-alice-labuser.png), [AuditLogs result](evidence/50-sentinel-entra-role-assignment-auditlogs-results.png) | Detection for Entra role assignment activity. |
| EV-19 | [Failed sign-in test](evidence/51-entra-failed-signin-test-action-alice.png), [SigninLogs result](evidence/52-sentinel-failed-signin-signinlogs-results.png) | Detection for failed Entra sign-in spikes. |
| EV-20 | [Log Analytics AuditLogs and SecurityAlert query](evidence/56-log-analytics-auditlogs-securityalert.png) | Entra AuditLogs and SecurityAlert data present in Log Analytics. |

## 4. Summary of Results

| NIST CSF function | Result | Summary |
| --- | --- | --- |
| Govern | Partial | Lab purpose, scope, policy-as-code, and known constraints are documented. Formal risk acceptance and policy compliance evidence are incomplete. |
| Identify | Pass | Azure assets, AD objects, synced objects, and hybrid device state are documented with screenshots and code. |
| Protect | Partial | Identity scoping, GPOs, RBAC design, and RDP restrictions are present. Some controls need final evidence, especially RBAC assignment and emergency access testing. |
| Detect | Pass | AD DS, Entra audit, and Entra sign-in events are collected and queried. Multiple detections have test actions and results. |
| Respond | Partial | Response actions and Sentinel analytics rules are documented. Incident workflow evidence is not complete. |
| Recover | Partial | Terraform gives a rebuild path for Azure resources. AD DS restore and full recovery testing are out of scope. |

## 5. Control Assessment

| CSF function | Category | Control objective | Evidence | Test performed | Result | Gap or finding | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Govern | Organizational Context | Define the lab purpose, environment boundary, and security goal. | EV-01, EV-05 | Reviewed README scope and Azure resource group inventory. | Pass | None for lab scope. | Keep README scope current when adding new services. |
| Govern | Risk Management Strategy | Record lab constraints and known design risks. | EV-01 | Reviewed documented note that Entra Connect Sync runs on `dc01` for cost reasons. | Partial | Risk is documented, but there is no formal risk register. | Add a short risk register with owner, likelihood, impact, decision, and target remediation. |
| Govern | Policy | Use policy-as-code guardrails for baseline resource governance. | EV-04 | Reviewed custom Azure Policy definitions that deny resources missing required tags. | Partial | Terraform defines the policy, but no Azure Policy assignment or compliance screenshot is linked. | Capture Azure Policy assignment and compliance evidence after apply. |
| Govern | Oversight | Keep infrastructure changes reviewable. | EV-02, EV-03, EV-05 | Reviewed Terraform definitions and Azure deployment count. | Partial | Terraform code exists, but saved `terraform plan` or `terraform apply` output is not in evidence. | Save sanitized plan and apply output in `evidence/`. |
| Identify | Asset Management | Maintain an inventory of Azure and identity assets in scope. | EV-02, EV-05, EV-06, EV-07, EV-10, EV-12 | Reviewed Azure resource group, Terraform, AD objects, synced Entra users/groups, and hybrid device evidence. | Pass | None for lab inventory. | Add a small asset inventory table if the project grows. |
| Identify | Risk Assessment | Identify material risks in the hybrid identity design. | EV-01, EV-09, EV-10 | Reviewed sync scoping and the documented `dc01`/sync role tradeoff. | Partial | Risks are described in prose, but not rated. | Add risk ratings for combined DC/sync server, public IP/RDP exposure, logging retention, and licensing gaps. |
| Identify | Improvement | Track design changes and future improvements. | EV-01 | Reviewed documented future work for Conditional Access, PIM, emergency access, and production-style sync separation. | Partial | Improvements are spread through the README, not tracked in one place. | Add a "Remediation Roadmap" or "Future Improvements" table. |
| Protect | Identity Management, Authentication, and Access Control | Sync only intended AD objects into Microsoft Entra ID. | EV-06, EV-09, EV-10 | Reviewed OU filtering and synced users/groups. | Pass | None for the tested scope. | Keep service accounts and privileged-only objects outside normal sync scope unless business need is documented. |
| Protect | Identity Management, Authentication, and Access Control | Use group-based access instead of direct user assignment where practical. | EV-02, EV-07, EV-18 | Reviewed AD group design, Terraform RBAC assignment logic, and Entra role assignment test. | Partial | Azure/Sentinel RBAC group assignment screenshot is not yet linked. The role assignment test uses Alice directly for Directory Readers. | Capture IAM role assignment evidence for synced groups such as `GRP_AZ_Reader` and `GRP_SEN_Responder`. |
| Protect | Platform Security | Restrict direct administrative network access. | EV-02 | Reviewed NSG rule logic that only creates inbound RDP from `admin_source_ip_cidr`, or no public IP/RDP when null. | Partial | Actual NSG inbound rule screenshot is not linked. | Capture NSG inbound rules and public IP state for `dc01` and `winclient01`. |
| Protect | Platform Security | Apply workstation and domain controller security baselines through GPO. | EV-11, EV-17 | Reviewed domain sign-in, GPO result, GPMC evidence, and GPO change detection. | Partial | Screenshots show GPO application and management, but exact firewall and audit policy settings are not fully evidenced. | Add screenshots or exported GPO reports for firewall, account policy, local admin, and advanced audit policy settings. |
| Protect | Technology Infrastructure Resilience | Keep Azure infrastructure rebuildable. | EV-02, EV-03, EV-04 | Reviewed Terraform for compute, network, monitoring, policy, and Sentinel analytics resources. | Partial | Rebuild path exists for Azure resources, but AD DS state restore is not tested. | Document what Terraform rebuilds and what must be restored or recreated manually in AD DS. |
| Detect | Continuous Monitoring | Collect Windows Security events from identity systems. | EV-03, EV-13, EV-14 | Reviewed DCR configuration, AMA association, and SecurityEvent results. | Pass | None for tested events. | Recheck data after changing DCR event IDs or VM names. |
| Detect | Continuous Monitoring | Collect Microsoft Entra audit and sign-in activity where available. | EV-18, EV-19, EV-20 | Reviewed AuditLogs, SigninLogs, and Log Analytics evidence. | Pass | None for tested logs. | Track licensing and retention limits in the risk register. |
| Detect | Adverse Event Analysis | Detect suspicious or sensitive identity events. | EV-15, EV-16, EV-17, EV-18, EV-19 | Reviewed test actions and KQL results for group changes, account admin activity, GPO changes, role assignment, and failed sign-ins. | Pass | None for lab detections. | Add expected false positives and tuning notes for each detection. |
| Respond | Incident Management | Convert high-value detections into Sentinel analytics rules. | EV-03, EV-14 | Reviewed Terraform-managed scheduled analytics rule definitions. | Partial | Analytics rules are defined in code, but generated incident evidence is not linked. | Deploy analytics rules, trigger one test incident, and capture the incident page. |
| Respond | Incident Analysis | Tie each detection to a test action, query, and result. | EV-15, EV-16, EV-17, EV-18, EV-19 | Compared test actions with KQL result screenshots. | Pass | None for the tested detections. | Add a short analyst note for each detection explaining why the event matters. |
| Respond | Incident Mitigation | Demonstrate basic identity response actions. | EV-15, EV-16 | Reviewed privileged group removal and account disable/reset test actions with log results. | Pass | The tests are lab simulations, not a full incident response runbook. | Add a simple response runbook for suspected privileged access misuse. |
| Recover | Incident Recovery Plan Execution | Provide a rebuild path for Azure monitoring and infrastructure. | EV-02, EV-03, EV-04 | Reviewed Terraform coverage for Azure resources and monitoring configuration. | Partial | No full rebuild or restore test evidence is present. | Capture a destroy/reapply test in a separate lab run, or document why it was not run. |
| Recover | Incident Recovery Communication | Preserve evidence before teardown. | EV-01, EV-05 through EV-20 | Reviewed saved screenshots and README references. | Partial | Evidence is present, but there is no final evidence checklist with owner and date captured. | Add an evidence checklist with IDs, file paths, capture dates, and notes. |

## 6. Findings

| ID | Severity | Finding | Evidence | Recommendation |
| --- | --- | --- | --- | --- |
| F-01 | Medium | Entra Connect Sync is installed on `dc01` for lab cost reasons. This combines domain controller and sync roles. | EV-01, EV-09 | For a production design, use a separate `sync01` server and document the service account permissions. |
| F-02 | Medium | Conditional Access and PIM are designed but not fully implemented or tested. | EV-01 | Record licensing limits, then capture Security Defaults, Conditional Access, or PIM evidence when available. |
| F-03 | Low | Azure Policy tag guardrails are defined in Terraform, but assignment/compliance evidence is missing. | EV-04 | Capture Azure Policy assignment and compliance screenshots after apply. |
| F-04 | Low | Group-based Azure/Sentinel RBAC is designed in Terraform, but final role assignment screenshots are incomplete. | EV-02, EV-18 | Capture IAM evidence showing synced groups assigned to Reader, Log Analytics Reader, Sentinel Responder, or Sentinel Contributor. |
| F-05 | Medium | Recovery testing is limited to Terraform rebuild capability. AD DS restore and full lab recovery are not tested. | EV-02, EV-03, EV-04 | Add a recovery section that separates Azure rebuild, AD DS recovery, and evidence preservation. |
| F-06 | Low | GPO security settings are described, but exact exported GPO settings are not attached. | EV-11, EV-17 | Export GPO reports or capture screenshots for firewall, audit policy, account policy, and local admin assignment settings. |

## 7. Evidence Still Needed

These items would make the assessment stronger:

- Azure Policy assignment and compliance result
- NSG inbound rule screenshot showing RDP limited to the admin source IP, or no inbound RDP when `admin_source_ip_cidr` is null
- Terraform plan and apply output, sanitized if needed
- Azure IAM role assignments for synced groups
- Sentinel analytics rule page and one generated incident
- Conditional Access, PIM, or Security Defaults status
- Emergency access account test evidence
- Exported GPO reports for the implemented GPO baselines
- Recovery or rebuild test notes
