# Microsoft Entra Cloud Sync Migration Notes

This lab uses Microsoft Entra Connect Sync for v1 because many organizations still run hybrid AD DS with Connect Sync. It is also easier to demonstrate OU scoping, Password Hash Synchronization, sync health, and hybrid join from a traditional lab build.

Microsoft Entra Cloud Sync should still be part of the design notes. If this lab were rebuilt for a newer production-style sync design, Cloud Sync would be the first option to evaluate.

## 1. Why Connect Sync Was Used in This Lab

Connect Sync gives the lab a clear on-premises sync server story:

- `dc01` is the AD DS source of identity.
- Microsoft Entra Connect Sync moves selected users, groups, and device objects into Microsoft Entra ID.
- Password Hash Synchronization gives synced users the same-password sign-in path.
- OU filtering keeps service accounts and other non-cloud identities out of scope.
- The sync engine and Synchronization Service Manager provide visible evidence for a portfolio README.

For this student-budget v1, Connect Sync runs on `dc01` to reduce VM cost. In a production-style build, it should run on a dedicated member server such as `sync01`.

## 2. Why Cloud Sync Should Be Reviewed

Cloud Sync uses a lighter agent model and moves more of the sync configuration into Microsoft Entra. That can reduce the amount of infrastructure managed on-premises.

Before replacing Connect Sync with Cloud Sync, check whether the lab or production environment needs features that are still better handled by Connect Sync. Do not assume feature parity. The sync design should be chosen after checking the current Microsoft documentation and the exact identity requirements.

## 3. Migration Questions to Answer

Before rebuilding the lab with Cloud Sync, answer these questions:

- Which users, groups, and computer objects must sync?
- Is Password Hash Synchronization still the right sign-in method?
- Are there unsupported attributes, filtering rules, or writeback requirements?
- Does Cloud Sync support the required OU, group, or attribute scoping behavior?
- How will hybrid join be configured and validated?
- How will sync errors be monitored without the same local sync-engine workflow?
- Which admin roles are required in Microsoft Entra?
- What evidence screenshots will replace the Connect Sync wizard and Synchronization Service Manager screenshots?

## 4. What Would Change in the README

The build guide would need these changes:

- Replace the Entra Connect Sync installer steps with Cloud Sync agent setup.
- Move sync scoping steps into the Microsoft Entra Cloud Sync configuration.
- Replace local sync-engine screenshots with Cloud Sync portal screenshots.
- Update validation steps for provisioning logs and agent health.
- Keep the `.onmicrosoft.com` UPN suffix decision unless a verified custom domain is added.
- Keep the same AD DS OU model unless Cloud Sync scoping requires a different layout.
- Keep the same Sentinel detections because the identity events being monitored do not change much.

## 5. Evidence Placeholders for a Cloud Sync Rebuild

Use these placeholders if the lab is rebuilt with Cloud Sync later.

- <evidence screenshot - Microsoft Entra Cloud Sync configuration showing the agent, scoped objects, and enabled provisioning job.>
- <evidence screenshot - Cloud Sync agent health page showing the lab agent online and reporting successfully.>
- <evidence screenshot - Cloud Sync provisioning logs showing successful sync for a test user and group.>
- <evidence screenshot - Microsoft Entra users and groups page showing objects synced by Cloud Sync from the lab AD DS environment.>
- <evidence screenshot - winclient01 dsregcmd /status output after the Cloud Sync rebuild showing AzureAdJoined YES, DomainJoined YES, and DeviceAuthStatus SUCCESS.>

## 6. References

- [What is Microsoft Entra Connect Sync?](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect)
- [What is Microsoft Entra Cloud Sync?](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync)
- [Compare Microsoft Entra Connect Sync and Cloud Sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync#comparison-between-microsoft-entra-connect-and-cloud-sync)
