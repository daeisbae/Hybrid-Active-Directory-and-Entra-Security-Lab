# Terraform Deployment

This Terraform deployment builds the Azure foundation for the hybrid identity lab.

It deploys:

- Resource group
- VNet, subnet, DNS setting, and NSG
- `dc01` and `winclient01`
- Optional public IPs and restricted RDP rule
- Log Analytics workspace
- Microsoft Sentinel onboarding
- Azure Monitor Agent on both VMs
- Data Collection Rule for selected Windows Security events
- Required-tag Azure Policy assignments
- Optional RBAC assignments for synced Microsoft Entra groups
- Optional Sentinel scheduled analytics rules

AD DS, DNS role configuration, OUs, GPOs, Microsoft Entra Connect Sync, and hybrid join are still guided steps in the main README. They need Windows and portal evidence, so the lab should not hide them inside a VM bootstrap script.

## 1. Prerequisites

Install:

- Terraform
- Azure CLI
- An Azure subscription where you can create VMs, policy assignments, Log Analytics, and Sentinel resources

Sign in:

```bash
az login
az account show
```

If you have more than one subscription, select the lab subscription.

```bash
az account set --subscription "<subscription id>"
```

## 2. Configure Variables

Copy the example variables file.

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`.

Set a strong `admin_password`.

If you need direct RDP access, set `admin_source_ip_cidr` to your public IP with `/32`.

```hcl
admin_source_ip_cidr = "203.0.113.10/32"
```

If `admin_source_ip_cidr` stays `null`, Terraform creates no public IPs and no inbound RDP rule.

## 3. Deploy the Lab Foundation

Initialize Terraform.

```bash
terraform init
```

Check formatting and validate the configuration.

```bash
terraform fmt
terraform validate
```

Review the plan.

```bash
terraform plan -out tfplan
```

Apply the plan.

```bash
terraform apply tfplan
```

<evidence screenshot - terminal output showing terraform plan with the resource group, VMs, VNet, NSG, Log Analytics workspace, Sentinel onboarding, AMA extensions, DCR, and tag policy assignments ready to deploy.>

<evidence screenshot - terminal output showing terraform apply completed successfully with outputs for dc01, winclient01, and the Log Analytics workspace.>

## 4. Apply RBAC After Sync

The RBAC assignments depend on Microsoft Entra group object IDs. Those groups do not exist until AD DS users and groups sync through Microsoft Entra Connect Sync.

After sync works, find the object IDs for the synced lab groups, then add them to `terraform.tfvars`.

```hcl
rbac_group_object_ids = {
  subscription_reader  = "00000000-0000-0000-0000-000000000000"
  log_analytics_reader = "00000000-0000-0000-0000-000000000000"
  sentinel_responder   = "00000000-0000-0000-0000-000000000000"
  sentinel_contributor = "00000000-0000-0000-0000-000000000000"
}
```

Run `terraform plan` and `terraform apply` again.

<evidence screenshot - terraform plan showing RBAC role assignments for the synced Microsoft Entra groups.>

## 5. Deploy Sentinel Analytics Rules

Keep `deploy_sentinel_analytics = false` for the first apply. Some Sentinel rule deployments can fail if the target table has not received data yet.

After AMA sends `SecurityEvent` data into Log Analytics, set:

```hcl
deploy_sentinel_analytics = true
```

Run Terraform again.

```bash
terraform plan -out tfplan
terraform apply tfplan
```

<evidence screenshot - terraform plan showing Sentinel scheduled analytics rules for privileged group changes, password/account activity, and GPO changes.>

## 6. NIST CSF 2.0 Coverage

This Terraform layer supports the NIST CSF 2.0 functions used in the main lab:

| CSF function | Terraform support |
| --- | --- |
| Govern | Required tags, named ownership tags, and policy assignments |
| Identify | Asset inventory through resource group, tags, outputs, and VM names |
| Protect | Restricted RDP, scoped NSG, RBAC group assignments, and DNS control |
| Detect | Log Analytics, Sentinel onboarding, AMA, DCR, and analytics rules |
| Respond | Sentinel incidents from scheduled analytics rules |
| Recover | Repeatable deployment and documented destroy/rebuild path |

See `../../nist-csf-2.0-mapping.md` for the full lab mapping.

## 7. Destroy the Lab

When the lab is finished, destroy the Azure resources to stop costs.

```bash
terraform destroy
```

Do not destroy the lab until screenshots and notes are saved.
