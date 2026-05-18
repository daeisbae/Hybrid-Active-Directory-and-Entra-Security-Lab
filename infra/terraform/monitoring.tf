resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}

resource "azurerm_virtual_machine_extension" "ama_dc01" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc01.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.tags
}

resource "azurerm_virtual_machine_extension" "ama_winclient01" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.winclient01.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.tags
}

resource "azurerm_monitor_data_collection_rule" "windows_security_events" {
  name                = "dcr-${var.resource_prefix}-windows-security"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  destinations {
    log_analytics {
      name                  = "law"
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["law"]
  }

  data_sources {
    windows_event_log {
      name = "windows-security-events"
      streams = [
        "Microsoft-SecurityEvent"
      ]
      x_path_queries = [
        "Security!*[System[(EventID=4672 or EventID=4720 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4740 or EventID=4756 or EventID=4757 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=5136)]]"
      ]
    }
  }
}

resource "azurerm_monitor_data_collection_rule_association" "dc01" {
  name                    = "dc01-windows-security-events"
  target_resource_id      = azurerm_windows_virtual_machine.dc01.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.windows_security_events.id
  depends_on              = [azurerm_virtual_machine_extension.ama_dc01]
}

resource "azurerm_monitor_data_collection_rule_association" "winclient01" {
  name                    = "winclient01-windows-security-events"
  target_resource_id      = azurerm_windows_virtual_machine.winclient01.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.windows_security_events.id
  depends_on              = [azurerm_virtual_machine_extension.ama_winclient01]
}

locals {
  privileged_group_changes_query = <<-KQL
    let PrivilegedGroups = dynamic([
        "Azure Subscription Reader",
        "Log Analytics Reader",
        "Sentinel Responder",
        "Sentinel Contributor",
        "Helpdesk Password Reset",
        "Server Local Admins",
        "GRP_AZ_Reader",
        "GRP_LA_Reader",
        "GRP_SEN_Responder",
        "GRP_SEN_Contributor",
        "GRP_HD_PwdReset",
        "GRP_SRV_LocalAdmins",
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins",
        "Account Operators"
    ]);
    SecurityEvent
    | where EventID in (4728, 4729, 4732, 4733, 4756, 4757)
    | where TargetUserName has_any (PrivilegedGroups)
        or TargetAccount has_any (PrivilegedGroups)
        or MemberName has_any (PrivilegedGroups)
    | project TimeGenerated, Computer, EventID, Activity, Account, SubjectAccount, TargetAccount, TargetUserName, MemberName
  KQL

  password_account_admin_query = <<-KQL
    SecurityEvent
    | where EventID in (4724, 4725, 4726)
    | summarize Count=count() by EventID, Account, Computer, bin(TimeGenerated, 1h)
  KQL

  gpo_change_query = <<-KQL
    SecurityEvent
    | where EventID == 5136
    | where ObjectName has "CN=Policies,CN=System"
    | project TimeGenerated, Computer, Account, SubjectAccount, ObjectName, ObjectType, OperationType
  KQL
}

resource "azurerm_sentinel_alert_rule_scheduled" "privileged_group_changes" {
  count = var.deploy_sentinel_analytics ? 1 : 0

  name                       = "ad-privileged-group-changes"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name               = "AD privileged group membership changes"
  severity                   = "Medium"
  enabled                    = true
  query                      = local.privileged_group_changes_query
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1098"]

  incident {
    create_incident_enabled = true

    grouping {
      enabled = false
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_alert_rule_scheduled" "password_account_admin" {
  count = var.deploy_sentinel_analytics ? 1 : 0

  name                       = "ad-password-disable-delete-activity"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name               = "AD password reset or account disable/delete activity"
  severity                   = "Low"
  enabled                    = true
  query                      = local.password_account_admin_query
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["CredentialAccess", "Impact"]

  incident {
    create_incident_enabled = true

    grouping {
      enabled = false
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

resource "azurerm_sentinel_alert_rule_scheduled" "gpo_change" {
  count = var.deploy_sentinel_analytics ? 1 : 0

  name                       = "ad-gpo-or-directory-object-change"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name               = "AD GPO or directory object modification"
  severity                   = "Medium"
  enabled                    = true
  query                      = local.gpo_change_query
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1484"]

  incident {
    create_incident_enabled = true

    grouping {
      enabled = false
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}
