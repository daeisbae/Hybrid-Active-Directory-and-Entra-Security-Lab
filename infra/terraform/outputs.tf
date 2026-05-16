output "resource_group_name" {
  description = "Lab resource group."
  value       = azurerm_resource_group.main.name
}

output "dc01_private_ip" {
  description = "Private IP address for dc01."
  value       = azurerm_network_interface.dc01.private_ip_address
}

output "winclient01_private_ip" {
  description = "Private IP address for winclient01."
  value       = azurerm_network_interface.winclient01.private_ip_address
}

output "dc01_public_ip" {
  description = "Public IP address for dc01 when admin_source_ip_cidr is set."
  value       = var.admin_source_ip_cidr == null ? null : azurerm_public_ip.dc01[0].ip_address
}

output "winclient01_public_ip" {
  description = "Public IP address for winclient01 when admin_source_ip_cidr is set."
  value       = var.admin_source_ip_cidr == null ? null : azurerm_public_ip.winclient01[0].ip_address
}

output "log_analytics_workspace_name" {
  description = "Log Analytics workspace used by Sentinel."
  value       = azurerm_log_analytics_workspace.main.name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID."
  value       = azurerm_log_analytics_workspace.main.id
}

output "sentinel_onboarding_id" {
  description = "Sentinel onboarding resource ID."
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.main.id
}
