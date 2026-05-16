variable "resource_prefix" {
  description = "Prefix used for Azure resource names."
  type        = string
  default     = "hybrid-identity-lab"
}

variable "location" {
  description = "Azure region for lab resources."
  type        = string
  default     = "canadacentral"
}

variable "environment" {
  description = "Environment tag value."
  type        = string
  default     = "lab"
}

variable "admin_username" {
  description = "Local administrator username for the Windows VMs."
  type        = string
  default     = "labadmin"
}

variable "admin_password" {
  description = "Local administrator password for the Windows VMs."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.admin_password) >= 12
    error_message = "The admin password must be at least 12 characters."
  }
}

variable "admin_source_ip_cidr" {
  description = "Optional source CIDR allowed to RDP to the VMs. Use your public IP with /32. If null, no public IPs or inbound RDP rules are created."
  type        = string
  default     = null
}

variable "vnet_address_space" {
  description = "Address space for the lab VNet."
  type        = string
  default     = "10.10.0.0/16"
}

variable "identity_subnet_prefix" {
  description = "Subnet prefix for the identity lab VMs."
  type        = string
  default     = "10.10.1.0/24"
}

variable "dc_private_ip" {
  description = "Static private IP address assigned to dc01."
  type        = string
  default     = "10.10.1.10"
}

variable "dc_vm_size" {
  description = "VM size for dc01. Entra Connect Sync needs more memory than a tiny test VM."
  type        = string
  default     = "Standard_B2ms"
}

variable "client_vm_size" {
  description = "VM size for winclient01."
  type        = string
  default     = "Standard_B2s"
}

variable "windows_server_sku" {
  description = "Windows Server image SKU used for the lab VMs."
  type        = string
  default     = "2022-datacenter-azure-edition"
}

variable "log_retention_days" {
  description = "Log Analytics retention in days."
  type        = number
  default     = 30
}

variable "deploy_sentinel_analytics" {
  description = "Deploy scheduled Sentinel analytics rules. Keep false for the first apply if SecurityEvent data has not arrived yet."
  type        = bool
  default     = false
}

variable "enable_required_tag_policy" {
  description = "Create and assign custom Azure Policy definitions that require the baseline lab tags."
  type        = bool
  default     = true
}

variable "required_tag_names" {
  description = "Tags required by the custom Azure Policy assignments."
  type        = set(string)
  default     = ["project", "environment", "managed_by", "nist_csf"]
}

variable "extra_tags" {
  description = "Additional tags to apply to lab resources."
  type        = map(string)
  default     = {}
}

variable "rbac_group_object_ids" {
  description = "Optional Microsoft Entra group object IDs for RBAC assignment after AD groups are synced."
  type = object({
    subscription_reader  = optional(string)
    log_analytics_reader = optional(string)
    sentinel_responder   = optional(string)
    sentinel_contributor = optional(string)
  })
  default = {}
}
