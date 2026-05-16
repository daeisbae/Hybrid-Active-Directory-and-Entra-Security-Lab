data "azurerm_subscription" "current" {}

locals {
  tags = merge(
    {
      project     = "azure-hybrid-identity-lab"
      environment = var.environment
      managed_by  = "terraform"
      nist_csf    = "GV,ID,PR,DE,RS,RC"
    },
    var.extra_tags
  )

  rbac_assignments = {
    subscription_reader = {
      principal_id         = try(var.rbac_group_object_ids.subscription_reader, null)
      role_definition_name = "Reader"
      scope                = data.azurerm_subscription.current.id
    }
    log_analytics_reader = {
      principal_id         = try(var.rbac_group_object_ids.log_analytics_reader, null)
      role_definition_name = "Log Analytics Reader"
      scope                = azurerm_log_analytics_workspace.main.id
    }
    sentinel_responder = {
      principal_id         = try(var.rbac_group_object_ids.sentinel_responder, null)
      role_definition_name = "Microsoft Sentinel Responder"
      scope                = azurerm_log_analytics_workspace.main.id
    }
    sentinel_contributor = {
      principal_id         = try(var.rbac_group_object_ids.sentinel_contributor, null)
      role_definition_name = "Microsoft Sentinel Contributor"
      scope                = azurerm_log_analytics_workspace.main.id
    }
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.resource_prefix}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = [var.vnet_address_space]
  dns_servers         = [var.dc_private_ip]
  tags                = local.tags
}

resource "azurerm_subnet" "identity" {
  name                 = "snet-identity"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.identity_subnet_prefix]
}

resource "azurerm_network_security_group" "identity" {
  name                = "nsg-${var.resource_prefix}-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  dynamic "security_rule" {
    for_each = var.admin_source_ip_cidr == null ? [] : [var.admin_source_ip_cidr]

    content {
      name                       = "Allow-RDP-From-Admin-IP"
      priority                   = 100
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "3389"
      source_address_prefix      = security_rule.value
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "identity" {
  subnet_id                 = azurerm_subnet.identity.id
  network_security_group_id = azurerm_network_security_group.identity.id
}

resource "azurerm_public_ip" "dc01" {
  count               = var.admin_source_ip_cidr == null ? 0 : 1
  name                = "pip-dc01"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_public_ip" "winclient01" {
  count               = var.admin_source_ip_cidr == null ? 0 : 1
  name                = "pip-winclient01"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "dc01" {
  name                = "nic-dc01"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.identity.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.dc_private_ip
    public_ip_address_id          = var.admin_source_ip_cidr == null ? null : azurerm_public_ip.dc01[0].id
  }
}

resource "azurerm_network_interface" "winclient01" {
  name                = "nic-winclient01"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.identity.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.admin_source_ip_cidr == null ? null : azurerm_public_ip.winclient01[0].id
  }
}

resource "azurerm_windows_virtual_machine" "dc01" {
  name                  = "dc01"
  computer_name         = "dc01"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  size                  = var.dc_vm_size
  admin_username        = var.admin_username
  admin_password        = var.admin_password
  network_interface_ids = [azurerm_network_interface.dc01.id]
  provision_vm_agent    = true
  tags                  = local.tags

  os_disk {
    name                 = "osdisk-dc01"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = var.windows_server_sku
    version   = "latest"
  }
}

resource "azurerm_windows_virtual_machine" "winclient01" {
  name                  = "winclient01"
  computer_name         = "winclient01"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  size                  = var.client_vm_size
  admin_username        = var.admin_username
  admin_password        = var.admin_password
  network_interface_ids = [azurerm_network_interface.winclient01.id]
  provision_vm_agent    = true
  tags                  = local.tags

  os_disk {
    name                 = "osdisk-winclient01"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = var.windows_server_sku
    version   = "latest"
  }
}

resource "azurerm_role_assignment" "lab_groups" {
  for_each = {
    for name, assignment in local.rbac_assignments : name => assignment
    if assignment.principal_id != null && assignment.principal_id != ""
  }

  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = each.value.principal_id
  principal_type       = "Group"
}
