resource "azurerm_policy_definition" "required_tags" {
  for_each = var.enable_required_tag_policy ? var.required_tag_names : toset([])

  name         = "require-tag-${each.value}-${var.environment}"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Require ${each.value} tag for ${var.resource_prefix}"
  description  = "Deny resources in the lab scope when the ${each.value} tag is missing."

  metadata = jsonencode({
    category = "Tags"
    nist_csf = "GV.OC,ID.AM"
  })

  policy_rule = jsonencode({
    if = {
      field  = "tags['${each.value}']"
      exists = "false"
    }
    then = {
      effect = "deny"
    }
  })
}

resource "azurerm_resource_group_policy_assignment" "required_tags" {
  for_each = azurerm_policy_definition.required_tags

  name                 = "require-tag-${each.key}"
  resource_group_id    = azurerm_resource_group.main.id
  policy_definition_id = each.value.id
  display_name         = "Require ${each.key} tag"
  description          = "NIST CSF lab guardrail requiring the ${each.key} tag in the lab resource group."
}
