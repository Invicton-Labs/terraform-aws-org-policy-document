locals {
  organizations_delegation_required = [
    for principal in local.org_principals :
    principal.entity_id
    if substr(principal.entity_id, 0, 2) == "o-" && principal.delegation_required
  ]
  organizations_delegation_not_required = [
    for principal in local.org_principals :
    principal.entity_id
    if substr(principal.entity_id, 0, 2) == "o-" && !principal.delegation_required
  ]
  organizational_units_delegation_required = [
    for principal in local.org_principals :
    principal.entity_id
    if substr(principal.entity_id, 0, 3) == "ou-" && principal.delegation_required
  ]
  organizational_units_delegation_not_required = [
    for principal in local.org_principals :
    principal.entity_id
    if substr(principal.entity_id, 0, 3) == "ou-" && !principal.delegation_required
  ]
  accounts_delegation_required = [
    for principal in local.org_principals :
    principal.entity_id
    if can(tonumber(principal.entity_id)) && principal.delegation_required
  ]
  accounts_delegation_not_required = [
    for principal in local.org_principals :
    principal.entity_id
    if can(tonumber(principal.entity_id)) && !principal.delegation_required
  ]
  uncategorized_entity_ids = [
    for principal in local.org_principals :
    principal.entity_id
    if
    !contains(local.organizations_delegation_required, principal.entity_id) && !contains(local.organizations_delegation_not_required, principal.entity_id) &&
    !contains(local.organizational_units_delegation_required, principal.entity_id) && !contains(local.organizational_units_delegation_not_required, principal.entity_id) &&
    !contains(local.accounts_delegation_required, principal.entity_id) && !contains(local.accounts_delegation_not_required, principal.entity_id)
  ]
}

module "assert_all_entities_categorized" {
  source        = "Invicton-Labs/assertion/null"
  version       = "~> 0.2.1"
  condition     = length(local.uncategorized_entity_ids) == 0
  error_message = "The following entities could not be identified as Organization, Organizational Unit, or AWS Account IDs: ${join(", ", local.uncategorized_entity_ids)}."
}

data "aws_iam_policy_document" "this" {
  // Check the assertions first
  depends_on = [
    module.assert_action_present,
    module.assert_all_entities_categorized,
  ]

  // Add the source/override documents
  source_policy_documents   = local.source_policy_documents
  override_policy_documents = local.override_policy_documents

  // This statement grants to principals that are explicitly specified
  dynamic "statement" {
    for_each = length(local.principals) > 0 ? [1] : []
    content {
      sid           = var.sid
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant access directly to explicitly specified principals
      dynamic "principals" {
        for_each = local.principals
        content {
          type        = principals.value.type
          identifiers = principals.value.identifiers
        }
      }
    }
  }

  // This statement grants permissions to the AWS accounts, to the root user
  dynamic "statement" {
    for_each = length(local.accounts_delegation_required) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}AccountsDelegationRequired" : null
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant the account roots access as principals
      principals {
        type = "AWS"
        identifiers = [
          for account_id in local.accounts_delegation_required :
          "arn:aws:iam::${account_id}:root"
        ]
      }
    }
  }

  // This statement grants permissions to all IAM entities within the specified AWS accounts
  dynamic "statement" {
    for_each = length(local.accounts_delegation_not_required) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}AccountsDelegationNotRequired" : null
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant all AWS principals access. Access is restricted with the condition key below.
      principals {
        type = "AWS"
        identifiers = [
          "*"
        ]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalAccount"
        values   = local.accounts_delegation_not_required
      }
    }
  }

  // This statement grants permissions to the roots of all accounts in the specified Organizations
  dynamic "statement" {
    for_each = length(local.organizations_delegation_required) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}OrganizationsDelegationRequired" : null
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant access to all account roots
      principals {
        type = "AWS"
        identifiers = [
          "*"
        ]
      }
      // Restrict it to accounts in the organization
      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = local.organizations_delegation_required
      }
      // Restrict it to account roots (they can then delegate within their account)
      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalType"
        values = [
          "Account"
        ]
      }
    }
  }

  // This statement grants permissions to all IAM entities in the specified Organizations
  dynamic "statement" {
    for_each = length(local.organizations_delegation_not_required) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}OrganizationsDelegationNotRequired" : null
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant access to all IAM entities
      principals {
        type = "AWS"
        identifiers = [
          "*"
        ]
      }
      // Restrict it to accounts in the organization
      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = local.organizations_delegation_not_required
      }
    }
  }

  // This statement grants permissions to the roots of all accounts in the specified Organizational Units
  dynamic "statement" {
    for_each = length(local.organizational_units_delegation_required) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}OrganizationalUnitsDelegationRequired" : null
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant access to all IAM entities
      principals {
        type = "AWS"
        identifiers = [
          "*"
        ]
      }
      // Restrict it to accounts in the organization
      condition {
        test     = "ForAnyValue:StringLike"
        variable = "aws:PrincipalOrgPaths"
        values = [
          // OU IDs are globally unique, so it's safe to do this without knowing anything
          // about the Organization structure (org ID, root ID, parent OU IDs, etc.).
          for ou_id in local.organizational_units_delegation_required :
          "*/${ou_id}/*"
        ]
      }
      // Restrict it to account roots (they can then delegate within their account)
      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalType"
        values = [
          "Account"
        ]
      }
    }
  }

  // This statement grants permissions to all IAM entities in the specified Organizational Units
  dynamic "statement" {
    for_each = length(local.organizational_units_delegation_not_required) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}OrganizationalUnitsDelegationNotRequired" : null
      effect        = local.effect
      actions       = local.actions
      not_actions   = local.not_actions
      resources     = local.resources
      not_resources = local.not_resources
      dynamic "not_principals" {
        for_each = local.not_principals
        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }
      dynamic "condition" {
        for_each = local.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }

      // Grant access to all IAM entities
      principals {
        type = "AWS"
        identifiers = [
          "*"
        ]
      }
      // Restrict it to accounts in the organization
      condition {
        test     = "ForAnyValue:StringLike"
        variable = "aws:PrincipalOrgPaths"
        values = [
          // OU IDs are globally unique, so it's safe to do this without knowing anything
          // about the Organization structure (org ID, root ID, parent OU IDs, etc.).
          for ou_id in local.organizational_units_delegation_not_required :
          "*/${ou_id}/*"
        ]
      }
    }
  }
}
