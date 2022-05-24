locals {
  organizations = [
    for principal in local.org_entities :
    principal
    if substr(principal, 0, 2) == "o-"
  ]
  organizational_units = [
    for principal in local.org_entities :
    principal
    if substr(principal, 0, 3) == "ou-"
  ]
  accounts = [
    for principal in local.org_entities :
    principal
    if can(tonumber(principal))
  ]
  uncategorized_entity_ids = [
    for principal in local.org_entities :
    principal
    if
    !contains(local.organizations, principal) &&
    !contains(local.organizational_units, principal) &&
    !contains(local.accounts, principal)
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

  // This statement grants permissions to the roots of all accounts in the specified Organizations
  dynamic "statement" {
    for_each = length(local.organizations) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}Organizations" : null
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
        values   = local.organizations
      }
      // Don't grant this permission on the owner account. If we do,
      // then all IAM entities in the owner account will have access,
      // even if they don't have a policy to do so. That would be insecure.
      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceAccount"
        values = [
          "$${aws:PrincipalAccount}"
        ]
      }
    }
  }

  // This statement grants permissions to the roots of all accounts in the specified Organizational Units
  dynamic "statement" {
    for_each = length(local.organizational_units) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}OrganizationalUnits" : null
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
          for ou_id in local.organizational_units :
          "*/${ou_id}/*"
        ]
      }
      // Don't grant this permission on the owner account. If we do,
      // then all IAM entities in the owner account will have access,
      // even if they don't have a policy to do so. That would be insecure.
      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceAccount"
        values = [
          "$${aws:PrincipalAccount}"
        ]
      }
    }
  }

  // This statement grants permissions to the AWS accounts, to the root user
  dynamic "statement" {
    for_each = length(local.accounts) > 0 ? [1] : []
    content {
      sid           = var.sid != null ? "${var.sid}Accounts" : null
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
      // Don't grant this permission on the owner account. If we do,
      // then all IAM entities in the owner account will have access,
      // even if they don't have a policy to do so. That would be insecure.
      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceAccount"
        values = [
          "$${aws:PrincipalAccount}"
        ]
      }
    }
  }
}
