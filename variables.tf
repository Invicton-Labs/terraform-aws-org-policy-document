variable "actions" {
  description = "A list of IAM actions that the policy applies to."
  type        = list(string)
  default     = []
}

variable "not_actions" {
  description = "A list of IAM actions that the policy does not apply to."
  type        = list(string)
  default     = []
}

variable "effect" {
  description = "The effect for the policy to have (`Allow` or `Deny`)."
  type        = string
  default     = "Allow"
  validation {
    condition     = var.effect == null || contains(["Allow", "Deny"], var.effect)
    error_message = "The `effect` input variable must be `Allow` or `Deny`."
  }
}

variable "resources" {
  description = "An optional list of resources that this policy applies to."
  type        = list(string)
  default     = []
}

variable "not_resources" {
  description = "An optional list of resources that this policy does not apply to."
  type        = list(string)
  default     = []
}

variable "principals" {
  description = "An optional list of principals (other than those defined in the `org_principals` input variable) that this policy applies to."
  type = list(object({
    type        = string
    identifiers = list(string)
  }))
  default = []
  validation {
    condition     = var.principals == null || length([for principal in var.principals : true if principal.type == null || principal.identifiers == null]) == 0
    error_message = "Neither the `type` nor `identifiers` field of any element in the `principals` input variable may be `null`."
  }
}

variable "not_principals" {
  description = "An optional list of principals that this policy does not apply to."
  type = list(object({
    type        = string
    identifiers = list(string)
  }))
  default = []
  validation {
    condition     = var.not_principals == null || length([for principal in var.not_principals : true if principal.type == null || principal.identifiers == null]) == 0
    error_message = "Neither the `type` nor `identifiers` field of any element in the `not_principals` input variable may be `null`."
  }
}

variable "conditions" {
  description = "An optional list of conditions to include in the policy."
  type = list(object({
    test     = string
    values   = list(string)
    variable = string
  }))
  default = []
  validation {
    condition     = var.conditions == null || length([for condition in var.conditions : true if condition.test == null || condition.values == null || condition.variable == null]) == 0
    error_message = "None of the `test`, `values`, `variable` fields of any element in the `conditions` input variable may be `null`."
  }
}

variable "sid" {
  description = "An optional statement ID to include in each statement of the policy (with unique suffixes)."
  type        = string
  default     = null
}

variable "org_principals" {
  description = <<EOF
A list of Organization resource identifiers to grant access to. Each element is an object with a `entity_id` value (an Organization ID, an Organizational Unit ID, or an Account ID) and an `iam_types` value.

If `delegation_required` is `true`, then permission will be granted to the root user of the given account (arn:aws:iam::ACCOUNT_ID:root). If it is `false`, then permission will be granted to any IAM entity (users, roles, groups, etc.) within that Organization/OU/Account."
EOF
  type = list(object({
    entity_id           = string
    delegation_required = bool
  }))
  validation {
    condition     = var.org_principals == null || length([for principal in var.org_principals : true if principal.entity_id == null || principal.delegation_required == null]) == 0
    error_message = "Neither the `entity_id` nor `delegation_required` field of any element in the `org_principals` input variable may be `null`."
  }
  validation {
    condition     = var.org_principals == null || length([for principal in var.org_principals : true if length(regexall("/", principal.entity_id)) > 0]) == 0
    error_message = "The `entity_id` fields may not contain the `/` character. For Organizations and Organizational Units, this field should be the Organization/OU ID, not the Organization root path or the full OU path."
  }
}

variable "source_policy_documents" {
  description = "A list of IAM policy documents that are merged together into the exported document. Statements generated by this module will overwrite statements with the same SID in these source documents."
  type        = list(string)
  default     = []
}

variable "override_policy_documents" {
  description = "A list of IAM policy documents that are merged together into the exported document. Statements generated by this module will be overwritten by statements with the same SID in these override documents."
  type        = list(string)
  default     = []
}

// This sets default values for variables that are provided as `null`
locals {
  actions                   = var.actions == null ? null : length(var.actions) == 0 ? null : var.actions
  not_actions               = var.not_actions == null ? null : length(var.not_actions) == 0 ? null : var.not_actions
  effect                    = var.effect == null ? "Allow" : var.effect
  resources                 = var.resources == null ? null : length(var.resources) == 0 ? null : var.resources
  not_resources             = var.not_resources == null ? null : length(var.not_resources) == 0 ? null : var.not_resources
  principals                = var.principals == null ? [] : var.principals
  not_principals            = var.not_principals == null ? [] : var.not_principals
  conditions                = var.not_principals == null ? [] : var.conditions
  org_principals            = var.org_principals == null ? [] : var.org_principals
  source_policy_documents   = var.source_policy_documents == null ? [] : var.source_policy_documents
  override_policy_documents = var.override_policy_documents == null ? [] : var.override_policy_documents
}

module "assert_action_present" {
  source        = "Invicton-Labs/assertion/null"
  version       = "~> 0.2.1"
  condition     = local.actions != null || local.not_actions != null
  error_message = "Either the `actions` or `not_actions` input variable must have at least one element."
}
