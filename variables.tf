variable "actions" {
  description = "A list of IAM actions that the policy applies to."
  type        = list(string)
  default     = []
}
locals {
  actions = var.actions == null ? null : length(var.actions) == 0 ? null : var.actions
}

variable "not_actions" {
  description = "A list of IAM actions that the policy does not apply to."
  type        = list(string)
  default     = []
}
locals {
  not_actions = var.not_actions == null ? null : length(var.not_actions) == 0 ? null : var.not_actions
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
locals {
  effect = var.effect == null ? "Allow" : var.effect
}

variable "resources" {
  description = "An optional list of resources that this policy applies to."
  type        = list(string)
  default     = []
}
locals {
  resources = var.resources == null ? null : length(var.resources) == 0 ? null : var.resources
}

variable "not_resources" {
  description = "An optional list of resources that this policy does not apply to."
  type        = list(string)
  default     = []
}
locals {
  not_resources = var.not_resources == null ? null : length(var.not_resources) == 0 ? null : var.not_resources
}

variable "principals" {
  description = "An optional list of principals (other than those defined in the `org_entities` input variable) that this policy applies to."
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
locals {
  principals = var.principals == null ? [] : var.principals
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
locals {
  not_principals = var.not_principals == null ? [] : var.not_principals
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
locals {
  conditions = var.not_principals == null ? [] : var.conditions
}

variable "sid" {
  description = "An optional statement ID to include in each statement of the policy (with unique suffixes)."
  type        = string
  default     = null
}

variable "organization_id" {
  description = "The ID of the AWS Organization that all Organizational Units that are specified in `org_identities` must be under. If this value is not specified, but an Organizational Unit ID is specified in `org_identities`, this module will throw an error."
  type        = string
  default     = null
}

variable "org_entities" {
  description = "A list of Organization resource identifiers to grant access to. Each element must be an Organization ID, an Organizational Unit ID, or an Account ID."
  type        = list(any)
  validation {
    condition = var.org_entities == null ? true : length([for principal in var.org_entities : true if(
      // If it can be converted to a number, it might be an AWS account number, so it's good
      can(tonumber(principal)) ? false : (
        // Otherwise, if it can't be converted to a string, it's invalid
        !can(tostring(principal)) ? true : (
          // It can be converted to a string, but not a number, so it's probably an Org/Root/OU ID, so check each
          !(substr(tostring(principal), 0, 2) == "o-" || substr(tostring(principal), 0, 2) == "r-" || substr(tostring(principal), 0, 3) == "ou-")
        )
      )
    )]) == 0
    error_message = "Each element of the `org_entities` input variable must be an AWS account ID, an Organization ID (string starting with \"o-\"), an Organization Root ID (string starting with \"r-\"), or an Organizational Unit ID (string starting with \"ou-\")."
  }
  validation {
    condition     = var.org_entities == null ? true : length([for principal in var.org_entities : true if !can(tostring(principal)) ? false : length(regexall("/", tostring(principal))) > 0]) == 0
    error_message = "The `entity_id` fields may not contain the `/` character. For Organizations and Organizational Units, this field should be the Organization/OU ID, not the Organization root path or the full OU path."
  }
}
locals {
  org_entities = var.org_entities == null ? [] : var.org_entities
}

variable "source_policy_documents" {
  description = "A list of IAM policy documents that are merged together into the exported document. Statements generated by this module will overwrite statements with the same SID in these source documents."
  type        = list(string)
  default     = []
}
locals {
  source_policy_documents = var.source_policy_documents == null ? [] : var.source_policy_documents
}

variable "override_policy_documents" {
  description = "A list of IAM policy documents that are merged together into the exported document. Statements generated by this module will be overwritten by statements with the same SID in these override documents."
  type        = list(string)
  default     = []
}
locals {
  override_policy_documents = var.override_policy_documents == null ? [] : var.override_policy_documents
}

module "assert_action_present" {
  source        = "Invicton-Labs/assertion/null"
  version       = "~> 0.2.1"
  condition     = local.actions != null || local.not_actions != null
  error_message = "Either the `actions` or `not_actions` input variable must have at least one element."
}
