# Terraform AWS Organization Policy Document

This module generates an IAM policy document that grants permissions to various Organization-based entities. It accepts all of the variables that the `aws_iam_policy_document` data source accepts, but saves you a lot of work in needing to customize policies for multiple different types of entities that you want to share with.

The policies created by this module can be used either as resource policies or trust policies (i.e. things that specify a `Principal`).

You can provide it with a list that can include Organization IDs, Organizational Unit IDs, or Account IDs, and it will automatically generate a policy that shares with all of them. The policy grants accounts that are in one one of the specified Organizations or Organizational Units, or that are specified explicitly as an Account ID, the ability to grant IAM entities *in that account* the permissions in the policy (delegated permissions). Even in the account that "owns" the resource that the policy is applied to, this requirement still stands (i.e. if Account 1234 owns a resource, and a policy from this module is used and "1234" is specified in the `org_entities` variable, IAM entities in account "1234" will still need IAM Policies that grant the permissions).
