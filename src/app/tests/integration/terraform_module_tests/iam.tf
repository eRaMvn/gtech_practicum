module "iam_assumable_roles" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"

  role_name   = "antonbenko-iam-test_role"
  create_role = true
  trusted_role_arns = [
    "arn:aws:iam::${var.account_id}:root",
  ]
}

module "role" {
  source = "cloudposse/iam-role/aws"

  enabled = true
  name    = "cloudposse-iam-test-role"

  policy_description = "Allow S3 FullAccess"
  role_description   = "IAM role with permissions to perform actions on S3 resources"

  principals = {
    AWS = ["arn:aws:iam::${var.account_id}:root"]
  }
}
