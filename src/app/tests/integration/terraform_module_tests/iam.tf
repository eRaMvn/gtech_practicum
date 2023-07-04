module "iam_assumable_roles" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"

  role_name   = "iam_keeper_anton_should_be_deleted_role1"
  create_role = true
  trusted_role_arns = [
    "arn:aws:iam::${var.account_id}:root",
  ]
}

data "aws_iam_policy_document" "base" {
  statement {
    sid = "BaseAccess"

    actions = [
      "s3:ListBucket",
      "s3:ListBucketVersions"
    ]

    resources = ["arn:aws:s3:::bucketname"]
    effect    = "Allow"
  }
}

module "role" {
  source = "cloudposse/iam-role/aws"

  enabled = true
  name    = "iam_keeper_posse_should_be_deleted_role2"

  policy_description = "Allow S3 FullAccess"
  role_description   = "IAM role with permissions to perform actions on S3 resources"

  principals = {
    AWS = ["arn:aws:iam::${var.account_id}:root"]
  }
  policy_documents = [
    data.aws_iam_policy_document.base.json
  ]
}
