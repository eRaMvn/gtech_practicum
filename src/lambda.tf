data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iam_keeper_event_handler_lambda_role" {
  name                = "iam_keeper_event_handler_role"
  assume_role_policy  = data.aws_iam_policy_document.lambda_assume_role_policy.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
  inline_policy {
    name = "lambda_policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "S3:Get*",
            "S3:Put*",
            "S3:List*",
          ]
          Effect = "Allow"
          Resource = [
            "arn:aws:s3:::${var.s3_bucket_name}/*",
            "arn:aws:s3:::${var.s3_bucket_name}"
          ]
        },
      ]
    })
  }
}

resource "aws_lambda_function" "iam_event_handler_func" {
  function_name = "iam_keeper_event_handler"
  role          = aws_iam_role.iam_keeper_event_handler_lambda_role.arn
  image_uri     = "014824332634.dkr.ecr.us-east-1.amazonaws.com/iam_keeper_event_handler:${var.image_tag}"
  package_type  = "Image"
  depends_on    = [aws_iam_role.iam_keeper_event_handler_lambda_role]
}
