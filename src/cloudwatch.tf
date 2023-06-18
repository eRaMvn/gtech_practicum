resource "aws_cloudwatch_event_rule" "iam_keeper_event_handler_rule" {
  name        = "iam_keeper_event_handler_rule"
  description = "IAM event rule to trigger iam_keeper lambda"

  event_pattern = <<EOF
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"]
  }
}
EOF
}

resource "aws_lambda_permission" "lambda_perm_for_event_handler" {
  statement_id  = "AllowExecutionFromCloudWatchEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_event_handler_func.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_keeper_event_handler_rule.arn
}

resource "aws_cloudwatch_event_target" "iam_keeper_event_handler_target" {
  rule      = aws_cloudwatch_event_rule.iam_keeper_event_handler_rule.name
  target_id = "iam_keeper_event_handler_lambda_target"
  arn       = aws_lambda_function.iam_event_handler_func.arn
}

resource "aws_cloudwatch_event_rule" "policy_snapshot_cron" {
  name                = "policy_snapshot_cron"
  description         = "Cron event rule for policy snapshot"
  schedule_expression = "cron(0 7 * * ? *)"
}

resource "aws_lambda_permission" "policy_snapshot_lambda_perm" {
  statement_id  = "AllowExecutionFromCloudWatchEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_policy_snapshot_func.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.policy_snapshot_cron.arn
}

resource "aws_cloudwatch_event_target" "policy_snapshot_lambda_target" {
  rule      = aws_cloudwatch_event_rule.policy_snapshot_cron.name
  target_id = "policy_snapshot_lambda_target"
  arn       = aws_lambda_function.iam_policy_snapshot_func.arn
}
