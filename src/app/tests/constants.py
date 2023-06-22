TEST_ROLE_NAME = "test_iam_keeper_role"
TEST_USER_NAME = "test_iam_keeper_user"
TEST_POLICIES = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
]
TEST_MANAGED_POLICY_NAME = "test_managed_policy"
TEST_MANAGED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1234567890123",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "*",
        }
    ],
}
TEST_INLINE_POLICY_NAME = "test_inline_policy"
TEST_INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example-bucket/*",
        }
    ],
}
DESIGNATED_ROLE_NAME = "thor"
MALICIOUS_ROLE_NAME = "loki"
INTEGRATION_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
CASE_1_ROLE_NAME = "case_1_role"
CASE_2_ROLE_NAME = "case_2_role"
CASE_3_ROLE_NAME = "case_3_role"
