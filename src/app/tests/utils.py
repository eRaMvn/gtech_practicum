import boto3

from .constants import TEST_ROLE_NAME


def create_iam_role(iam_client):
    # Create the IAM role
    response = iam_client.create_role(
        RoleName=TEST_ROLE_NAME,
        AssumeRolePolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }""",
    )

    return response["Role"]["Arn"]


def create_role_with_managed_policies():
    managed_policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
    ]
    iam_client = boto3.client("iam")
    create_iam_role(iam_client)

    # Attach managed policies to the role
    for policy_arn in managed_policy_arns:
        iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=policy_arn)
