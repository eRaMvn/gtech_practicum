import json

from .constants import (
    TEST_INLINE_POLICY,
    TEST_INLINE_POLICY_NAME,
    TEST_MANAGED_POLICY,
    TEST_MANAGED_POLICY_NAME,
    TEST_POLICIES,
    TEST_ROLE_NAME,
)


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


def create_role_with_managed_policies(iam_client):
    create_iam_role(iam_client)

    # Attach managed policies to the role
    for policy_arn in TEST_POLICIES:
        iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=policy_arn)


def create_role_with_inline_policies(iam_client):
    create_iam_role(iam_client)
    iam_client.put_role_policy(
        RoleName=TEST_ROLE_NAME,
        PolicyName=TEST_INLINE_POLICY_NAME,
        PolicyDocument=json.dumps(TEST_INLINE_POLICY),
    )


def create_managed_policy(iam_client):
    response = iam_client.create_policy(
        PolicyName=TEST_MANAGED_POLICY_NAME,
        PolicyDocument=json.dumps(TEST_MANAGED_POLICY),
    )

    return response["Policy"]["Arn"]


def updated_managed_policy(iam_client, policy_arn):
    response = iam_client.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Stmt1234567890123",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ],
                    "Resource": "*"
                }
            ]
        }""",
        SetAsDefault=True,
    )

    return response["PolicyVersion"]["VersionId"]


def get_current_managed_policy(iam_client, policy_arn):
    response = iam_client.get_policy(PolicyArn=policy_arn)
    policy_document = response["Policy"]["DefaultVersionId"]

    response = iam_client.get_policy_version(
        PolicyArn=policy_arn, VersionId=policy_document
    )
    policy_doc = response["PolicyVersion"]["Document"]
    return policy_doc
