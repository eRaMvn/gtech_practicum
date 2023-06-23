import json

from app.lambda_func.use_cases.iam import IAMType
from app.lambda_func.use_cases.remediate import get_managed_policies_for_principal

from .constants import (
    TEST_INLINE_POLICY,
    TEST_INLINE_POLICY_NAME,
    TEST_POLICIES,
    TEST_ROLE_NAME,
    TEST_USER_NAME,
)


def create_iam_role(iam_client, role_name=TEST_ROLE_NAME):
    # Create the IAM role
    response = iam_client.create_role(
        RoleName=role_name,
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


def create_role_with_managed_policies(iam_client, role_name=TEST_ROLE_NAME):
    create_iam_role(iam_client, role_name)

    # Attach managed policies to the role
    for policy_arn in TEST_POLICIES:
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def create_role_with_inline_policies(iam_client):
    create_iam_role(iam_client)
    iam_client.put_role_policy(
        RoleName=TEST_ROLE_NAME,
        PolicyName=TEST_INLINE_POLICY_NAME,
        PolicyDocument=json.dumps(TEST_INLINE_POLICY),
    )


def create_iam_user(iam_client):
    iam_client.create_user(UserName=TEST_USER_NAME)


def create_user_with_managed_policies(iam_client):
    create_iam_user(iam_client)

    # Attach managed policies to the role
    for policy_arn in TEST_POLICIES:
        iam_client.attach_user_policy(UserName=TEST_USER_NAME, PolicyArn=policy_arn)


def create_user_with_inline_policies(iam_client):
    create_iam_user(iam_client)
    iam_client.put_user_policy(
        UserName=TEST_USER_NAME,
        PolicyName=TEST_INLINE_POLICY_NAME,
        PolicyDocument=json.dumps(TEST_INLINE_POLICY),
    )


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


def validate_principal_is_deleted(
    principal_name: str, principal_type: IAMType, iam_client
):
    if principal_type == IAMType.ROLE:
        roles_response = iam_client.list_roles()
        roles = roles_response["Roles"]
        assert principal_name not in {role["RoleName"] for role in roles}
    else:
        iam_user_response = iam_client.list_users()
        users = iam_user_response["Users"]
        assert principal_name not in {user["UserName"] for user in users}


def validate_managed_policy_is_detached(
    principal_name: str, principal_type: IAMType, policy_arn: str, iam_client
):
    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, iam_client
    )
    assert policy_arn not in managed_policy_arns


def validate_managed_policy_is_attached(
    principal_name: str, principal_type: IAMType, policy_arn: str, iam_client
):
    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, iam_client
    )
    assert policy_arn in managed_policy_arns


def validate_inline_policy_is_attached(
    principal_name: str, principal_type: IAMType, inline_policy_name: str, iam_client
):
    if principal_type == IAMType.ROLE:
        response = iam_client.list_role_policies(RoleName=principal_name)
    else:
        response = iam_client.list_user_policies(UserName=principal_name)

    assert inline_policy_name in response["PolicyNames"]


def validate_inline_policy_is_not_attached(
    principal_name: str, principal_type: IAMType, inline_policy_name: str, iam_client
):
    if principal_type == IAMType.ROLE:
        response = iam_client.list_role_policies(RoleName=principal_name)
    else:
        response = iam_client.list_user_policies(UserName=principal_name)

    assert inline_policy_name not in response["PolicyNames"]
