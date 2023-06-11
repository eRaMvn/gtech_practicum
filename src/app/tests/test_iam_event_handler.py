import json
import os

import boto3

from app.iam_event_handler.constants import BUCKET_NAME, WHITELISTED_IAM_USERS_VARIABLE
from app.iam_event_handler.record import IAMPolicy, record
from app.iam_event_handler.remediate import get_managed_policies_for_role, remediate
from app.iam_event_handler.utils import (
    IdentityType,
    extract_principal,
    extract_whitelisted_principals,
    is_whitelisted_principal,
)

from .constants import (
    TEST_INLINE_POLICY,
    TEST_INLINE_POLICY_NAME,
    TEST_MANAGED_POLICY,
    TEST_MANAGED_POLICY_NAME,
    TEST_ROLE_NAME,
)
from .events import (
    ATTACH_ROLE_POLICY_EVENT,
    CREATE_POLICY_VERSION_EVENT,
    CREATE_ROLE_EVENT,
    DETACH_ROLE_POLICY_EVENT,
    EVENT_FROM_ASSUME_ROLE,
    PUT_ROLE_POLICY_EVENT,
)
from .utils import (
    create_iam_role,
    create_managed_policy,
    create_role_with_inline_policies,
    create_role_with_managed_policies,
    get_current_managed_policy,
    updated_managed_policy,
)


def test_extract_principal():
    principal_type, principal_name = extract_principal(EVENT_FROM_ASSUME_ROLE)
    assert principal_type == IdentityType.ASSUMED_ROLE
    assert principal_name == "thor"

    principal_type, principal_name = extract_principal(ATTACH_ROLE_POLICY_EVENT)
    assert principal_type == IdentityType.IAM_USER
    assert principal_name == "john.doe"


def test_extract_white_listed_principals(monkeypatch):
    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()
    assert whitelisted_users == set(["thor", "odin"])
    assert whitelisted_roles == set(["thor", "odin"])

    # Define the mock environment variable
    mock_env = {WHITELISTED_IAM_USERS_VARIABLE: "zeus|athena"}

    # Mock os.environ with the mock_env dictionary
    monkeypatch.setattr(os, "environ", mock_env)

    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()
    assert whitelisted_users == set(["zeus", "athena"])
    assert whitelisted_roles == set(["thor", "odin"])


def test_is_whitelisted_principal():
    principal_type, principal_name = extract_principal(EVENT_FROM_ASSUME_ROLE)
    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()
    assert (
        is_whitelisted_principal(
            principal_name, principal_type, whitelisted_users, whitelisted_roles
        )
        is True
    )


def test_upload_managed_policies_list_to_s3(iam_client, s3_client):
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    iam_guide = IAMPolicy()

    create_iam_role(iam_client)
    test_policy_arn = create_managed_policy(iam_client)
    iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn)

    s3_client.create_bucket(Bucket=BUCKET_NAME)
    managed_policies_list_path = iam_guide.get_s3_managed_policies_list_path(
        TEST_ROLE_NAME
    )

    record(updated_event)
    response = s3_client.get_object(Bucket=BUCKET_NAME, Key=managed_policies_list_path)

    assert json.loads(response["Body"].read().decode("utf-8")) == [
        f"arn:aws:iam::123456789012:policy/{TEST_MANAGED_POLICY_NAME}"
    ]


def test_upload_managed_policies_to_s3(iam_client, s3_client):
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    iam_guide = IAMPolicy()

    create_iam_role(iam_client)
    test_policy_arn = create_managed_policy(iam_client)
    test_policy_name = test_policy_arn.split("/")[-1]
    iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn)

    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_path = iam_guide.get_s3_managed_path(test_policy_name)

    record(updated_event)
    response = s3_client.get_object(Bucket=BUCKET_NAME, Key=s3_path)

    assert json.loads(response["Body"].read().decode("utf-8")) == TEST_MANAGED_POLICY


def test_upload_inline_policies_to_s3(iam_client, s3_client):
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    updated_event["detail"]["requestParameters"]["policyName"] = TEST_INLINE_POLICY_NAME
    iam_guide = IAMPolicy()

    create_role_with_inline_policies(iam_client)

    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_path = iam_guide.get_s3_inline_path(TEST_ROLE_NAME, TEST_INLINE_POLICY_NAME)

    record(updated_event)
    response = s3_client.get_object(Bucket=BUCKET_NAME, Key=s3_path)

    assert json.loads(response["Body"].read().decode("utf-8")) == TEST_INLINE_POLICY


def test_remediate_create_role_with_managed_policy(iam_client):
    # Update event to have the test role name
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME

    create_role_with_managed_policies(iam_client)
    managed_policy_arns = get_managed_policies_for_role(TEST_ROLE_NAME, iam_client)
    assert len(managed_policy_arns) == 2

    remediate(updated_event)
    roles_response = iam_client.list_roles()
    roles = roles_response["Roles"]
    assert len(roles) == 0


def test_remediate_update_role_by_adding_attach_managed_policy(iam_client):
    updated_event = ATTACH_ROLE_POLICY_EVENT

    test_policy = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy
    iam_client = boto3.client("iam")

    create_iam_role(iam_client)
    iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=test_policy)
    managed_policy_arns = get_managed_policies_for_role(TEST_ROLE_NAME, iam_client)
    assert len(managed_policy_arns) == 1

    remediate(updated_event)
    managed_policy_arns = get_managed_policies_for_role(TEST_ROLE_NAME, iam_client)
    assert len(managed_policy_arns) == 0


def test_remediate_update_role_by_detaching_managed_policy(iam_client):
    updated_event = DETACH_ROLE_POLICY_EVENT
    test_policy = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy

    iam_client = boto3.client("iam")

    create_role_with_managed_policies(iam_client)
    managed_policy_arns = get_managed_policies_for_role(TEST_ROLE_NAME, iam_client)
    assert len(managed_policy_arns) == 2

    remediate(updated_event)
    managed_policy_arns = get_managed_policies_for_role(TEST_ROLE_NAME, iam_client)
    assert len(managed_policy_arns) == 3


def test_remediate_update_managed_policy_assigned_to_a_role(iam_client):
    updated_event = CREATE_POLICY_VERSION_EVENT
    iam_client = boto3.client("iam")
    test_policy_arn = create_managed_policy(iam_client)
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy_arn

    create_iam_role(iam_client)
    iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn)

    updated_managed_policy(iam_client, test_policy_arn)
    current_managed_policy = get_current_managed_policy(iam_client, test_policy_arn)
    assert len(current_managed_policy["Statement"][0]["Action"]) == 3

    remediate(updated_event)
    current_managed_policy = get_current_managed_policy(iam_client, test_policy_arn)
    assert len(current_managed_policy["Statement"][0]["Action"]) == 2


def test_remediate_create_a_role_with_inline_policy(iam_client):
    updated_event = PUT_ROLE_POLICY_EVENT
    iam_client = boto3.client("iam")
    create_role_with_inline_policies(iam_client)

    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    updated_event["detail"]["requestParameters"]["policyName"] = TEST_INLINE_POLICY_NAME

    response = iam_client.list_role_policies(RoleName=TEST_ROLE_NAME)
    assert len(response["PolicyNames"]) == 1

    remediate(updated_event)

    response = iam_client.list_role_policies(RoleName=TEST_ROLE_NAME)
    assert len(response["PolicyNames"]) == 0
