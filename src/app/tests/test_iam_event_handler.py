import json
import os

import pytest

from app.lambda_func.use_cases import (
    EventName,
    IdentityType,
    extract_principal,
    extract_whitelisted_principals,
    is_whitelisted_principal,
)
from app.lambda_func.use_cases.constants import (
    BUCKET_NAME,
    WHITELISTED_IAM_USERS_VARIABLE,
)
from app.lambda_func.use_cases.iam import IAMPolicy, IAMType, create_managed_policy
from app.lambda_func.use_cases.record import record
from app.lambda_func.use_cases.remediate import (
    get_managed_policies_for_principal,
    remediate,
)
from app.lambda_func.use_cases.s3 import upload_file_to_s3

from .constants import (
    TEST_INLINE_POLICY,
    TEST_INLINE_POLICY_NAME,
    TEST_MANAGED_POLICY,
    TEST_MANAGED_POLICY_NAME,
    TEST_ROLE_NAME,
    TEST_USER_NAME,
)
from .events import (
    ATTACH_ROLE_POLICY_EVENT,
    CREATE_POLICY_VERSION_EVENT,
    CREATE_ROLE_EVENT,
    DELETE_ROLE_POLICY_EVENT,
    DETACH_ROLE_POLICY_EVENT,
    EVENT_FROM_ASSUME_ROLE,
    PUT_ROLE_POLICY_EVENT,
)
from .utils import (
    create_iam_role,
    create_iam_user,
    create_role_with_inline_policies,
    create_role_with_managed_policies,
    create_user_with_inline_policies,
    create_user_with_managed_policies,
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
    assert whitelisted_users == set(["thor", "odin", "thien"])
    assert whitelisted_roles == set(["thor", "odin", "terraform_cloud_role"])

    # Define the mock environment variable
    mock_env = {WHITELISTED_IAM_USERS_VARIABLE: "zeus|athena"}

    # Mock os.environ with the mock_env dictionary
    monkeypatch.setattr(os, "environ", mock_env)

    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()
    assert whitelisted_users == set(["zeus", "athena"])
    assert whitelisted_roles == set(["thor", "odin", "terraform_cloud_role"])


def test_is_whitelisted_principal():
    principal_type, principal_name = extract_principal(EVENT_FROM_ASSUME_ROLE)
    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()
    assert (
        is_whitelisted_principal(
            principal_name, principal_type, whitelisted_users, whitelisted_roles
        )
        is True
    )


def test_upload_managed_policies_list_to_s3(mock_iam_client, mock_s3_client):
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    iam_guide = IAMPolicy()

    create_iam_role(mock_iam_client)
    test_policy_arn = create_managed_policy(
        TEST_MANAGED_POLICY_NAME, TEST_MANAGED_POLICY, mock_iam_client
    )
    mock_iam_client.attach_role_policy(
        RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn
    )

    mock_s3_client.create_bucket(Bucket=BUCKET_NAME)
    managed_policies_list_path = iam_guide.get_s3_managed_policies_list_path(
        TEST_ROLE_NAME
    )

    record(updated_event)
    response = mock_s3_client.get_object(
        Bucket=BUCKET_NAME, Key=managed_policies_list_path
    )

    assert json.loads(response["Body"].read().decode("utf-8")) == [
        f"arn:aws:iam::123456789012:policy/{TEST_MANAGED_POLICY_NAME}"
    ]


def test_upload_managed_policies_to_s3(mock_iam_client, mock_s3_client):
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    iam_guide = IAMPolicy()

    create_iam_role(mock_iam_client)
    test_policy_arn = create_managed_policy(
        TEST_MANAGED_POLICY_NAME, TEST_MANAGED_POLICY, mock_iam_client
    )
    test_policy_name = test_policy_arn.split("/")[-1]
    mock_iam_client.attach_role_policy(
        RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn
    )

    mock_s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_path = iam_guide.get_s3_managed_path(test_policy_name)

    record(updated_event)
    response = mock_s3_client.get_object(Bucket=BUCKET_NAME, Key=s3_path)

    assert json.loads(response["Body"].read().decode("utf-8")) == TEST_MANAGED_POLICY


def test_upload_inline_policies_to_s3(mock_iam_client, mock_s3_client):
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    updated_event["detail"]["requestParameters"]["policyName"] = TEST_INLINE_POLICY_NAME
    iam_guide = IAMPolicy()

    create_role_with_inline_policies(mock_iam_client)

    mock_s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_path = iam_guide.get_s3_inline_path(TEST_ROLE_NAME, TEST_INLINE_POLICY_NAME)

    record(updated_event)
    response = mock_s3_client.get_object(Bucket=BUCKET_NAME, Key=s3_path)

    assert json.loads(response["Body"].read().decode("utf-8")) == TEST_INLINE_POLICY


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_create_principal_with_managed_policy(
    mock_iam_client, principal_type
):
    # Update event to have the test role name
    updated_event = CREATE_ROLE_EVENT
    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_role_with_managed_policies(mock_iam_client)
    else:
        updated_event["detail"]["eventName"] = EventName.CREATE_USER.value
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        create_user_with_managed_policies(mock_iam_client)

    remediate(updated_event)

    if principal_type == IAMType.ROLE:
        roles_response = mock_iam_client.list_roles()
        roles = roles_response["Roles"]
        assert len(roles) == 0
    else:
        iam_user_response = mock_iam_client.list_users()
        users = iam_user_response["Users"]
        assert len(users) == 0


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_update_principal_by_adding_attach_managed_policy(
    mock_iam_client, principal_type
):
    updated_event = ATTACH_ROLE_POLICY_EVENT

    test_policy = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy

    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_iam_role(mock_iam_client)
        mock_iam_client.attach_role_policy(
            RoleName=TEST_ROLE_NAME, PolicyArn=test_policy
        )
        principal_name = TEST_ROLE_NAME
    else:
        updated_event["detail"]["eventName"] = EventName.ATTACH_USER_POLICY.value
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        create_iam_user(mock_iam_client)

        mock_iam_client.attach_user_policy(
            UserName=TEST_USER_NAME, PolicyArn=test_policy
        )
        principal_name = TEST_USER_NAME

    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, mock_iam_client
    )
    assert len(managed_policy_arns) == 1

    remediate(updated_event)

    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, mock_iam_client
    )
    assert len(managed_policy_arns) == 0


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_update_principal_by_detaching_managed_policy(
    mock_iam_client, principal_type
):
    updated_event = DETACH_ROLE_POLICY_EVENT
    test_policy = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy

    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_role_with_managed_policies(mock_iam_client)
        principal_name = TEST_ROLE_NAME
    else:
        updated_event["detail"]["eventName"] = EventName.DETACH_USER_POLICY.value
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        create_user_with_managed_policies(mock_iam_client)
        principal_name = TEST_USER_NAME

    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, mock_iam_client
    )
    assert len(managed_policy_arns) == 2

    remediate(updated_event)
    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, mock_iam_client
    )
    assert len(managed_policy_arns) == 3


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_update_principal_by_deleting_an_user_managed_policy(
    mock_iam_client, mock_s3_client, principal_type
):
    updated_event = DETACH_ROLE_POLICY_EVENT
    test_policy = f"arn:aws:iam::123456789012:policy/{TEST_MANAGED_POLICY_NAME}"
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy
    iam_guide = IAMPolicy()

    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_iam_role(mock_iam_client)
        principal_name = TEST_ROLE_NAME
    else:
        updated_event["detail"]["eventName"] = EventName.DETACH_USER_POLICY.value
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        create_iam_user(mock_iam_client)
        principal_name = TEST_USER_NAME

    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, mock_iam_client
    )
    assert len(managed_policy_arns) == 0

    mock_s3_client.create_bucket(Bucket=BUCKET_NAME)
    managed_policy_s3_path = iam_guide.get_s3_managed_path(TEST_MANAGED_POLICY_NAME)
    upload_file_to_s3(
        json.dumps(TEST_MANAGED_POLICY),
        BUCKET_NAME,
        managed_policy_s3_path,
        mock_s3_client,
    )
    remediate(updated_event)
    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, mock_iam_client
    )
    assert len(managed_policy_arns) == 1


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_update_managed_policy_assigned_to_a_principal(
    mock_iam_client, principal_type
):
    updated_event = CREATE_POLICY_VERSION_EVENT
    test_policy_arn = create_managed_policy(
        TEST_MANAGED_POLICY_NAME, TEST_MANAGED_POLICY, mock_iam_client
    )
    updated_event["detail"]["requestParameters"]["policyArn"] = test_policy_arn

    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_iam_role(mock_iam_client)
        mock_iam_client.attach_role_policy(
            RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn
        )
    else:
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        create_iam_user(mock_iam_client)
        mock_iam_client.attach_user_policy(
            UserName=TEST_USER_NAME, PolicyArn=test_policy_arn
        )

    updated_managed_policy(mock_iam_client, test_policy_arn)
    current_managed_policy = get_current_managed_policy(
        mock_iam_client, test_policy_arn
    )
    assert len(current_managed_policy["Statement"][0]["Action"]) == 3

    remediate(updated_event)
    current_managed_policy = get_current_managed_policy(
        mock_iam_client, test_policy_arn
    )
    assert len(current_managed_policy["Statement"][0]["Action"]) == 2


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_create_a_principal_with_inline_policy(
    mock_iam_client, principal_type
):
    updated_event = PUT_ROLE_POLICY_EVENT

    updated_event["detail"]["requestParameters"]["policyName"] = TEST_INLINE_POLICY_NAME

    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_role_with_inline_policies(mock_iam_client)
        response = mock_iam_client.list_role_policies(RoleName=TEST_ROLE_NAME)
    else:
        updated_event["detail"]["eventName"] = EventName.PUT_USER_POLICY.value
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        create_user_with_inline_policies(mock_iam_client)
        response = mock_iam_client.list_user_policies(UserName=TEST_USER_NAME)

    assert len(response["PolicyNames"]) == 1

    remediate(updated_event)

    if principal_type == IAMType.ROLE:
        response = mock_iam_client.list_role_policies(RoleName=TEST_ROLE_NAME)
    else:
        response = mock_iam_client.list_user_policies(UserName=TEST_USER_NAME)

    assert len(response["PolicyNames"]) == 0


@pytest.mark.parametrize("principal_type", [IAMType.ROLE, IAMType.IAM_USER])
def test_remediate_deleting_inline_policy_in_role(
    mock_iam_client, mock_s3_client, principal_type
):
    updated_event = DELETE_ROLE_POLICY_EVENT
    iam_guide = IAMPolicy()
    updated_event["detail"]["requestParameters"]["policyName"] = TEST_INLINE_POLICY_NAME

    if principal_type == IAMType.ROLE:
        updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
        create_iam_role(mock_iam_client)
        principal_name = TEST_ROLE_NAME
        response = mock_iam_client.list_role_policies(RoleName=TEST_ROLE_NAME)
    else:
        updated_event["detail"]["eventName"] = EventName.DELETE_USER_POLICY.value
        updated_event["detail"]["requestParameters"]["userName"] = TEST_USER_NAME
        principal_name = TEST_USER_NAME
        create_iam_user(mock_iam_client)
        response = mock_iam_client.list_user_policies(UserName=TEST_USER_NAME)

    assert len(response["PolicyNames"]) == 0

    mock_s3_client.create_bucket(Bucket=BUCKET_NAME)
    inline_policy_s3_path = iam_guide.get_s3_inline_path(
        principal_name, TEST_INLINE_POLICY_NAME, principal_type
    )
    upload_file_to_s3(
        json.dumps(TEST_INLINE_POLICY),
        BUCKET_NAME,
        inline_policy_s3_path,
        mock_s3_client,
    )

    remediate(updated_event)

    if principal_type == IAMType.ROLE:
        response = mock_iam_client.list_role_policies(RoleName=TEST_ROLE_NAME)
    else:
        response = mock_iam_client.list_user_policies(UserName=TEST_USER_NAME)
    assert len(response["PolicyNames"]) == 1
