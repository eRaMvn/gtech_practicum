import os

import boto3
from moto import mock_iam

from app.iam_event_handler.constants import WHITELISTED_IAM_USERS_VARIABLE
from app.iam_event_handler.utils import (
    IdentityType,
    extract_principal,
    extract_whitelisted_principals,
    get_managed_policies_for_role,
    is_whitelisted_principal,
    remediate,
)

from .constants import TEST_ROLE_NAME
from .events import ATTACH_ROLE_POLICY_EVENT, CREATE_ROLE_EVENT, EVENT_FROM_ASSUME_ROLE
from .utils import create_role_with_managed_policies


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


@mock_iam
def test_create_role_with_managed_policy_remediation():
    # Update event to have the test role name
    updated_event = CREATE_ROLE_EVENT
    updated_event["detail"]["requestParameters"]["roleName"] = TEST_ROLE_NAME
    iam_client = boto3.client("iam")

    create_role_with_managed_policies()
    managed_policy_arns = get_managed_policies_for_role(TEST_ROLE_NAME, iam_client)
    assert len(managed_policy_arns) == 2

    remediate(updated_event)
    roles_response = iam_client.list_roles()
    roles = roles_response["Roles"]
    assert len(roles) == 0
