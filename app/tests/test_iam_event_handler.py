import os

from app.iam_event_handler.constants import WHITELISTED_IAM_USERS_VARIABLE
from app.iam_event_handler.utils import (
    IdentityType,
    extract_principal,
    extract_whitelisted_principals,
    is_whitelisted_principal,
)

from .events import ATTACH_ROLE_POLICY_EVENT, EVENT_FROM_ASSUME_ROLE


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
