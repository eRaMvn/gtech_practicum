import json
import os
from enum import Enum
from typing import List, Set, Tuple

import boto3

from .constants import (
    WHITELISTED_IAM_ROLES,
    WHITELISTED_IAM_ROLES_VARIABLE,
    WHITELISTED_IAM_USERS,
    WHITELISTED_IAM_USERS_VARIABLE,
)


class IdentityType(Enum):
    ASSUMED_ROLE = "AssumedRole"
    IAM_USER = "IAMUser"


class EventName(Enum):
    # User events
    ATTACH_USER_POLICY = "AttachUserPolicy"
    DETACH_USER_POLICY = "DetachUserPolicy"
    DELETE_USER = "DeleteUser"
    PUT_USER_POLICY = "PutUserPolicy"
    DELETE_USER_POLICY = "DeleteUserPolicy"
    # Role events
    CREATE_ROLE = "CreateRole"
    ATTACH_ROLE_POLICY = "AttachRolePolicy"
    DETACH_ROLE_POLICY = "DetachRolePolicy"
    CREATE_POLICY_VERSION = "CreatePolicyVersion"
    DELETE_POLICY = "DeletePolicy"
    DELETE_ROLE = "DeleteRole"
    PUT_ROLE_POLICY = "PutRolePolicy"
    DELETE_ROLE_POLICY = "DeleteRolePolicy"


def extract_principal(event: dict) -> Tuple[IdentityType, str]:
    principal_arn: str = event["detail"]["userIdentity"]["arn"]
    principal_arn_split: List[str] = principal_arn.split("/")
    principal_type: str = event["detail"]["userIdentity"]["type"]

    if principal_type == IdentityType.ASSUMED_ROLE.value:
        return (IdentityType.ASSUMED_ROLE, principal_arn_split[1])
    elif principal_type == IdentityType.IAM_USER.value:
        return (IdentityType.IAM_USER, principal_arn_split[1])

    err_msg = "Unknown principal type: {}".format(principal_type)
    print(err_msg)
    raise Exception(err_msg)


def extract_whitelisted_principals() -> Tuple[Set[str], Set[str]]:
    if WHITELISTED_IAM_USERS_VARIABLE in os.environ:
        whitelisted_users = os.environ[WHITELISTED_IAM_USERS_VARIABLE]
    else:
        whitelisted_users = WHITELISTED_IAM_USERS

    if WHITELISTED_IAM_ROLES_VARIABLE in os.environ:
        whitelisted_roles = os.environ[WHITELISTED_IAM_ROLES_VARIABLE]
    else:
        whitelisted_roles = WHITELISTED_IAM_ROLES

    return (set(whitelisted_users.split("|")), set(whitelisted_roles.split("|")))


def is_whitelisted_principal(
    principal_name, principal_type, whitelisted_users, whitelisted_roles
) -> bool:
    if principal_type == IdentityType.ASSUMED_ROLE:
        return principal_name in whitelisted_roles
    elif principal_type == IdentityType.IAM_USER:
        return principal_name in whitelisted_users
    return False


def get_managed_policies_for_role(role_name: str, iam_client) -> List[str]:
    # Retrieve the list of attached policies for the role
    response = iam_client.list_attached_role_policies(RoleName=role_name)
    attached_policies = response["AttachedPolicies"]

    # Extract the policy ARNs from the response
    policy_arns = [policy["PolicyArn"] for policy in attached_policies]

    return policy_arns


def check_role_exists(role_name, iam_client):
    try:
        # Retrieve information about the role
        iam_client.get_role(RoleName=role_name)
        print(f"Role {role_name} exists.")
        return True
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Role {role_name} does not exist.")
        return False


def check_managed_policy_exists(policy_arn, iam_client):
    try:
        # Retrieve information about the policy
        iam_client.get_policy(PolicyArn=policy_arn)
        print(f"Policy {policy_arn} exists.")
        return True
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Policy {policy_arn} does not exist.")
        return False


def attach_managed_policy_to_role(policy_arn: str, role_name: str, iam_client):
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def detach_managed_policy_from_role(policy_arn: str, role_name: str, iam_client):
    iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def detach_managed_policies_from_role(
    policy_arns: List[str], role_name: str, iam_client
):
    # Detach each policy from the role
    for policy_arn in policy_arns:
        detach_managed_policy_from_role(policy_arn, role_name, iam_client)


def check_policy_attached_to_any_role(policy_arn, iam_client) -> bool:
    # Retrieve the list of roles attached to the policy
    response = iam_client.list_entities_for_policy(
        PolicyArn=policy_arn, EntityFilter="Role"
    )
    attached_roles = response["PolicyRoles"]

    # Check if the policy is attached to any role
    if attached_roles:
        return True

    return False


def update_managed_policy_to_certain_version(policy_arn, version_id, iam_client):
    # Retrieve information about the previous version
    response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    policy_document = response["PolicyVersion"]["Document"]

    # Update the policy with the previous version
    response = iam_client.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True,
    )


def get_previous_policy_version(policy_arn, iam_client) -> str | None:
    # Retrieve the list of versions for the policy
    response = iam_client.list_policy_versions(PolicyArn=policy_arn)
    versions = response["Versions"]

    # Sort the versions by the version number in descending order
    sorted_versions = sorted(versions, key=lambda v: v["VersionId"], reverse=True)

    # Find the previous version
    if len(sorted_versions) > 1:
        previous_version = sorted_versions[1]
        previous_version_id = previous_version["VersionId"]
        return previous_version_id

    return None


def remediate_create_role(event: dict, iam_client) -> None:
    role_name = event["detail"]["requestParameters"]["roleName"]
    managed_policy_arns = get_managed_policies_for_role(role_name, iam_client)
    detach_managed_policies_from_role(managed_policy_arns, role_name, iam_client)
    iam_client.delete_role(RoleName=role_name)


# TODO: Handle the case where the role or policy does not exist
def remediate_detach_role_policy(event: dict, iam_client) -> None:
    role_name = event["detail"]["requestParameters"]["roleName"]
    policy_arn = event["detail"]["requestParameters"]["policyArn"]
    role_exists = check_role_exists(role_name, iam_client)
    policy_exists = check_managed_policy_exists(policy_arn, iam_client)

    if role_exists and policy_exists:
        attach_managed_policy_to_role(policy_arn, role_name, iam_client)
        return


def remediate_create_policy_version(policy_arn: str, iam_client):
    if not check_policy_attached_to_any_role(policy_arn, iam_client):
        return

    previous_version_id = get_previous_policy_version(policy_arn, iam_client)
    if previous_version_id:
        update_managed_policy_to_certain_version(
            policy_arn, previous_version_id, iam_client
        )


def remediate(event: dict) -> None:
    iam_client = boto3.client("iam")
    event_name = event["detail"]["eventName"]

    match event_name:
        case EventName.CREATE_ROLE.value:
            remediate_create_role(event, iam_client)
        case EventName.ATTACH_ROLE_POLICY.value:
            role_name = event["detail"]["requestParameters"]["roleName"]
            policy_arn = event["detail"]["requestParameters"]["policyArn"]
            detach_managed_policy_from_role(policy_arn, role_name, iam_client)
        case EventName.DETACH_ROLE_POLICY.value:
            remediate_detach_role_policy(event, iam_client)
        case EventName.CREATE_POLICY_VERSION.value:
            policy_arn = event["detail"]["requestParameters"]["policyArn"]
            remediate_create_policy_version(policy_arn, iam_client)

    return None
