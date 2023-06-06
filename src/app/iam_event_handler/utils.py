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


def detach_managed_policies_from_role(
    policy_arns: List[str], role_name: str, iam_client
):
    # Detach each policy from the role
    for policy_arn in policy_arns:
        iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    print("Detached policies from role: {}".format(role_name))


def remediate(event: dict) -> None:
    iam_client = boto3.client("iam")
    event_name = event["detail"]["eventName"]

    match event_name:
        case EventName.CREATE_ROLE.value:
            role_name = event["detail"]["requestParameters"]["roleName"]
            managed_policy_arns = get_managed_policies_for_role(role_name, iam_client)
            detach_managed_policies_from_role(
                managed_policy_arns, role_name, iam_client
            )
            iam_client.delete_role(RoleName=role_name)

    print("Remediation not implemented yet")
    return None
