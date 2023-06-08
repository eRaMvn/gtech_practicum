import json
from typing import List

import boto3

from .utils import EventName


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
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False


def check_managed_policy_exists(policy_arn, iam_client):
    try:
        # Retrieve information about the policy
        iam_client.get_policy(PolicyArn=policy_arn)
        return True
    except iam_client.exceptions.NoSuchEntityException:
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


def remediate_create_policy_version(event: dict, iam_client):
    policy_arn = event["detail"]["requestParameters"]["policyArn"]

    if not check_policy_attached_to_any_role(policy_arn, iam_client):
        return

    previous_version_id = get_previous_policy_version(policy_arn, iam_client)
    if previous_version_id:
        update_managed_policy_to_certain_version(
            policy_arn, previous_version_id, iam_client
        )


# TODO: Address the case when an inline policy is attached to the role is updated. How to detect that vs creating a new role with an inline policy?
def remediate_put_role_policy(event: dict, iam_client) -> None:
    role_name = event["detail"]["requestParameters"]["roleName"]
    policy_name = event["detail"]["requestParameters"]["policyName"]

    iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)


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
            remediate_create_policy_version(event, iam_client)
        case EventName.PUT_ROLE_POLICY.value:
            remediate_put_role_policy(event, iam_client)

    return None
