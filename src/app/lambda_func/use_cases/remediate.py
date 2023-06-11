import boto3

from . import EventName
from .iam import (
    attach_managed_policy_to_role,
    check_managed_policy_exists,
    check_policy_attached_to_any_role,
    check_role_exists,
    detach_managed_policies_from_role,
    detach_managed_policy_from_role,
    get_managed_policies_for_role,
    get_previous_policy_version,
    update_managed_policy_to_certain_version,
)


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
