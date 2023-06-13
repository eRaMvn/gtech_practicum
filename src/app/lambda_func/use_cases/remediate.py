import json

import boto3

from . import EventName
from .constants import BUCKET_NAME
from .iam import (
    IAMPolicy,
    attach_managed_policy_to_role,
    check_managed_policy_exists,
    check_policy_attached_to_any_role,
    check_role_exists,
    create_managed_policy,
    detach_managed_policies_from_role,
    detach_managed_policy_from_role,
    get_managed_policies_for_role,
    get_previous_policy_version,
    update_managed_policy_to_certain_version,
)

iam_policy_path_guide = IAMPolicy()


def remediate_create_role(event: dict, iam_client) -> None:
    role_name = event["detail"]["requestParameters"]["roleName"]
    managed_policy_arns = get_managed_policies_for_role(role_name, iam_client)
    detach_managed_policies_from_role(managed_policy_arns, role_name, iam_client)
    iam_client.delete_role(RoleName=role_name)


# TODO: Handle the case where the role does not exist
def remediate_detach_role_policy(event: dict, iam_client, s3_client) -> None:
    role_name = event["detail"]["requestParameters"]["roleName"]
    policy_arn = event["detail"]["requestParameters"]["policyArn"]
    role_exists = check_role_exists(role_name, iam_client)
    policy_exists = check_managed_policy_exists(policy_arn, iam_client)

    if role_exists and policy_exists:
        attach_managed_policy_to_role(policy_arn, role_name, iam_client)
        return
    elif role_exists and not policy_exists:
        managed_policy_name = policy_arn.split("/")[-1]
        policy_s3_path = iam_policy_path_guide.get_s3_managed_path(managed_policy_name)

        try:
            response = s3_client.get_object(Bucket=BUCKET_NAME, Key=policy_s3_path)
            policy_dict = json.loads(response["Body"].read().decode("utf-8"))
            new_policy_arn = create_managed_policy(
                managed_policy_name, policy_dict, iam_client
            )

            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=new_policy_arn)
        except s3_client.exceptions.NoSuchKey:
            print(f"Policy {policy_s3_path} does not exist in S3 bucket {BUCKET_NAME}")
            pass

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


# TODO: Handle when role does not exist
def remediate_delete_role_policy(event: dict, iam_client, s3_client) -> None:
    role_name = event["detail"]["requestParameters"]["roleName"]
    inline_policy_name = event["detail"]["requestParameters"]["policyName"]
    role_exists = check_role_exists(role_name, iam_client)
    if role_exists:
        role_inline_policy_s3_path = iam_policy_path_guide.get_s3_inline_path(
            role_name, inline_policy_name
        )
        response = s3_client.get_object(
            Bucket=BUCKET_NAME, Key=role_inline_policy_s3_path
        )
        inline_policy_dict = json.loads(response["Body"].read().decode("utf-8"))
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=inline_policy_name,
            PolicyDocument=json.dumps(inline_policy_dict),
        )


def remediate(event: dict) -> None:
    iam_client = boto3.client("iam")
    s3_client = boto3.client("s3")
    event_name = event["detail"]["eventName"]

    match event_name:
        case EventName.CREATE_ROLE.value:
            remediate_create_role(event, iam_client)
        case EventName.ATTACH_ROLE_POLICY.value:
            role_name = event["detail"]["requestParameters"]["roleName"]
            policy_arn = event["detail"]["requestParameters"]["policyArn"]
            detach_managed_policy_from_role(policy_arn, role_name, iam_client)
        case EventName.DETACH_ROLE_POLICY.value:
            remediate_detach_role_policy(event, iam_client, s3_client)
        case EventName.CREATE_POLICY_VERSION.value:
            remediate_create_policy_version(event, iam_client)
        case EventName.PUT_ROLE_POLICY.value:
            remediate_put_role_policy(event, iam_client)
        case EventName.DELETE_ROLE_POLICY.value:
            remediate_delete_role_policy(event, iam_client, s3_client)

    return None
