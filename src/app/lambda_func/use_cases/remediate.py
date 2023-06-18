import json

import boto3

from . import EventName
from .constants import BUCKET_NAME
from .iam import (
    IAMPolicy,
    IAMType,
    attach_managed_policy_to_principal,
    check_managed_policy_exists,
    check_policy_attached_to_any_principal,
    check_principal_exists,
    create_managed_policy,
    detach_managed_policies_from_principal,
    detach_managed_policy_from_principal,
    get_managed_policies_for_principal,
    get_previous_policy_version,
    update_managed_policy_to_certain_version,
)

iam_policy_path_guide = IAMPolicy()


def remediate_create_principal(
    event: dict, principal_type: IAMType, iam_client
) -> None:
    if principal_type == IAMType.ROLE:
        principal_name = event["detail"]["requestParameters"]["roleName"]
    else:
        principal_name = event["detail"]["requestParameters"]["userName"]

    managed_policy_arns = get_managed_policies_for_principal(
        principal_name, principal_type, iam_client
    )
    if managed_policy_arns:
        detach_managed_policies_from_principal(
            managed_policy_arns, principal_name, principal_type, iam_client
        )
    if principal_type == IAMType.ROLE:
        iam_client.delete_role(RoleName=principal_name)
    else:
        iam_client.delete_user(UserName=principal_name)


# TODO: Handle the case when the principal (user/role) does not exist
def remediate_detach_principal_policy(
    event: dict, principal_type: IAMType, iam_client, s3_client
) -> None:
    if principal_type == IAMType.ROLE:
        principal_name = event["detail"]["requestParameters"]["roleName"]
    else:
        principal_name = event["detail"]["requestParameters"]["userName"]

    policy_arn = event["detail"]["requestParameters"]["policyArn"]
    principal_exists = check_principal_exists(
        principal_name, principal_type, iam_client
    )
    policy_exists = check_managed_policy_exists(policy_arn, iam_client)

    if principal_exists and policy_exists:
        attach_managed_policy_to_principal(
            policy_arn, principal_name, principal_type, iam_client
        )
        return
    elif principal_exists and not policy_exists:
        managed_policy_name = policy_arn.split("/")[-1]
        policy_s3_path = iam_policy_path_guide.get_s3_managed_path(managed_policy_name)

        try:
            response = s3_client.get_object(Bucket=BUCKET_NAME, Key=policy_s3_path)
            policy_dict = json.loads(response["Body"].read().decode("utf-8"))
            new_policy_arn = create_managed_policy(
                managed_policy_name, policy_dict, iam_client
            )

            attach_managed_policy_to_principal(
                new_policy_arn, principal_name, principal_type, iam_client
            )
        except s3_client.exceptions.NoSuchKey:
            print(f"Policy {policy_s3_path} does not exist in S3 bucket {BUCKET_NAME}")
            pass

        return


def remediate_create_policy_version(event: dict, iam_client) -> None:
    policy_arn = event["detail"]["requestParameters"]["policyArn"]

    if not check_policy_attached_to_any_principal(policy_arn, iam_client):
        return

    previous_version_id = get_previous_policy_version(policy_arn, iam_client)
    if previous_version_id:
        update_managed_policy_to_certain_version(
            policy_arn, previous_version_id, iam_client
        )


# TODO: Address the case when an inline policy is attached to the role is updated. How to detect that vs creating a new role with an inline policy?
def remediate_put_principal_policy(
    event: dict, principal_type: IAMType, iam_client
) -> None:
    policy_name = event["detail"]["requestParameters"]["policyName"]
    if principal_type == IAMType.ROLE:
        principal_name = event["detail"]["requestParameters"]["roleName"]
        iam_client.delete_role_policy(RoleName=principal_name, PolicyName=policy_name)
    else:
        principal_name = event["detail"]["requestParameters"]["userName"]
        iam_client.delete_user_policy(UserName=principal_name, PolicyName=policy_name)


# TODO: Handle when principal (user/role) does not exist
def remediate_delete_principal_policy(
    event: dict, iam_client, principal_type: IAMType, s3_client
) -> None:
    inline_policy_name = event["detail"]["requestParameters"]["policyName"]
    if principal_type == IAMType.ROLE:
        principal_name = event["detail"]["requestParameters"]["roleName"]
    else:
        principal_name = event["detail"]["requestParameters"]["userName"]

    principal_exists = check_principal_exists(
        principal_name, principal_type, iam_client
    )
    if principal_exists:
        inline_policy_s3_path = iam_policy_path_guide.get_s3_inline_path(
            principal_name, inline_policy_name, type=principal_type
        )
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=inline_policy_s3_path)
        inline_policy_dict = json.loads(response["Body"].read().decode("utf-8"))
        if principal_type == IAMType.ROLE:
            iam_client.put_role_policy(
                RoleName=principal_name,
                PolicyName=inline_policy_name,
                PolicyDocument=json.dumps(inline_policy_dict),
            )
        else:
            iam_client.put_user_policy(
                UserName=principal_name,
                PolicyName=inline_policy_name,
                PolicyDocument=json.dumps(inline_policy_dict),
            )


def remediate(event: dict) -> None:
    iam_client = boto3.client("iam")
    s3_client = boto3.client("s3")
    event_name = event["detail"]["eventName"]

    match event_name:
        # Role events
        case EventName.CREATE_ROLE.value:
            remediate_create_principal(event, IAMType.ROLE, iam_client)
        case EventName.ATTACH_ROLE_POLICY.value:
            role_name = event["detail"]["requestParameters"]["roleName"]
            policy_arn = event["detail"]["requestParameters"]["policyArn"]
            detach_managed_policy_from_principal(
                policy_arn, role_name, IAMType.ROLE, iam_client
            )
        case EventName.DETACH_ROLE_POLICY.value:
            remediate_detach_principal_policy(
                event, IAMType.ROLE, iam_client, s3_client
            )
        case EventName.CREATE_POLICY_VERSION.value:
            remediate_create_policy_version(event, iam_client)
        case EventName.PUT_ROLE_POLICY.value:
            remediate_put_principal_policy(event, IAMType.ROLE, iam_client)
        case EventName.DELETE_ROLE_POLICY.value:
            remediate_delete_principal_policy(
                event, iam_client, IAMType.ROLE, s3_client
            )

        # User events
        case EventName.CREATE_USER.value:
            remediate_create_principal(event, IAMType.IAM_USER, iam_client)
        case EventName.ATTACH_USER_POLICY.value:
            user_name = event["detail"]["requestParameters"]["userName"]
            policy_arn = event["detail"]["requestParameters"]["policyArn"]
            detach_managed_policy_from_principal(
                policy_arn, user_name, IAMType.IAM_USER, iam_client
            )
        case EventName.DETACH_USER_POLICY.value:
            remediate_detach_principal_policy(
                event, IAMType.IAM_USER, iam_client, s3_client
            )
        case EventName.PUT_USER_POLICY.value:
            remediate_put_principal_policy(event, IAMType.IAM_USER, iam_client)
        case EventName.DELETE_USER_POLICY.value:
            remediate_delete_principal_policy(
                event, iam_client, IAMType.IAM_USER, s3_client
            )

    return None
