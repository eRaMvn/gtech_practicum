import boto3

from . import EventName
from .iam import (
    IAMPolicy,
    IAMType,
    get_principal_policies,
    list_roles_and_users,
    write_inline_policy_to_s3,
    write_managed_policies_list_to_s3,
    write_managed_policy_to_s3,
)

iam_policy_path_guide = IAMPolicy()


def record_all_policies_for_principal(
    principal_name: str, principal_type: IAMType, iam_client, s3_client
) -> None:
    managed_policies, inline_policies = get_principal_policies(
        principal_name, principal_type, iam_client
    )
    managed_policies_arns = []

    for each_managed_policy in managed_policies:
        managed_policy_arn = each_managed_policy["PolicyArn"]
        write_managed_policy_to_s3(
            managed_policy_arn, iam_client, iam_policy_path_guide, s3_client
        )
        managed_policies_arns.append(managed_policy_arn)

    for each_inline_policy in inline_policies:
        write_inline_policy_to_s3(
            principal_name,
            principal_type,
            each_inline_policy,
            iam_client,
            iam_policy_path_guide,
            s3_client,
        )

    write_managed_policies_list_to_s3(
        principal_name,
        principal_type,
        managed_policies_arns,
        iam_policy_path_guide,
        s3_client,
    )


def record_all_policies_for_users_and_roles(iam_client, s3_client) -> None:
    role_records, user_records = list_roles_and_users(iam_client)
    for each_record in role_records:
        record_all_policies_for_principal(
            each_record["RoleName"], IAMType.ROLE, iam_client, s3_client
        )
    for each_record in user_records:
        record_all_policies_for_principal(
            each_record["RoleName"], IAMType.ROLE, iam_client, s3_client
        )


def record(event: dict, principal_type: IAMType) -> None:
    iam_client = boto3.client("iam")
    s3_client = boto3.client("s3")
    event_name = event["detail"]["eventName"]
    all_role_events = [
        f"{EventName.CREATE_ROLE.value}",
        f"{EventName.ATTACH_ROLE_POLICY.value}",
        f"{EventName.DETACH_ROLE_POLICY.value}",
        f"{EventName.CREATE_POLICY_VERSION.value}",
        f"{EventName.PUT_ROLE_POLICY.value}",
    ]

    if event_name in all_role_events:
        print(f"Start recording process for event: {event_name}")
        if principal_type == IAMType.ROLE:
            principal_name = event["detail"]["requestParameters"]["roleName"]
        else:
            principal_name = event["detail"]["requestParameters"]["userName"]

        record_all_policies_for_principal(
            principal_name, principal_type, iam_client, s3_client
        )
