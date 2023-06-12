import boto3

from . import EventName
from .iam import (
    IAMPolicy,
    get_role_policies,
    write_inline_policy_to_s3,
    write_managed_policies_list_to_s3,
    write_managed_policy_to_s3,
)

iam_policy_path_guide = IAMPolicy()


def record_all_policies_for_role(role_name: str, iam_client, s3_client) -> None:
    managed_policies, inline_policies = get_role_policies(role_name, iam_client)
    managed_policies_arns = []

    for each_managed_policy in managed_policies:
        managed_policy_arn = each_managed_policy["PolicyArn"]
        write_managed_policy_to_s3(
            managed_policy_arn, iam_client, iam_policy_path_guide, s3_client
        )
        managed_policies_arns.append(managed_policy_arn)

    for each_inline_policy in inline_policies:
        write_inline_policy_to_s3(
            role_name,
            each_inline_policy,
            iam_client,
            iam_policy_path_guide,
            s3_client,
        )

    write_managed_policies_list_to_s3(
        role_name, managed_policies_arns, iam_policy_path_guide, s3_client
    )


def record(event: dict) -> None:
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
        role_name = event["detail"]["requestParameters"]["roleName"]
        record_all_policies_for_role(role_name, iam_client, s3_client)
