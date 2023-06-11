import hashlib
import json

import boto3

from .constants import BUCKET_NAME
from .utils import EventName, upload_file_to_s3


class IAMPolicy:
    def calculate_sha256(self, string_value):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(string_value.encode("utf-8"))
        return sha256_hash.hexdigest()

    # some_name could be role_name or policy_name
    def get_s3_inline_path(self, some_name, inline_policy_name):
        file_name = self.calculate_sha256(f"{some_name}_{inline_policy_name}")
        return f"{some_name}/inline_policies/{file_name}.json"

    def get_s3_managed_policies_list_path(self, some_name):
        return f"{some_name}/managed_policies/list.json"

    def get_s3_managed_path(self, managed_policy_name):
        return f"managed_policies/{managed_policy_name}.json"


iam_policy_path_guide = IAMPolicy()


def get_role_policies(role_name, iam_client):
    # Get managed policies attached to the role
    response_managed = iam_client.list_attached_role_policies(RoleName=role_name)
    managed_policies = response_managed["AttachedPolicies"]

    # Get inline policies attached to the role
    response_inline = iam_client.list_role_policies(RoleName=role_name)
    inline_policies = response_inline["PolicyNames"]

    return managed_policies, inline_policies


def write_inline_policy_to_s3(role_name, policy_name, iam_client, s3_client):
    response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    policy_document = response["PolicyDocument"]
    upload_file_to_s3(
        json.dumps(policy_document),
        BUCKET_NAME,
        iam_policy_path_guide.get_s3_inline_path(role_name, policy_name),
        s3_client,
    )


def is_customer_managed_policy(policy_arn):
    return policy_arn.startswith("arn:aws:iam::") and "policy/" in policy_arn


def write_managed_policy_to_s3(policy_arn, iam_client, s3_client):
    if is_customer_managed_policy(policy_arn):
        response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version = response["Policy"]["DefaultVersionId"]
        policy_document = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=policy_version
        )["PolicyVersion"]["Document"]
        policy_name = policy_arn.split("/")[-1]
        upload_file_to_s3(
            json.dumps(policy_document),
            BUCKET_NAME,
            iam_policy_path_guide.get_s3_managed_path(policy_name),
            s3_client,
        )


def write_managed_policies_list_to_s3(role_name, managed_policies, s3_client):
    upload_file_to_s3(
        json.dumps(managed_policies),
        BUCKET_NAME,
        iam_policy_path_guide.get_s3_managed_policies_list_path(role_name),
        s3_client,
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
        managed_policies, inline_policies = get_role_policies(role_name, iam_client)
        managed_policies_arns = []

        for each_managed_policy in managed_policies:
            managed_policy_arn = each_managed_policy["PolicyArn"]
            write_managed_policy_to_s3(managed_policy_arn, iam_client, s3_client)
            managed_policies_arns.append(managed_policy_arn)

        for each_inline_policy in inline_policies:
            write_inline_policy_to_s3(
                role_name, each_inline_policy, iam_client, s3_client
            )

        write_managed_policies_list_to_s3(role_name, managed_policies_arns, s3_client)
