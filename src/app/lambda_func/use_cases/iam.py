import json
from typing import List
import hashlib
from .s3 import upload_file_to_s3, list_objects_in_s3
from app.lambda_func.constants import BUCKET_NAME

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


def get_role_policies(role_name, iam_client):
    # Get managed policies attached to the role
    response_managed = iam_client.list_attached_role_policies(RoleName=role_name)
    managed_policies = response_managed["AttachedPolicies"]

    # Get inline policies attached to the role
    response_inline = iam_client.list_role_policies(RoleName=role_name)
    inline_policies = response_inline["PolicyNames"]

    return managed_policies, inline_policies


def write_inline_policy_to_s3(role_name, policy_name, iam_client, iam_policy_path_guide, s3_client):
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


def write_managed_policy_to_s3(policy_arn, iam_client, iam_policy_path_guide, s3_client):
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


def write_managed_policies_list_to_s3(role_name, managed_policies,iam_policy_path_guide, s3_client):
    upload_file_to_s3(
        json.dumps(managed_policies),
        BUCKET_NAME,
        iam_policy_path_guide.get_s3_managed_policies_list_path(role_name),
        s3_client,
    )
