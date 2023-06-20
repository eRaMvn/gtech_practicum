import hashlib
import json
from enum import Enum
from typing import List, Tuple

from .constants import BUCKET_NAME
from .s3 import upload_file_to_s3


class IAMType(Enum):
    ROLE = "role"
    IAM_USER = "user"


class IAMPolicy:
    def calculate_sha256(self, string_value):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(string_value.encode("utf-8"))
        return sha256_hash.hexdigest()

    # some_name could be role_name or policy_name
    def get_s3_inline_path(self, some_name, inline_policy_name, type=IAMType.ROLE):
        file_name = self.calculate_sha256(f"{some_name}_{inline_policy_name}")
        if type == IAMType.ROLE:
            return f"roles/{some_name}/inline_policies/{file_name}.json"
        return f"users/{some_name}/inline_policies/{file_name}.json"

    def get_s3_managed_policies_list_path(self, some_name, type=IAMType.ROLE):
        if type == IAMType.ROLE:
            return f"roles/{some_name}/managed_policies/list.json"
        return f"users/{some_name}/managed_policies/list.json"

    def get_s3_managed_path(self, managed_policy_name):
        return f"managed_policies/{managed_policy_name}.json"


def list_roles_and_users(iam_client):
    response = iam_client.list_roles()
    roles = response["Roles"]

    response = iam_client.list_users()
    users = response["Users"]

    return roles, users


def get_managed_policies_for_principal(
    principal_name: str, principal_type: IAMType, iam_client
) -> List[str]:
    if principal_type == IAMType.ROLE:
        # Retrieve the list of attached policies for the role
        response = iam_client.list_attached_role_policies(RoleName=principal_name)
    else:
        # Retrieve the list of attached policies for the user
        response = iam_client.list_attached_user_policies(UserName=principal_name)

    attached_policies = response["AttachedPolicies"]

    # Extract the policy ARNs from the response
    policy_arns = [policy["PolicyArn"] for policy in attached_policies]

    return policy_arns


def check_principal_exists(principal_name: str, principal_type: IAMType, iam_client):
    try:
        if principal_type == IAMType.ROLE:
            # Retrieve information about the role
            iam_client.get_role(RoleName=principal_name)
        else:
            # Retrieve information about the user
            iam_client.get_user(UserName=principal_name)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False


def check_inline_policy_in_role(role_name, policy_name, iam_client):
    response = iam_client.list_role_policies(RoleName=role_name)

    policy_names = response["PolicyNames"]

    if policy_name in policy_names:
        return True

    return False


def check_managed_policy_exists(policy_arn, iam_client):
    try:
        # Retrieve information about the policy
        iam_client.get_policy(PolicyArn=policy_arn)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False


def attach_managed_policy_to_principal(
    policy_arn: str, principal_name: str, principal_type: IAMType, iam_client
):
    if principal_type == IAMType.ROLE:
        iam_client.attach_role_policy(RoleName=principal_name, PolicyArn=policy_arn)
    else:
        iam_client.attach_user_policy(UserName=principal_name, PolicyArn=policy_arn)


def detach_managed_policy_from_principal(
    policy_arn: str, principal_name: str, principal_type: IAMType, iam_client
):
    if principal_type == IAMType.ROLE:
        iam_client.detach_role_policy(RoleName=principal_name, PolicyArn=policy_arn)
    else:
        iam_client.detach_user_policy(UserName=principal_name, PolicyArn=policy_arn)


def detach_managed_policies_from_principal(
    policy_arns: List[str], principal_name: str, principal_type: IAMType, iam_client
):
    # Detach each policy from the role
    for policy_arn in policy_arns:
        detach_managed_policy_from_principal(
            policy_arn, principal_name, principal_type, iam_client
        )


def check_policy_attached_to_any_principal(policy_arn: str, iam_client) -> bool:
    # Retrieve the list of roles attached to the policy
    response = iam_client.list_entities_for_policy(
        PolicyArn=policy_arn, EntityFilter="Role"
    )
    attached_roles = response["PolicyRoles"]

    response = iam_client.list_entities_for_policy(
        PolicyArn=policy_arn, EntityFilter="User"
    )
    attached_users = response["PolicyUsers"]

    # Check if the policy is attached to any role
    if attached_roles or attached_users:
        return True

    return False


def update_managed_policy_to_certain_version(policy_arn: str, version_id, iam_client):
    # Retrieve information about the previous version
    response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    policy_document = response["PolicyVersion"]["Document"]

    # Update the policy with the previous version
    response = iam_client.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True,
    )


def get_previous_policy_version(policy_arn: str, iam_client) -> str | None:
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


def get_principal_policies(
    principal_name: str, principal_type: IAMType, iam_client
) -> Tuple[List, List]:
    if principal_type == IAMType.ROLE:
        # Get managed policies attached to the role
        response_managed = iam_client.list_attached_role_policies(
            RoleName=principal_name
        )

        # Get inline policies attached to the role
        response_inline = iam_client.list_role_policies(RoleName=principal_name)
    else:
        # Get managed policies attached to the user
        response_managed = iam_client.list_attached_user_policies(
            UserName=principal_name
        )

        # Get inline policies attached to the user
        response_inline = iam_client.list_user_policies(UserName=principal_name)

    managed_policies = response_managed["AttachedPolicies"]
    inline_policies = response_inline["PolicyNames"]

    return managed_policies, inline_policies


def create_managed_policy(policy_name: str, policy_doc: dict, iam_client) -> str:
    response = iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )

    return response["Policy"]["Arn"]


def get_instance_profiles_attached_to_role(role_name: str, iam_client) -> List:
    response = iam_client.list_instance_profiles_for_role(RoleName=role_name)
    instance_profiles = response["InstanceProfiles"]

    return instance_profiles


def remove_instance_profiles_from_role(
    role_name: str, instance_profiles: List[dict], iam_client
) -> None:
    for instance_profile in instance_profiles:
        instance_profile_name = instance_profile["InstanceProfileName"]
        iam_client.remove_role_from_instance_profile(
            RoleName=role_name, InstanceProfileName=instance_profile_name
        )


def write_inline_policy_to_s3(
    principal_name,
    principal_type,
    policy_name,
    iam_client,
    iam_policy_path_guide,
    s3_client,
) -> None:
    if principal_type == IAMType.ROLE:
        response = iam_client.get_role_policy(
            RoleName=principal_name, PolicyName=policy_name
        )
    else:
        response = iam_client.get_user_policy(
            UserName=principal_name, PolicyName=policy_name
        )

    policy_document = response["PolicyDocument"]
    upload_file_to_s3(
        json.dumps(policy_document),
        BUCKET_NAME,
        iam_policy_path_guide.get_s3_inline_path(
            principal_name, policy_name, principal_type
        ),
        s3_client,
    )


def is_customer_managed_policy(policy_arn) -> bool:
    return policy_arn.startswith("arn:aws:iam::") and "policy/" in policy_arn


def write_managed_policy_to_s3(
    policy_arn, iam_client, iam_policy_path_guide, s3_client
) -> None:
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


def write_managed_policies_list_to_s3(
    principal_name, principal_type, managed_policies, iam_policy_path_guide, s3_client
) -> None:
    upload_file_to_s3(
        json.dumps(managed_policies),
        BUCKET_NAME,
        iam_policy_path_guide.get_s3_managed_policies_list_path(
            principal_name, principal_type
        ),
        s3_client,
    )
