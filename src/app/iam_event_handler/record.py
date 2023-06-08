import boto3
import json
import hashlib
from .utils import EventName

class IAMPolicy:
    def calculate_sha256(self, string_value):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(string_value.encode('utf-8'))
        return sha256_hash.hexdigest()

    # some_name could be role_name or policy_name
    def get_s3_inline_path(self, some_name, inline_policy_name):
        file_name = self.calculate_sha256(f"{some_name}_{inline_policy_name}")
        return f"{some_name}/inline_policies/{file_name}.json"

    def get_local_inline_path(self, some_name, inline_policy_name):
        file_name = self.calculate_sha256(f"{some_name}_{inline_policy_name}")
        return f"/tmp/{file_name}.json"

    def get_s3_managed_path(self, managed_policy_name):
        return f"managed_policies/{managed_policy_name}.json"

    def get_local_managed_path(self, managed_policy_name):
        return f"/tmp/{managed_policy_name}.json"

iam_policy_path_guide  = IAMPolicy()

def get_role_policies(role_name, iam_client):
    # Get managed policies attached to the role
    response_managed = iam_client.list_attached_role_policies(RoleName=role_name)
    managed_policies = response_managed['AttachedPolicies']

    # Get inline policies attached to the role
    response_inline = iam_client.list_role_policies(RoleName=role_name)
    inline_policies = response_inline['PolicyNames']

    return managed_policies, inline_policies

def write_dict_to_file(dictionary, file_path):
    with open(file_path, 'w') as file:
        json.dump(dictionary, file, indent=4)


def write_inline_policy_to_file(role_name, policy_name, iam_client):
    response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    policy_document = response['PolicyDocument']
    write_dict_to_file(policy_document, iam_policy_path_guide.get_local_inline_path(role_name, policy_name))

def is_customer_managed_policy(policy_arn):
    return policy_arn.startswith("arn:aws:iam::") and "/policy/" in policy_arn

def write_managed_policy_to_file(policy_arn, iam_client):
    if is_customer_managed_policy(policy_arn):
        response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version = response['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        policy_name = policy_arn.split('/')[-1]

        write_dict_to_file(policy_document, iam_policy_path_guide.get_local_managed_path(policy_name))

def record(event:dict)->None:
    iam_client = boto3.client("iam")
    event_name = event["detail"]["eventName"]
    all_role_events = [f"{EventName.CREATE_ROLE.value}", f"{EventName.ATTACH_ROLE_POLICY.value}", f"{EventName.DETACH_ROLE_POLICY.value}", f"{EventName.CREATE_POLICY_VERSION.value}", f"{EventName.PUT_ROLE_POLICY.value}"]

    if event_name in all_role_events:
        role_name = event["detail"]["requestParameters"]["roleName"]
        managed_policies, inline_policies = get_role_policies(role_name, iam_client)