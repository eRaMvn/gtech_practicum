import boto3
from use_cases import (
    IdentityType,
    extract_principal,
    extract_whitelisted_principals,
    is_whitelisted_principal,
)
from use_cases.iam import IAMType
from use_cases.record import record, record_all_policies_for_users_and_roles
from use_cases.remediate import remediate


def iam_event_handler(event, context):
    principal_type, principal_name = extract_principal(event)
    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()

    if is_whitelisted_principal(
        principal_name, principal_type, whitelisted_users, whitelisted_roles
    ):
        print(f"Principal {principal_name} is whitelisted")
        if principal_type == IdentityType.ASSUMED_ROLE:
            record(event, IAMType.ROLE)
        else:
            record(event, IAMType.IAM_USER)
    else:
        print(f"Principal {principal_name} is NOT whitelisted")
        remediate(event)


def policy_snapshot_handler(event, context):
    iam_client = boto3.client("iam")
    s3_client = boto3.client("s3")
    record_all_policies_for_users_and_roles(iam_client, s3_client)
