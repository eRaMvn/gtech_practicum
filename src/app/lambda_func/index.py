from use_cases import (
    extract_principal,
    extract_whitelisted_principals,
    is_whitelisted_principal,
)
from use_cases.record import record
from use_cases.remediate import remediate


def iam_event_handler(event, context):
    principal_type, principal_name = extract_principal(event)
    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()

    if is_whitelisted_principal(
        principal_type, principal_name, whitelisted_users, whitelisted_roles
    ):
        record(event)
    else:
        remediate(event)


def policy_snapshot_handler(event, context):
    return {"statusCode": 200, "body": "Hello from Lambda!"}
