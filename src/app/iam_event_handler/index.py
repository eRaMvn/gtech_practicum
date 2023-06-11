from .record import record
from .remediate import remediate
from .utils import (
    extract_principal,
    extract_whitelisted_principals,
    is_whitelisted_principal,
)


def lambda_handler(event, context):
    principal_type, principal_name = extract_principal(event)
    whitelisted_users, whitelisted_roles = extract_whitelisted_principals()

    if is_whitelisted_principal(
        principal_type, principal_name, whitelisted_users, whitelisted_roles
    ):
        record(event)
    else:
        remediate(event)
