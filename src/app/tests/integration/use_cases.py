
from app.lambda_func.use_cases.iam import IAMType

from ..constants import (
    CASE_1_ROLE_NAME,
    CASE_2_ROLE_NAME,
    CASE_3_ROLE_NAME,
    INTEGRATION_MANAGED_POLICY_ARN,
)
from ..utils import (
    validate_managed_policy_is_attached,
    validate_managed_policy_is_detached,
    validate_principal_is_deleted,
)


def test_use_cases(setup_integration_testing):
    thor_iam_client, loki_iam_client = setup_integration_testing

    validate_principal_is_deleted(CASE_1_ROLE_NAME, IAMType.ROLE, thor_iam_client)
    validate_managed_policy_is_detached(
        CASE_2_ROLE_NAME, IAMType.ROLE, INTEGRATION_MANAGED_POLICY_ARN, thor_iam_client
    )
    validate_managed_policy_is_attached(
        CASE_3_ROLE_NAME, IAMType.ROLE, INTEGRATION_MANAGED_POLICY_ARN, thor_iam_client
    )