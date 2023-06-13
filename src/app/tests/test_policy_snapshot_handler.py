import json


from app.lambda_func.use_cases.constants import (
    BUCKET_NAME,
)
from app.lambda_func.use_cases.iam import IAMPolicy, create_managed_policy
from app.lambda_func.use_cases.record import record_all_policies_for_users_and_roles

from .constants import (
    TEST_INLINE_POLICY,
    TEST_INLINE_POLICY_NAME,
    TEST_MANAGED_POLICY,
    TEST_MANAGED_POLICY_NAME,
    TEST_ROLE_NAME,
)

from .utils import (
    create_role_with_inline_policies,

)


def test_policy_snapshot_handler(iam_client, s3_client):
    iam_guide = IAMPolicy()

    create_role_with_inline_policies(iam_client)
    test_policy_arn = create_managed_policy(
        TEST_MANAGED_POLICY_NAME, TEST_MANAGED_POLICY, iam_client
    )
    iam_client.attach_role_policy(RoleName=TEST_ROLE_NAME, PolicyArn=test_policy_arn)

    s3_client.create_bucket(Bucket=BUCKET_NAME)

    record_all_policies_for_users_and_roles(iam_client, s3_client)
    managed_policies_list_path = iam_guide.get_s3_managed_policies_list_path(
        TEST_ROLE_NAME
    )
    response = s3_client.get_object(Bucket=BUCKET_NAME, Key=managed_policies_list_path)
    assert json.loads(response["Body"].read().decode("utf-8")) == [
        f"arn:aws:iam::123456789012:policy/{TEST_MANAGED_POLICY_NAME}"
    ]

    role_inline_policy_s3_path = iam_guide.get_s3_inline_path(TEST_ROLE_NAME, TEST_INLINE_POLICY_NAME)
    response = s3_client.get_object(Bucket=BUCKET_NAME, Key=role_inline_policy_s3_path)
    assert json.loads(response["Body"].read().decode("utf-8")) == TEST_INLINE_POLICY

    role_managed_policy_s3_path = iam_guide.get_s3_managed_path(TEST_MANAGED_POLICY_NAME)
    response = s3_client.get_object(Bucket=BUCKET_NAME, Key=role_managed_policy_s3_path)
    assert json.loads(response["Body"].read().decode("utf-8")) == TEST_MANAGED_POLICY