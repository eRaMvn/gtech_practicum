import os
import time

import boto3
import moto
import pytest

from app.lambda_func.use_cases.iam import (
    IAMType,
    detach_managed_policies_from_principal,
    get_managed_policies_for_principal,
)

from .constants import (
    CASE_1_ROLE_NAME,
    CASE_2_ROLE_NAME,
    CASE_3_ROLE_NAME,
    DESIGNATED_ROLE_NAME,
    INTEGRATION_MANAGED_POLICY_ARN,
    MALICIOUS_ROLE_NAME,
)
from .utils import create_iam_role, create_role_with_managed_policies


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def mock_iam_client(aws_credentials):
    with moto.mock_iam():
        yield boto3.client("iam")


@pytest.fixture(scope="function")
def mock_s3_client(aws_credentials):
    with moto.mock_s3():
        yield boto3.client("s3", region_name="us-east-1")


sts_client = boto3.client("sts")


def create_custom_clients(role_arn: str, session_name: str):
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name
        )

        # Extract the temporary credentials
        credentials = response["Credentials"]
        access_key = credentials["AccessKeyId"]
        secret_key = credentials["SecretAccessKey"]
        session_token = credentials["SessionToken"]

        # Create a new session with the assumed role credentials
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
        return session.client("iam"), session.resource("s3")
    except BaseException:
        raise Exception(
            f"Failed to create custom clients for {session_name} and it could be due to the role does not exist."
        )


def clean_up_test_roles(iam_client):
    roles_to_delete = [CASE_1_ROLE_NAME, CASE_2_ROLE_NAME, CASE_3_ROLE_NAME]
    for role_name in roles_to_delete:
        try:
            managed_policy_arns = get_managed_policies_for_principal(
                role_name, IAMType.ROLE, iam_client
            )
            if managed_policy_arns:
                detach_managed_policies_from_principal(
                    managed_policy_arns, role_name, IAMType.ROLE, iam_client
                )

            iam_client.delete_role(RoleName=role_name)
        except BaseException:
            pass


def case_1_create_role_with_unapproved_creds(unapproved_iam_client):
    create_role_with_managed_policies(unapproved_iam_client, CASE_1_ROLE_NAME)


def case_2_update_principal_by_adding_attach_managed_policy(
    approved_iam_client, unapproved_iam_client
):
    create_iam_role(approved_iam_client, CASE_2_ROLE_NAME)
    unapproved_iam_client.attach_role_policy(
        RoleName=DESIGNATED_ROLE_NAME, PolicyArn=INTEGRATION_MANAGED_POLICY_ARN
    )


def case_3_update_principal_by_detaching_managed_policy(
    approved_iam_client, unapproved_iam_client
):
    create_role_with_managed_policies(approved_iam_client, CASE_3_ROLE_NAME)
    unapproved_iam_client.detach_role_policy(
        RoleName=CASE_3_ROLE_NAME, PolicyArn=INTEGRATION_MANAGED_POLICY_ARN
    )


def create_use_cases(thor_iam_client, loki_iam_client):
    case_1_create_role_with_unapproved_creds(loki_iam_client)
    case_2_update_principal_by_adding_attach_managed_policy(
        thor_iam_client, loki_iam_client
    )
    case_3_update_principal_by_detaching_managed_policy(
        thor_iam_client, loki_iam_client
    )


@pytest.fixture
def setup_integration_testing():
    iam_base_arn = "arn:aws:iam::014824332634:role/"

    thor_iam_client, thor_s3_client = create_custom_clients(
        iam_base_arn + DESIGNATED_ROLE_NAME, "thor"
    )
    loki_iam_client, loki_s3_client = create_custom_clients(
        iam_base_arn + MALICIOUS_ROLE_NAME, "loki"
    )
    clean_up_test_roles(thor_iam_client)
    time.sleep(10)
    create_use_cases(thor_iam_client, loki_iam_client)
    time.sleep(90)
    yield thor_iam_client, loki_iam_client
