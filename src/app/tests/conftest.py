import os

import boto3
import moto
import pytest


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
