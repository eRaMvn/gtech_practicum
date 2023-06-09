import boto3
import moto
import pytest


@pytest.fixture
def iam_client():
    with moto.mock_iam():
        yield boto3.client("iam")


@pytest.fixture
def s3_client():
    with moto.mock_s3():
        yield boto3.client("s3", region_name="us-east-1")
