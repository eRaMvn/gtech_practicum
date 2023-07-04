from diagrams import Cluster, Diagram
from diagrams.aws.compute import Lambda
from diagrams.aws.management import Cloudtrail, CloudwatchEventEventBased
from diagrams.aws.security import (
    IAMPermissions,
    IdentityAndAccessManagementIam,
    SecretsManager,
)
from diagrams.aws.storage import S3
from diagrams.onprem.ci import GithubActions, Jenkins, TravisCI
from diagrams.onprem.iac import Atlantis, Terraform

graph_attr = {
    "fontsize": "20",
    "bgcolor": "transparent",
    # "bgcolor": "white",
}

with Diagram(
    "monitor_policy_changes", show=False, direction="TB", graph_attr=graph_attr
):
    with Cluster("IaC"):
        terraform_resources = Terraform("terraform_resources")
        atlantis = Atlantis("atlantis")

    with Cluster("CI/CD"):
        ci_cd = [
            Jenkins("jenkins"),
            GithubActions("github actions"),
            TravisCI("travis ci"),
        ]
        iam_creds = IdentityAndAccessManagementIam("iam_creds")

    with Cluster("AWS"):
        cloudtrail_logs = Cloudtrail("cloudtrail_logs")
        cloudwatch_events = CloudwatchEventEventBased("iam_events")
        cloudwatch_cron = CloudwatchEventEventBased("cron_job")

        handle_policy_event_lambda = Lambda("event_handler")
        snapshot_cron_lambda = Lambda("policy_snapshot")

        resource_bucket = S3("policy_store")
        iam_permissions = IAMPermissions("iam_permissions")

    # IaC
    terraform_resources >> ci_cd  # type: ignore
    atlantis >> ci_cd  # type: ignore

    # CI/CD
    iam_creds >> resource_bucket  # type: ignore
    ci_cd >> iam_creds  # type: ignore

    # Cloudtrail events
    (
        cloudtrail_logs  # type: ignore
        >> cloudwatch_events
        >> handle_policy_event_lambda
        >> resource_bucket
    )

    # Cloudwatch cron
    cloudwatch_cron >> snapshot_cron_lambda >> resource_bucket  # type: ignore

    # Lambda functions
    handle_policy_event_lambda >> iam_permissions  # type: ignore