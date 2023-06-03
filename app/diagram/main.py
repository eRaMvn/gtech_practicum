from diagrams import Cluster, Diagram
from diagrams.aws.compute import Lambda
from diagrams.aws.storage import S3
from diagrams.aws.management import CloudwatchEventEventBased, Cloudtrail
from diagrams.onprem.ci import Jenkins, GithubActions, TravisCI
from diagrams.aws.security import IAMPermissions
from diagrams.aws.security import IdentityAndAccessManagementIam
from diagrams.onprem.iac import Atlantis, Terraform
from diagrams.aws.security import SecretsManager

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

        secret_manager = SecretsManager("secret_manager")

        resource_bucket = S3("policy_store")
        iam_permissions = IAMPermissions("iam_permissions")

    # IaC
    terraform_resources >> ci_cd
    atlantis >> ci_cd

    # CI/CD
    iam_creds >> resource_bucket
    ci_cd >> iam_creds

    # Cloudtrail events
    cloudtrail_logs >> cloudwatch_events >> handle_policy_event_lambda >> resource_bucket

    # Cloudwatch cron
    cloudwatch_cron >> snapshot_cron_lambda >> resource_bucket

    # Lambda functions
    handle_policy_event_lambda >> iam_permissions

    # Secrets manager
    secret_manager >> handle_policy_event_lambda