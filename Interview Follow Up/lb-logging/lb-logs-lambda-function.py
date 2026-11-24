import json
import logging
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

LOG_BUCKET_NAME = os.environ["LOG_BUCKET_NAME"]
LOG_PREFIX = os.environ.get("LOG_PREFIX", "alb-access").strip("/")
AWS_REGION = os.environ["AWS_REGION"]
WORK_QUEUE_URL = os.environ["WORK_QUEUE_URL"]
WORK_QUEUE_ARN = os.environ["WORK_QUEUE_ARN"]
INVENTORY_WORKFLOW_ARN = os.environ["INVENTORY_WORKFLOW_ARN"]
USE_SECURITY_HUB_FOR_SCHEDULED_SCAN = (
    os.environ.get("USE_SECURITY_HUB_FOR_SCHEDULED_SCAN") == "true"
)

# A work item can make two ELB calls, each with SDK timeouts and retries.
MIN_WORK_ITEM_TIME_MS = 150_000

client_config = Config(
    connect_timeout=5,
    read_timeout=15,
    retries={"mode": "standard", "total_max_attempts": 3},
)
elbv2 = boto3.client("elbv2", config=client_config)
sqs = boto3.client("sqs", config=client_config)
step_functions = boto3.client("stepfunctions", config=client_config)
security_hub = boto3.client("securityhub", config=client_config)


def is_application_load_balancer(arn):
    return (
        isinstance(arn, str)
        and ":loadbalancer/app/" in arn
    )


def remediate_load_balancer(arn):
    try:
        response = elbv2.describe_load_balancer_attributes(
            LoadBalancerArn=arn
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return "deleted"
        raise

    attributes = {
        item["Key"]: item["Value"]
        for item in response["Attributes"]
    }

    desired = {
        "access_logs.s3.enabled": "true",
        "access_logs.s3.bucket": LOG_BUCKET_NAME,
        "access_logs.s3.prefix": LOG_PREFIX,
    }

    if all(
        attributes.get(key) == value
        for key, value in desired.items()
    ):
        return "already_enabled"

    try:
        elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=arn,
            Attributes=[
                {"Key": key, "Value": value}
                for key, value in desired.items()
            ],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return "deleted"
        raise

    return "remediated"


def enqueue_load_balancers(arns):
    # SQS accepts up to ten messages per API call.
    for offset in range(0, len(arns), 10):
        response = sqs.send_message_batch(
            QueueUrl=WORK_QUEUE_URL,
            Entries=[
                {"Id": str(index), "MessageBody": json.dumps({"arn": arn})}
                for index, arn in enumerate(arns[offset:offset + 10])
            ],
        )
        if response.get("Failed"):
            raise RuntimeError(f"SQS failed to queue ALB work: {response['Failed']}")


def list_inventory_page(marker):
    request = {"PageSize": 50}
    if marker:
        request["Marker"] = marker
    page = elbv2.describe_load_balancers(**request)
    arns = [
        lb["LoadBalancerArn"] for lb in page["LoadBalancers"]
        if lb["Type"] == "application"
    ]
    return arns, page.get("NextMarker") or None


def list_open_finding_page(marker, function_arn):
    _, partition, _, region, account, _ = function_arn.split(":", 5)
    resource_type = "AwsElbv2LoadBalancer"
    allowed_arn_prefix = f"arn:{partition}:elasticloadbalancing:{region}:{account}:loadbalancer/app/"
    filter_values = {
        "ComplianceSecurityControlId": ["ELB.5"],
        "ComplianceStatus": ["FAILED"],
        "RecordState": ["ACTIVE"],
        "WorkflowStatus": ["NEW", "NOTIFIED"],
        "AwsAccountId": [account],
        "ResourceRegion": [region],
        "ResourceType": [resource_type],
        "ProductArn": [f"arn:{partition}:securityhub:{region}::product/aws/securityhub"],
    }
    request = {
        "Filters": {
            key: [{"Comparison": "EQUALS", "Value": value} for value in values]
            for key, values in filter_values.items()
        },
        "MaxResults": 50,
    }
    if marker:
        request["NextToken"] = marker
    page = security_hub.get_findings(**request)
    arns = sorted({
        resource["Id"]
        for finding in page["Findings"]
        for resource in finding["Resources"]
        if resource["Type"] == resource_type and resource["Id"].startswith(allowed_arn_prefix)
    })
    return arns, page.get("NextToken") or None


def enqueue_inventory_page(event, context):
    use_findings = event.get("use_findings") is True
    if use_findings:
        arns, next_marker = list_open_finding_page(event["marker"], context.invoked_function_arn)
    else:
        arns, next_marker = list_inventory_page(event["marker"])

    # Persist the cursor only after all ALBs from this page are queued.
    # A retry may enqueue duplicates. The worker checks current state first.
    enqueue_load_balancers(arns)
    queued = event["queued"] + len(arns)
    if next_marker is None:
        print(json.dumps({
            "event": "inventory_enqueued",
            "scheduled": event["scheduled"],
            "source": "security_hub" if use_findings else "elb_inventory",
            "execution_arn": event["execution_arn"],
            "region": AWS_REGION,
            "queued": queued,
        }), flush=True)
    return {"marker": next_marker, "queued": queued}


def start_inventory_scan(event):
    scheduled = event.get("scheduled") is True
    use_findings = event.get("mode") == "import_findings" or (
        scheduled and USE_SECURITY_HUB_FOR_SCHEDULED_SCAN
    )
    request = {
        "stateMachineArn": INVENTORY_WORKFLOW_ARN,
        "input": json.dumps({
            "scheduled": scheduled,
            "use_findings": use_findings,
            "page": {"marker": None, "queued": 0},
        }),
    }
    if scheduled and event.get("scan_id"):
        request["name"] = event["scan_id"]
    try:
        response = step_functions.start_execution(**request)
    except step_functions.exceptions.ExecutionAlreadyExists:
        if "name" not in request:
            raise
        return {"status": "scan_already_started", "scan_id": request["name"]}
    return {"status": "scan_started", "execution_arn": response["executionArn"]}


def event_load_balancer_arns(detail):
    arns = set()

    request = detail.get("requestParameters") or {}
    response = detail.get("responseElements") or {}

    request_arn = request.get("loadBalancerArn")
    if request_arn:
        arns.add(request_arn)

    for load_balancer in response.get("loadBalancers") or []:
        arn = load_balancer.get("loadBalancerArn")
        if arn:
            arns.add(arn)

    return sorted(
        arn for arn in arns
        if is_application_load_balancer(arn)
    )


def process_remediation_batch(records, context):
    counts = {"remediated": 0, "already_enabled": 0, "deleted": 0, "failed": 0, "deferred": 0}
    failures = []

    for index, record in enumerate(records):
        if context.get_remaining_time_in_millis() < MIN_WORK_ITEM_TIME_MS:
            pending = records[index:]
            counts["deferred"] = len(pending)
            failures.extend({"itemIdentifier": item["messageId"]} for item in pending)
            break

        message_id = record["messageId"]
        arn = None
        try:
            if record.get("eventSourceARN") != WORK_QUEUE_ARN:
                raise ValueError("Unexpected work queue ARN.")
            arn = json.loads(record["body"])["arn"]
            if not is_application_load_balancer(arn):
                raise ValueError("Work queue item does not contain an ALB ARN.")

            outcome = remediate_load_balancer(arn)
            counts[outcome] += 1
            if outcome == "remediated":
                logger.info("Remediated ALB access logging: %s", arn)
        except Exception:
            counts["failed"] += 1
            failures.append({"itemIdentifier": message_id})
            logger.exception("ALB remediation failed for message %s, ALB %s", message_id, arn)

    print(json.dumps({"event": "remediation_batch_completed", **counts}), flush=True)
    return {"batchItemFailures": failures}


def lambda_handler(event, context):
    if "Records" in event:
        return process_remediation_batch(event["Records"], context)

    if event.get("mode") in {"scan", "import_findings"}:
        return start_inventory_scan(event)

    if event.get("source") == "aws.events" and event.get("detail-type") == "Scheduled Event":
        return start_inventory_scan({"scheduled": True, "scan_id": event["id"]})

    if event.get("mode") == "inventory_page":
        return enqueue_inventory_page(event, context)

    if (
        event.get("source") != "aws.elasticloadbalancing"
        or event.get("detail-type") != "AWS API Call via CloudTrail"
    ):
        raise ValueError(
            'Unsupported event. Use {"mode": "scan"} for ALB inventory or '
            '{"mode": "import_findings"} for an open Security Hub findings import.'
        )

    detail = event.get("detail") or {}

    if detail.get("errorCode"):
        logger.info(
            "Ignoring unsuccessful ELB API call: %s",
            detail.get("eventName"),
        )
        return {"status": "ignored_failed_api_call"}

    arns = event_load_balancer_arns(detail)

    if not arns:
        logger.info("ELB event contains no application load balancer ARN.")
        return {"status": "ignored_no_alb_arn"}

    enqueue_load_balancers(arns)
    return {"status": "queued", "count": len(arns)}
