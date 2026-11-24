terraform {
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }

    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  function_name          = "alb-logging-remediation"
  bucket_name            = "alb-access-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  lambda_timeout_seconds = 300
  log_prefix             = "alb-access"

  alb_arn_pattern = "arn:${data.aws_partition.current.partition}:elasticloadbalancing:${var.aws_region}:${data.aws_caller_identity.current.account_id}:loadbalancer/app/*"

  # Function-specific namespace avoids merging heartbeat metrics
  # with those from another remediation function in this region.
  metric_namespace = "Custom/ALBLoggingRemediation/${local.function_name}"

  monitoring_alarms = {
    lambda_errors = {
      namespace   = "AWS/Lambda"
      metric_name = "Errors"
      statistic   = "Sum"
      threshold   = 1
      description = "The remediation Lambda encountered an execution error."
      dimensions = {
        FunctionName = aws_lambda_function.remediation.function_name
      }
    }

    lambda_throttles = {
      namespace   = "AWS/Lambda"
      metric_name = "Throttles"
      statistic   = "Sum"
      threshold   = 1
      description = "The remediation Lambda was throttled."
      dimensions = {
        FunctionName = aws_lambda_function.remediation.function_name
      }
    }

    lambda_duration = {
      namespace   = "AWS/Lambda"
      metric_name = "Duration"
      statistic   = "Maximum"
      threshold   = 240000
      description = "Lambda duration reached 240 seconds, 80% of its timeout."
      dimensions = {
        FunctionName = aws_lambda_function.remediation.function_name
      }
    }

    lambda_destination_delivery_failures = {
      namespace   = "AWS/Lambda"
      metric_name = "DestinationDeliveryFailures"
      statistic   = "Sum"
      threshold   = 1
      description = "Lambda could not send a record to its failure destination."
      dimensions = {
        FunctionName = aws_lambda_function.remediation.function_name
      }
    }

    eventbridge_failure_queue = {
      namespace   = "AWS/SQS"
      metric_name = "ApproximateNumberOfMessagesVisible"
      statistic   = "Maximum"
      threshold   = 1
      description = "The EventBridge delivery-failure queue contains messages."
      dimensions = {
        QueueName = aws_sqs_queue.eventbridge_failures.name
      }
    }

    lambda_failure_queue = {
      namespace   = "AWS/SQS"
      metric_name = "ApproximateNumberOfMessagesVisible"
      statistic   = "Maximum"
      threshold   = 1
      description = "The Lambda processing-failure queue contains messages."
      dimensions = {
        QueueName = aws_sqs_queue.lambda_failures.name
      }
    }

    remediation_work_failures = {
      namespace   = "AWS/SQS"
      metric_name = "ApproximateNumberOfMessagesVisible"
      statistic   = "Maximum"
      threshold   = 1
      description = "One or more ALBs exhausted their remediation retries."
      dimensions = {
        QueueName = aws_sqs_queue.remediation_work_failures.name
      }
    }

    remediation_batch_errors = {
      namespace   = local.metric_namespace
      metric_name = "RemediationBatchErrors"
      statistic   = "Sum"
      threshold   = 1
      description = "An ALB remediation batch recorded one or more item errors."
      dimensions  = {}
    }

    remediation_work_age = {
      namespace   = "AWS/SQS"
      metric_name = "ApproximateAgeOfOldestMessage"
      statistic   = "Maximum"
      threshold   = 900
      description = "ALB remediation work has been queued for at least 15 minutes."
      dimensions = {
        QueueName = aws_sqs_queue.remediation_work.name
      }
    }

    inventory_workflow_failed = {
      namespace   = "AWS/States"
      metric_name = "ExecutionsFailed"
      statistic   = "Sum"
      threshold   = 1
      description = "Scheduled or manual ALB reconciliation failed."
      dimensions = {
        StateMachineArn = aws_sfn_state_machine.inventory.arn
      }
    }

    inventory_workflow_timed_out = {
      namespace   = "AWS/States"
      metric_name = "ExecutionsTimedOut"
      statistic   = "Sum"
      threshold   = 1
      description = "ALB reconciliation exceeded its workflow timeout."
      dimensions = {
        StateMachineArn = aws_sfn_state_machine.inventory.arn
      }
    }

    eventbridge_changes_dlq_delivery_failures = {
      namespace   = "AWS/Events"
      metric_name = "InvocationsFailedToBeSentToDlq"
      statistic   = "Sum"
      threshold   = 1
      description = "The ALB change rule could not send an event to its DLQ."
      dimensions = {
        RuleName = aws_cloudwatch_event_rule.alb_changes.name
      }
    }

    eventbridge_scan_dlq_delivery_failures = {
      namespace   = "AWS/Events"
      metric_name = "InvocationsFailedToBeSentToDlq"
      statistic   = "Sum"
      threshold   = 1
      description = "The scheduled scan rule could not send an event to its DLQ."
      dimensions = {
        RuleName = aws_cloudwatch_event_rule.alb_scan.name
      }
    }
  }
}

# ---------------------------------------------------------------------------
# ALB access-log bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "alb_logs" {
  bucket        = local.bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  count  = var.alb_log_retention_days == null ? 0 : 1
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-alb-access-logs"
    status = "Enabled"

    filter {
      prefix = "${local.log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/elasticloadbalancing/${var.aws_region}/"
    }

    expiration {
      days = var.alb_log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowALBLogDelivery"
        Effect = "Allow"
        Principal = {
          Service = "logdelivery.elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/${local.log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:elasticloadbalancing:${var.aws_region}:${data.aws_caller_identity.current.account_id}:loadbalancer/*"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.alb_logs.arn,
          "${aws_s3_bucket.alb_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport"       = "false"
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda execution role and logging
# ---------------------------------------------------------------------------

resource "aws_iam_role" "remediation" {
  name = "${local.function_name}-${var.aws_region}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "remediation" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 90
}

resource "aws_iam_role_policy" "remediation" {
  name = "alb-logging-remediation"
  role = aws_iam_role.remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteFunctionLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.remediation.arn}:*"
      },
      {
        Sid    = "DescribeLoadBalancers"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes"
        ]
        Resource = "*"
      },
      {
        Sid      = "RemediateApplicationLoadBalancers"
        Effect   = "Allow"
        Action   = "elasticloadbalancing:ModifyLoadBalancerAttributes"
        Resource = local.alb_arn_pattern
      },
      {
        Sid      = "SendLambdaFailureRecords"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.lambda_failures.arn
      },
      {
        Sid    = "ProcessRemediationWork"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.remediation_work.arn
      },
      {
        Sid      = "StartInventoryWorkflow"
        Effect   = "Allow"
        Action   = "states:StartExecution"
        Resource = local.inventory_workflow_arn
      },
      {
        Sid      = "ReadRegionalSecurityHubFindings"
        Effect   = "Allow"
        Action   = "securityhub:GetFindings"
        Resource = "arn:${data.aws_partition.current.partition}:securityhub:${var.aws_region}:${data.aws_caller_identity.current.account_id}:hub/default"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Failure queues
# ---------------------------------------------------------------------------

resource "aws_sqs_queue" "eventbridge_failures" {
  name                      = "${local.function_name}-eventbridge-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "lambda_failures" {
  name                      = "${local.function_name}-lambda-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue_policy" "eventbridge_failures" {
  queue_url = aws_sqs_queue.eventbridge_failures.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgeFailureDelivery"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.eventbridge_failures.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.alb_changes.arn,
              aws_cloudwatch_event_rule.alb_scan.arn
            ]
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.eventbridge_failures.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_sqs_queue_policy" "lambda_failures" {
  queue_url = aws_sqs_queue.lambda_failures.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaFailureDelivery"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.remediation.arn
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.lambda_failures.arn
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.lambda_failures.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda function and asynchronous failure destination
# ---------------------------------------------------------------------------

data "archive_file" "remediation" {
  type                    = "zip"
  output_path             = "${path.root}/alb_remediation_lambda.zip"
  source_content          = file("${path.module}/lb-logs-lambda-function.py")
  source_content_filename = "lambda_function.py"
}

resource "aws_lambda_function" "remediation" {
  filename         = data.archive_file.remediation.output_path
  source_code_hash = data.archive_file.remediation.output_base64sha256

  function_name = local.function_name
  role          = aws_iam_role.remediation.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  timeout       = local.lambda_timeout_seconds
  memory_size   = 256

  environment {
    variables = {
      LOG_BUCKET_NAME                     = aws_s3_bucket.alb_logs.bucket
      LOG_PREFIX                          = local.log_prefix
      WORK_QUEUE_URL                      = aws_sqs_queue.remediation_work.url
      WORK_QUEUE_ARN                      = aws_sqs_queue.remediation_work.arn
      INVENTORY_WORKFLOW_ARN              = local.inventory_workflow_arn
      USE_SECURITY_HUB_FOR_SCHEDULED_SCAN = tostring(var.use_security_hub_for_scheduled_scan)
    }
  }

  depends_on = [
    aws_iam_role_policy.remediation,
    aws_s3_bucket_policy.alb_logs,
    aws_s3_bucket_public_access_block.alb_logs,
    aws_s3_bucket_server_side_encryption_configuration.alb_logs,
    aws_cloudwatch_log_group.remediation
  ]
}

resource "aws_lambda_function_event_invoke_config" "remediation" {
  function_name = aws_lambda_function.remediation.function_name

  maximum_event_age_in_seconds = 21600
  maximum_retry_attempts       = 2

  destination_config {
    on_failure {
      destination = aws_sqs_queue.lambda_failures.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.remediation,
    aws_sqs_queue_policy.lambda_failures
  ]
}

# ---------------------------------------------------------------------------
# EventBridge: ALB configuration changes
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "alb_changes" {
  name = "alb-logging-configuration-changes"

  event_pattern = jsonencode({
    source        = ["aws.elasticloadbalancing"]
    "detail-type" = ["AWS API Call via CloudTrail"]

    detail = {
      eventSource = ["elasticloadbalancing.amazonaws.com"]
      apiVersion  = ["2015-12-01"]
      errorCode   = [{ exists = false }]
      eventName = [
        "CreateLoadBalancer",
        "ModifyLoadBalancerAttributes"
      ]
    }
  })
}

resource "aws_lambda_permission" "alb_changes" {
  statement_id  = "AllowALBChangeEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alb_changes.arn
}

resource "aws_cloudwatch_event_target" "alb_changes" {
  rule      = aws_cloudwatch_event_rule.alb_changes.name
  target_id = "ALBLoggingRemediation"
  arn       = aws_lambda_function.remediation.arn

  dead_letter_config {
    arn = aws_sqs_queue.eventbridge_failures.arn
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }

  depends_on = [
    aws_sqs_queue_policy.eventbridge_failures,
    aws_lambda_permission.alb_changes,
    aws_lambda_function_event_invoke_config.remediation,
    aws_lambda_event_source_mapping.remediation_work
  ]
}

# ---------------------------------------------------------------------------
# EventBridge: daily inventory scan
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "alb_scan" {
  name                = "alb-logging-scheduled-scan"
  schedule_expression = "rate(1 day)"
}

resource "aws_lambda_permission" "alb_scan" {
  statement_id  = "AllowScheduledALBScan"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alb_scan.arn
}

resource "aws_cloudwatch_event_target" "alb_scan" {
  rule      = aws_cloudwatch_event_rule.alb_scan.name
  target_id = "ALBLoggingInventoryScan"
  arn       = aws_lambda_function.remediation.arn

  dead_letter_config {
    arn = aws_sqs_queue.eventbridge_failures.arn
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }

  depends_on = [
    aws_sqs_queue_policy.eventbridge_failures,
    aws_lambda_permission.alb_scan,
    aws_lambda_function_event_invoke_config.remediation,
    aws_lambda_event_source_mapping.remediation_work,
    aws_sfn_state_machine.inventory,
    aws_cloudwatch_log_metric_filter.inventory_scan_success
  ]
}

# ---------------------------------------------------------------------------
# Standard operational alarms
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "remediation_health" {
  for_each = local.monitoring_alarms

  alarm_name        = "${local.function_name}-${replace(each.key, "_", "-")}"
  alarm_description = each.value.description

  namespace   = each.value.namespace
  metric_name = each.value.metric_name
  dimensions  = each.value.dimensions
  statistic   = each.value.statistic

  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = each.value.threshold

  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1

  treat_missing_data = "notBreaching"

  alarm_actions             = var.alarm_action_arns
  ok_actions                = []
  insufficient_data_actions = []
}

# ---------------------------------------------------------------------------
# One custom metric: scheduled inventories fully queued for remediation
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "inventory_scan_success" {
  name           = "${local.function_name}-inventory-scan-success"
  log_group_name = aws_cloudwatch_log_group.remediation.name

  pattern = "{ $.event = \"inventory_enqueued\" && $.scheduled IS TRUE }"

  metric_transformation {
    name      = "InventoryScanSuccess"
    namespace = local.metric_namespace
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "remediation_batch_errors" {
  name           = "${local.function_name}-batch-errors"
  log_group_name = aws_cloudwatch_log_group.remediation.name
  pattern        = "{ $.event = \"remediation_batch_completed\" && $.failed > 0 }"

  metric_transformation {
    name      = "RemediationBatchErrors"
    namespace = local.metric_namespace
    value     = "$.failed"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "inventory_scan_missing" {
  alarm_name = "${local.function_name}-inventory-scan-missing"

  alarm_description = join(" ", [
    "Scheduled reconciliations did not finish queueing work in consecutive daily periods.",
    "Check the schedule, Step Functions executions, and Lambda logs."
  ])

  namespace   = local.metric_namespace
  metric_name = "InventoryScanSuccess"

  statistic           = "Sum"
  comparison_operator = "LessThanThreshold"
  threshold           = 1

  period              = 86400
  evaluation_periods  = 2
  datapoints_to_alarm = 2

  treat_missing_data = "breaching"

  alarm_actions             = var.alarm_action_arns
  ok_actions                = []
  insufficient_data_actions = []

  depends_on = [
    aws_cloudwatch_log_metric_filter.inventory_scan_success
  ]
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "alb_log_bucket_name" {
  value = aws_s3_bucket.alb_logs.bucket
}

output "remediation_lambda_name" {
  value = aws_lambda_function.remediation.function_name
}

output "eventbridge_failure_queue_url" {
  value = aws_sqs_queue.eventbridge_failures.url
}

output "eventbridge_failure_queue_arn" {
  value = aws_sqs_queue.eventbridge_failures.arn
}

output "lambda_failure_queue_url" {
  value = aws_sqs_queue.lambda_failures.url
}

output "lambda_failure_queue_arn" {
  value = aws_sqs_queue.lambda_failures.arn
}

output "inventory_scan_missing_alarm_name" {
  value = aws_cloudwatch_metric_alarm.inventory_scan_missing.alarm_name
}

output "operational_alarm_names" {
  value = {
    for key, alarm in aws_cloudwatch_metric_alarm.remediation_health :
    key => alarm.alarm_name
  }
}
