locals {
  inventory_workflow_name = "${local.function_name}-inventory"
  inventory_workflow_arn  = "arn:${data.aws_partition.current.partition}:states:${var.aws_region}:${data.aws_caller_identity.current.account_id}:stateMachine:${local.inventory_workflow_name}"
}

resource "aws_iam_role" "inventory_workflow" {
  name = "${local.inventory_workflow_name}-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "states.amazonaws.com" }
      Condition = {
        ArnEquals    = { "aws:SourceArn" = local.inventory_workflow_arn }
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "inventory_workflow" {
  name = "invoke-inventory-lambda"
  role = aws_iam_role.inventory_workflow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.remediation.arn
    }]
  })
}

resource "aws_sfn_state_machine" "inventory" {
  name     = local.inventory_workflow_name
  role_arn = aws_iam_role.inventory_workflow.arn
  type     = "STANDARD"

  definition = jsonencode({
    StartAt        = "Queue inventory page"
    TimeoutSeconds = 7200
    States = {
      "Queue inventory page" = {
        Type     = "Task"
        Resource = aws_lambda_function.remediation.arn
        Parameters = {
          mode              = "inventory_page"
          "marker.$"        = "$.page.marker"
          "queued.$"        = "$.page.queued"
          "scheduled.$"     = "$.scheduled"
          "use_findings.$"  = "$.use_findings"
          "execution_arn.$" = "$$.Execution.Id"
        }
        ResultPath = "$.page"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          BackoffRate     = 2
          MaxAttempts     = 5
          JitterStrategy  = "FULL"
        }]
        Next = "More inventory pages?"
      }
      "More inventory pages?" = {
        Type = "Choice"
        Choices = [{
          Variable = "$.page.marker"
          IsNull   = true
          Next     = "Inventory queued"
        }]
        Default = "Queue inventory page"
      }
      "Inventory queued" = {
        Type = "Succeed"
      }
    }
  })

  depends_on = [aws_iam_role_policy.inventory_workflow]
}

resource "aws_sqs_queue" "remediation_work_failures" {
  name                      = "${local.function_name}-work-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "remediation_work" {
  name                       = "${local.function_name}-work"
  visibility_timeout_seconds = 6 * local.lambda_timeout_seconds
  message_retention_seconds  = 345600
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.remediation_work_failures.arn
    maxReceiveCount     = 5
  })
}

resource "aws_lambda_event_source_mapping" "remediation_work" {
  event_source_arn        = aws_sqs_queue.remediation_work.arn
  function_name           = aws_lambda_function.remediation.arn
  batch_size              = 10
  function_response_types = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = var.remediation_max_concurrency
  }

  depends_on = [
    aws_iam_role_policy.remediation,
    aws_cloudwatch_log_metric_filter.remediation_batch_errors
  ]
}

output "inventory_workflow_arn" {
  value = aws_sfn_state_machine.inventory.arn
}

output "remediation_work_failure_queue_url" {
  value = aws_sqs_queue.remediation_work_failures.url
}
