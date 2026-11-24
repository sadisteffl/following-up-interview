variable "aws_region" {
  description = "AWS region containing the ALBs and remediation resources."
  type        = string
}

variable "alarm_action_arns" {
  description = "Existing SNS topic ARNs for operational alarm notifications."
  type        = list(string)

  validation {
    condition = (
      length(var.alarm_action_arns) > 0 &&
      alltrue([
        for arn in var.alarm_action_arns :
        can(regex("^arn:[^:]+:sns:[^:]+:[0-9]{12}:.+$", arn))
      ])
    )

    error_message = "Provide at least one valid SNS topic ARN."
  }
}