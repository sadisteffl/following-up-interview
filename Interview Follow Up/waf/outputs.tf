output "web_acl_arn" {
  description = "ARN of the WAF Web ACL."
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the WAF Web ACL."
  value       = aws_wafv2_web_acl.this.id
}

output "log_group_name" {
  description = "CloudWatch log group for WAF events."
  value       = aws_cloudwatch_log_group.waf.name
}
