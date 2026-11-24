locals {
  managed_groups = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesSQLiRuleSet"
  ]

  managed_block_overrides = {
    AWSManagedRulesAmazonIpReputationList = ["AWSManagedIPDDoSList"]
    AWSManagedRulesKnownBadInputsRuleSet = [
      "ApacheMod_HTTP2",
      "Java4Shell_AUTHORIZATION_HEADER",
      "Java4Shell_BODY",
      "Java4Shell_HEADER",
      "Java4Shell_QUERYARGUMENTS",
      "Ruby2Shell_METHODOVERRIDE_HEADER",
      "Ruby2Shell_MethodOverride_BODY",
      "Ruby2Shell_MULTIPARTMETHOD"
    ]
  }

  sensitive_headers = toset([
    # Authentication and authorization
    "authorization",
    "proxy-authorization",
    "cookie",

    # API credentials
    "api-key",
    "x-api-key",
    "x-api-token",
    "x-auth-token",
    "x-access-token",
    "x-refresh-token",
    "x-client-secret",

    # Session and browser security
    "x-session-id",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",

    # Third-party integration credentials
    "x-partner-token",
    "x-partner-key",
    "x-integration-token",
    "x-integration-key",

    # Request authentication and signatures
    "x-signature",
    "x-hub-signature",
    "x-hub-signature-256",
    "x-amz-security-token",

    # Advertising and privacy identifiers
    "x-device-id",
    "x-user-id",
    "x-impression-id",
    "x-consent-string"
  ])

  protected_fields = {
    SINGLE_HEADER = local.sensitive_headers
    QUERY_STRING  = null
    BODY          = null
  }

  scoped_rate_routes = var.ad_sales == null ? {} : {
    for name, route in merge(
      { for name, route in var.ad_sales.api_rate_limits : "AdSalesRate-${name}" => route },
      { for name, route in var.ad_sales.browser_rate_limits : "AdSalesBrowserRate-${name}" => route }
    ) : name => route if route.limit != null || var.rate_limit != null
  }

  payload_routes = var.ad_sales == null ? {} : var.ad_sales.payload_protection
  blocking_payload_routes = {
    for name, route in local.payload_routes : name => route if route.block_injection
  }

  routes = merge(
    local.scoped_rate_routes,
    { for name, route in local.payload_routes : "AdSalesPayload-${name}" => route }
  )

  route_matches = {
    for name, route in local.routes : name => merge(
      {
        hostname = {
          search_string         = lower(route.hostname)
          positional_constraint = "EXACTLY"
          transformation        = "LOWERCASE"
        }
        path_prefix = {
          search_string         = route.path_prefix
          positional_constraint = "STARTS_WITH"
          transformation        = "NONE"
        }
      },
      route.http_method == null ? {} : {
        http_method = {
          search_string         = upper(route.http_method)
          positional_constraint = "EXACTLY"
          transformation        = "NONE"
        }
      }
    )
  }

  rate_rules = merge(
    var.rate_limit == null ? {} : {
      SourceIpRateLimit = {
        evaluation_window_sec = 300
        limit                 = var.rate_limit
        forwarded_ip_header   = var.rate_limit_forwarded_ip_header
        identity_header       = null
        scoped                = false
      }
    },
    {
      for name, route in local.scoped_rate_routes : name => {
        evaluation_window_sec = route.evaluation_window_sec
        limit                 = route.limit == null ? var.rate_limit : route.limit
        forwarded_ip_header   = route.forwarded_ip_header
        identity_header       = route.identity_header
        scoped                = true
      }
    }
  )

  payload_rules = merge(
    {
      for index, name in keys(local.payload_routes) : "AdSalesPayload-${name}" => {
        route_key         = "AdSalesPayload-${name}"
        priority          = length(local.rate_rules) + index
        block             = false
        inspect_injection = !local.payload_routes[name].block_injection
      }
    },
    {
      for index, name in keys(local.blocking_payload_routes) : "AdSalesInjection-${name}" => {
        route_key         = "AdSalesPayload-${name}"
        priority          = length(local.rate_rules) + length(local.payload_routes) + index
        block             = true
        inspect_injection = true
      }
    }
  )

  # Keep metric names readable and unique even for arbitrary route keys.
  rule_names = {
    for name in concat(keys(local.routes), [
      for name in keys(local.blocking_payload_routes) : "AdSalesInjection-${name}"
    ]) :
    name => "${substr(replace(name, "/[^A-Za-z0-9_-]/", "-"), 0, 80)}-${substr(sha1(name), 0, 12)}"
  }
}

resource "aws_wafv2_web_acl" "this" {
  name  = var.name
  scope = var.scope
  tags  = var.tags

  default_action {
    allow {}
  }

  data_protection_config {
    dynamic "data_protection" {
      for_each = local.protected_fields

      content {
        action = "SUBSTITUTION"

        field {
          field_type = data_protection.key
          field_keys = data_protection.value
        }
      }
    }
  }

  # Enforce application-wide and route-specific rate limits.
  dynamic "rule" {
    for_each = local.rate_rules
    iterator = rate_rule

    content {
      name     = lookup(local.rule_names, rate_rule.key, rate_rule.key)
      priority = index(keys(local.rate_rules), rate_rule.key)

      action {
        block {}
      }

      statement {
        rate_based_statement {
          aggregate_key_type = (
            rate_rule.value.forwarded_ip_header != null ? "FORWARDED_IP" :
            rate_rule.value.identity_header != null ? "CUSTOM_KEYS" : "IP"
          )
          evaluation_window_sec = rate_rule.value.evaluation_window_sec
          limit                 = rate_rule.value.limit

          dynamic "forwarded_ip_config" {
            for_each = rate_rule.value.forwarded_ip_header[*]

            content {
              header_name       = lower(forwarded_ip_config.value)
              fallback_behavior = "MATCH"
            }
          }

          dynamic "custom_key" {
            for_each = rate_rule.value.identity_header[*]

            content {
              header {
                name = lower(custom_key.value)

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }

          dynamic "scope_down_statement" {
            for_each = rate_rule.value.scoped ? [rate_rule.key] : []

            content {
              and_statement {
                dynamic "statement" {
                  for_each = local.route_matches[scope_down_statement.value]

                  content {
                    byte_match_statement {
                      search_string         = statement.value.search_string
                      positional_constraint = statement.value.positional_constraint

                      field_to_match {
                        dynamic "single_header" {
                          for_each = statement.key == "hostname" ? [1] : []
                          content {
                            name = "host"
                          }
                        }

                        dynamic "uri_path" {
                          for_each = statement.key == "path_prefix" ? [1] : []
                          content {}
                        }

                        dynamic "method" {
                          for_each = statement.key == "http_method" ? [1] : []
                          content {}
                        }
                      }

                      text_transformation {
                        priority = 0
                        type     = statement.value.transformation
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = lookup(local.rule_names, rate_rule.key, rate_rule.key)
        sampled_requests_enabled   = false
      }
    }
  }

  dynamic "rule" {
    for_each = local.payload_rules
    iterator = payload_rule

    content {
      name     = local.rule_names[payload_rule.key]
      priority = payload_rule.value.priority

      action {
        dynamic "count" {
          for_each = payload_rule.value.block ? [] : [1]
          content {}
        }

        dynamic "block" {
          for_each = payload_rule.value.block ? [1] : []
          content {}
        }
      }

      statement {
        and_statement {
          dynamic "statement" {
            for_each = local.route_matches[payload_rule.value.route_key]

            content {
              byte_match_statement {
                search_string         = statement.value.search_string
                positional_constraint = statement.value.positional_constraint

                field_to_match {
                  dynamic "single_header" {
                    for_each = statement.key == "hostname" ? [1] : []
                    content {
                      name = "host"
                    }
                  }

                  dynamic "uri_path" {
                    for_each = statement.key == "path_prefix" ? [1] : []
                    content {}
                  }

                  dynamic "method" {
                    for_each = statement.key == "http_method" ? [1] : []
                    content {}
                  }
                }

                text_transformation {
                  priority = 0
                  type     = statement.value.transformation
                }
              }
            }
          }

          statement {
            or_statement {
              # Match the AWS Core Rule Set size thresholds in the Count rule.
              dynamic "statement" {
                for_each = payload_rule.value.block ? {} : { body = 8192, query_string = 2048 }
                iterator = size_check

                content {
                  size_constraint_statement {
                    comparison_operator = "GT"
                    size                = size_check.value

                    field_to_match {
                      dynamic "body" {
                        for_each = size_check.key == "body" ? [1] : []
                        content {
                          oversize_handling = "MATCH"
                        }
                      }

                      dynamic "query_string" {
                        for_each = size_check.key == "query_string" ? [1] : []
                        content {}
                      }
                    }

                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }

              dynamic "statement" {
                for_each = payload_rule.value.inspect_injection ? [1] : []

                content {
                  sqli_match_statement {
                    field_to_match {
                      json_body {
                        match_scope               = "ALL"
                        invalid_fallback_behavior = "EVALUATE_AS_STRING"
                        oversize_handling         = "MATCH"

                        match_pattern {
                          all {}
                        }
                      }
                    }

                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }

              dynamic "statement" {
                for_each = payload_rule.value.inspect_injection ? [1] : []

                content {
                  xss_match_statement {
                    field_to_match {
                      json_body {
                        match_scope               = "ALL"
                        invalid_fallback_behavior = "EVALUATE_AS_STRING"
                        oversize_handling         = "MATCH"

                        match_pattern {
                          all {}
                        }
                      }
                    }

                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = local.rule_names[payload_rule.key]
        sampled_requests_enabled   = false
      }
    }
  }

  dynamic "rule" {
    for_each = local.managed_groups
    iterator = managed_group

    content {
      name     = managed_group.value
      priority = length(local.rate_rules) + length(local.payload_rules) + managed_group.key

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = managed_group.value
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = toset(lookup(local.managed_block_overrides, managed_group.value, []))

            content {
              name = rule_action_override.value

              action_to_use {
                block {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = managed_group.value
        sampled_requests_enabled   = false
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "waf-${substr(var.name, 0, 124)}"
    sampled_requests_enabled   = false
  }

  lifecycle {
    precondition {
      condition     = length(local.rate_rules) <= 10
      error_message = "AWS WAF permits up to 10 rate rules per ACL, including the application-wide rule."
    }
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = 90

  tags = var.tags
}


resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn = aws_wafv2_web_acl.this.arn

  log_destination_configs = [
    aws_cloudwatch_log_group.waf.arn
  ]

  # Retain security events and relevant advertising bot activity.
  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      # General security events
      dynamic "condition" {
        for_each = toset([
          "BLOCK",
          "COUNT",
          "EXCLUDED_AS_COUNT",
          "CAPTCHA",
          "CHALLENGE"
        ])

        content {
          action_condition {
            action = condition.value
          }
        }
      }

      # Ad Sales bot activity
      dynamic "condition" {
        for_each = toset([
          "awswaf:managed:aws:bot-control:bot:category:advertising",
          "awswaf:managed:aws:bot-control:bot:category:scraping_framework",
          "awswaf:managed:aws:bot-control:bot:category:ai",
          "awswaf:managed:aws:bot-control:bot:category:webhooks",
          "awswaf:managed:aws:bot-control:bot:verified",
          "awswaf:managed:aws:bot-control:signal:automated_browser"
        ])

        content {
          label_name_condition {
            label_name = condition.value
          }
        }
      }
    }
  }

  # Redact sensitive query parameters.
  redacted_fields {
    query_string {}
  }

  # Redact sensitive HTTP headers.
  dynamic "redacted_fields" {
    for_each = local.sensitive_headers

    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  for_each = var.scope == "REGIONAL" ? var.resource_arns : {}

  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.this.arn

  depends_on = [
    aws_wafv2_web_acl_logging_configuration.this
  ]
}
