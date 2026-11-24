# Ad Sales WAF Terraform module

This module creates an AWS WAFv2 Web ACL, a 90-day CloudWatch log group,
and WAF request logging. It can associate a regional ACL with existing
Application Load Balancers. For CloudFront, use the ACL ARN in the
distribution that your application manages.

## Use the module in an application build

Terraform 1.5 or later and the AWS provider from 5.100 up to, but excluding, 6.0 are required.
Configure the AWS provider in the calling root module.

Use the module repository URL and a published Git tag or commit in
the source address. This example assumes the calling root already
defines `aws_lb.app`. [Terraform Git module sources](https://developer.hashicorp.com/terraform/language/modules/configuration#install-modules-from-a-git-repository)

```hcl
module "ad_sales_waf" {
  source = "git::ssh://git@git.example.com/platform/terraform-aws-ad-sales-waf.git?ref=v1.0.0"

  name  = "ad-sales-prod"
  scope = "REGIONAL"
  resource_arns = {
    app = aws_lb.app.arn
  }
  tags = {
    Application = "ad-sales"
    Environment = "prod"
  }
  rate_limit = 20000

  ad_sales = {
    browser_rate_limits = {
      web = {
        hostname    = "ads.example.com"
        path_prefix = "/web/"
        limit       = 1000
      }
    }
    api_rate_limits = {
      auction = {
        hostname    = "ads.example.com"
        path_prefix = "/auction"
        http_method = "POST"
        limit       = 10000
      }
    }
    payload_protection = {
      auction = {
        hostname    = "ads.example.com"
        path_prefix = "/auction"
        http_method = "POST"
      }
    }
  }
}
```

In the calling directory, run `terraform init` to fetch the module and
`terraform plan` to review the proposed resources. For a local checkout
or vendored copy, use a relative source path from the calling root.

### Inputs

| Input | Required | Purpose |
| --- | --- | --- |
| `name` | Yes | Web ACL name. |
| `scope` | Yes | `REGIONAL` or `CLOUDFRONT`. |
| `resource_arns` | Yes | Map of regional ALB ARNs. Use `{}` when there is no ALB association. |
| `tags` | Yes | Map of AWS tags. Use `{}` when no module-specific tags are needed. |
| `rate_limit` | Yes | Application-wide request threshold and fallback for scoped rules. Pass `null` to disable the application-wide rule and any scoped rule without its own limit. |
| `rate_limit_forwarded_ip_header` | No | Trusted proxy header to use for the application-wide rule. Defaults to the source IP. |
| `ad_sales` | No | Optional `browser_rate_limits`, `api_rate_limits`, and `payload_protection` maps keyed by route name. |

Each route takes `hostname`, `path_prefix`, and an optional `http_method`.

### Rate limits

Browser and API routes use the same options. Their host, path prefix, and
optional method determine which traffic each rule covers.

- `limit` sets the number of requests per aggregation key. It defaults to
  `rate_limit`. Limits are whole numbers from 10 to 2,000,000,000.
- `evaluation_window_sec` accepts 60, 120, 300, or 600 seconds and defaults
  to 300 seconds. The application-wide rule uses 300 seconds.
- Source IP is the default for each scoped rule. Set `forwarded_ip_header`
  to aggregate by the first address in a trusted proxy header. Use this
  only when the proxy overwrites client-supplied values and traffic cannot
  bypass the proxy. AWS WAF groups malformed values with the `MATCH`
  fallback. [AWS WAF rate aggregation options](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-options.html)
- Set `identity_header` to aggregate by a non-secret application or partner
  identifier. An upstream proxy or gateway must authenticate the caller
  and overwrite this header before AWS WAF sees the request. Configure at
  most one of `identity_header` and `forwarded_ip_header` per scoped rule.
  A request missing the configured header skips that rate rule.
  [AWS WAF aggregation keys](https://docs.aws.amazon.com/waf/latest/APIReference/API_RateBasedStatement.html)

When configured, the application-wide rule also applies to browser and API
traffic. Set `rate_limit = null` and give each route its own `limit` to
enforce only independent thresholds. The ACL supports ten rate rules total,
including the application-wide rule when enabled.

### CloudFront

In the calling root, configure an AWS provider alias for `us-east-1`.
In the module block, set `scope = "CLOUDFRONT"`,
`resource_arns = {}`, and `providers = { aws = aws.us_east_1 }` if the
alias is named `us_east_1`. In the CloudFront distribution, set
`web_acl_id = module.ad_sales_waf.web_acl_arn`.
[Terraform CloudFront distribution documentation](https://registry.terraform.io/providers/hashicorp/aws/5.100.0/docs/resources/cloudfront_distribution#web_acl_id)

### Outputs

| Output | Value |
| --- | --- |
| `web_acl_arn` | ACL ARN for CloudFront and other integrations. |
| `web_acl_id` | WAF resource ID. |
| `log_group_name` | CloudWatch log group name. |

## Security behavior

- The ACL defaults to Allow. Amazon IP Reputation, Known Bad Inputs,
  Core Rule Set, and SQL Injection run as managed rule groups. The Core
  Rule Set blocks bodies over 8,192 bytes and query strings over 2,048
  bytes across the ACL. The module explicitly blocks the documented
  Count rules in Amazon IP Reputation and Known Bad Inputs.
  [Amazon IP Reputation rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html)
  [Core Rule Set and Known Bad Inputs rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
- Application-wide, browser, and API rate rules block matching requests
  when their aggregation key exceeds the configured limit. Custom payload
  size checks emit Count events. By default, custom JSON body checks also use Count for SQL
  injection and cross-site scripting matches. If JSON parsing fails,
  inspection evaluates the body as text.
- After reviewing Count events for a route and checking for false positives
  with representative traffic, set `block_injection = true` on that
  `ad_sales.payload_protection` entry. The route's host, path prefix, and
  optional HTTP method scope the explicit Block rule for SQL injection and
  cross-site scripting. Both JSON checks use `MATCH` for bodies beyond the
  AWS WAF inspection limit, so an oversized body triggers the route's
  configured Count or Block action. The explicit Block rule runs after
  the custom payload Count rules and before the managed rule groups.
  [AWS WAF oversize handling](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html)
- CloudWatch retains selected security events for 90 days. Bot Control
  appears only as log filter conditions. WAF data protection masks
  configured sensitive headers, query strings, and body data in telemetry.
  CloudWatch metrics are enabled and request sampling is disabled.

## Test from a checkout

The regional example uses the module as a child module and plans an
ACL and logging resources without an ALB association. Run these
commands with AWS credentials and a test region configured.

```sh
terraform -chdir=examples/regional init
terraform -chdir=examples/regional validate
terraform -chdir=examples/regional plan
```

The original proposal is available in the [design notes](docs/design-notes.md).
