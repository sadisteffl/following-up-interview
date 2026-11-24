# interview-followup

This repository contains two Terraform-based proof-of-concept projects created as an interview follow-up to demonstrate my approach to security engineering, infrastructure automation, and operational problem-solving.

## Projects

Click into either folder below to view the Terraform configurations, supporting scripts, and documentation:

- **[AWS ALB Access Logging Guardrail](https://github.com/sadisteffl/interview-follow-up/tree/main/Interview%20Follow%20Up/lb-logging)** — Event-driven and scheduled automation using Terraform, Lambda, EventBridge, Step Functions, and SQS to detect and remediate missing ALB access logging.
- **[Reusable WAF Module](https://github.com/sadisteffl/interview-follow-up/tree/main/Interview%20Follow%20Up/waf)** — A modular AWS WAFv2 configuration supporting scoped rate limiting, payload inspection, log filtering, and sensitive-field redaction.

> **Note on scope:** These configurations and scripts are working development prototypes rather than production-hardened implementations. Moving them toward production would involve tightening IAM least-privilege boundaries, adding failure handling and concurrency controls, validating log delivery and WAF tuning against real traffic, and coordinating with engineering and security teams.
