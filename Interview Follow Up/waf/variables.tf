
variable "name" {
  description = "Unique name of the WAF Web ACL."
  type        = string
  nullable    = false
}

variable "scope" {
  description = "Deployment scope of the WAF Web ACL."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.scope)
    error_message = "Scope must be REGIONAL or CLOUDFRONT."
  }
}

variable "resource_arns" {
  description = "Map of resource names to ALB ARNs associated with the Web ACL. Pass an empty map when no ALB association is needed."
  type        = map(string)
  nullable    = false
}

variable "tags" {
  description = "Tags applied to supported AWS resources. Pass an empty map when no module-specific tags are needed."
  type        = map(string)
  nullable    = false
}

variable "rate_limit" {
  description = "Application-wide request limit and fallback for scoped rate rules. Pass null to disable the application-wide rule and scoped rules that have no explicit limit."
  type        = number
  nullable    = true

  validation {
    condition     = var.rate_limit == null ? true : var.rate_limit >= 10 && var.rate_limit <= 2000000000 && floor(var.rate_limit) == var.rate_limit
    error_message = "Rate limit must be a whole number from 10 to 2,000,000,000."
  }
}

variable "rate_limit_forwarded_ip_header" {
  description = "Trusted proxy header carrying the client IP for the application-wide rate rule. Defaults to the request source IP."
  type        = string
  default     = null

  validation {
    condition     = var.rate_limit_forwarded_ip_header == null ? true : can(regex("^[A-Za-z0-9-]{1,255}$", var.rate_limit_forwarded_ip_header))
    error_message = "The application-wide forwarded IP header must have 1 to 255 ASCII letters, digits, or hyphens."
  }
}

variable "ad_sales" {
  description = "Ad Sales application routes, rate limits, and payload protection."

  type = object({

    # ------------------------------------------------
    # Advertising API Rate Limiting
    # ------------------------------------------------

    # OpenRTB
    # DSP and SSP integrations
    # VAST
    # Impression tracking
    # Conversion tracking
    # Measurement and verification
    # Partner APIs

    api_rate_limits = optional(map(object({

      # Endpoint configuration
      hostname    = string
      path_prefix = string
      http_method = optional(string)

      # Rate-limit evaluation window
      evaluation_window_sec = optional(number, 300)
      limit                 = optional(number)
      forwarded_ip_header   = optional(string)
      identity_header       = optional(string)

    })), {})

    browser_rate_limits = optional(map(object({
      hostname              = string
      path_prefix           = string
      http_method           = optional(string)
      evaluation_window_sec = optional(number, 300)
      limit                 = optional(number)
      forwarded_ip_header   = optional(string)
      identity_header       = optional(string)
    })), {})

    # ------------------------------------------------
    # Advertising Payload Protection
    # ------------------------------------------------

    payload_protection = optional(map(object({
      hostname        = string
      path_prefix     = string
      http_method     = optional(string)
      block_injection = optional(bool, false)
    })), {})
  })

  default = null

  validation {
    condition = var.ad_sales == null ? true : alltrue([
      for route in concat(values(var.ad_sales.api_rate_limits), values(var.ad_sales.browser_rate_limits)) :
      contains([60, 120, 300, 600], route.evaluation_window_sec)
    ])
    error_message = "Scoped rate-limit evaluation windows must be 60, 120, 300, or 600 seconds."
  }

  validation {
    condition = var.ad_sales == null ? true : alltrue([
      for route in concat(values(var.ad_sales.api_rate_limits), values(var.ad_sales.browser_rate_limits)) :
      route.limit == null ? true : route.limit >= 10 && route.limit <= 2000000000 && floor(route.limit) == route.limit
    ])
    error_message = "Scoped rate limits must be whole numbers from 10 to 2,000,000,000."
  }

  validation {
    condition = var.ad_sales == null ? true : alltrue([
      for route in concat(values(var.ad_sales.api_rate_limits), values(var.ad_sales.browser_rate_limits)) :
      (route.forwarded_ip_header == null || route.identity_header == null) &&
      (route.forwarded_ip_header == null ? true : can(regex("^[A-Za-z0-9-]{1,255}$", route.forwarded_ip_header))) &&
      (route.identity_header == null ? true : can(regex("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$", route.identity_header)))
    ])
    error_message = "A scoped rate rule can set one trusted header. Forwarded IP headers allow 1 to 255 ASCII letters, digits, or hyphens. Identity headers must be valid HTTP header names of up to 64 characters."
  }
}
