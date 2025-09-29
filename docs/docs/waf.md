# WAF

methodaws provides the capability to enumerate AWS WAF (Web Application Firewall) resources.

## Usage

```bash
methodaws waf enumerate --regions <regions>
```

## Examples

```bash
# Enumerate WAF resources in us-east-1
methodaws waf enumerate --regions us-east-1

# Enumerate WAF resources in multiple regions
methodaws waf enumerate --regions us-east-1 --regions us-west-2

# Enumerate WAF resources in all regions (default behavior)
methodaws waf enumerate

# Output to JSON format
methodaws waf enumerate --output json
```

## Resources Enumerated

The WAF enumerate command gathers information about:

- WAF Web ACLs
- WAF rules and rule groups
- WAF IP sets and regex pattern sets
- WAF rate-based rules
- Associated resources (CloudFront distributions, Application Load Balancers, API Gateway)
- WAF logging configurations
- WAF managed rule groups

## Output

The output includes detailed information about your WAF resources and their configurations in the specified output format (signal, json).

## Security Considerations

When enumerating WAF resources, methodaws will collect:
- Web ACL configurations and rules
- IP allow/block lists
- Rate limiting configurations
- Associated protected resources
- Logging and monitoring settings

This information is valuable for security assessments and ensuring proper web application protection is in place.