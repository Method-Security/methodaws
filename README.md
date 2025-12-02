<div align="center">
<h1>methodaws</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

methodaws provides security operators with a number of data-rich AWS enumeration capabilities to help them gain visibility into their AWS environments. Designed with data-modeling and data-integration needs in mind, methodaws can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The number of security-relevant AWS resources that methodaws can enumerate are constantly growing. For the most up to date listing, please see the documentation [here](docs-capabilities)

To learn more about methodaws, please see the [Documentation site](https://method-security.github.io/methodaws/) for the most detailed information.

## Quick Start

### Get methodaws

For the full list of available installation options, please see the [Installation](./docs/getting-started/index.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/methodaws`
- `docker run ghcr.io/method-security/methodaws:0.0.1`
- Download the latest binary from the [Github Releases](releases) page
- [Installation documentation](./docs/getting-started/index.md)

### Authentication

methodaws is built using the AWS Go SDK and leverages the same AWS Credentials that are used by the AWS CLI. Specifically, it looks for the proper environment variables to be exported with credential information. For more information, please see the AWS documentation on how to [export AWS credentials as environment variables](aws_env_vars).

### General Usage

```bash
methodaws <resource> enumerate --regions <AWS Region>
```

#### Examples

```bash
# Enumerate S3 buckets in a specific region
methodaws s3 enumerate --regions us-east-1

# Enumerate EC2 instances in a specific region
methodaws ec2 enumerate --regions us-east-1

# Enumerate API Gateway resources in multiple regions
methodaws api-gateway enumerate --regions us-east-1 --regions us-west-2

# Enumerate Lambda functions in all regions (default)
methodaws lambda enumerate

# Get current AWS caller identity
methodaws sts arn --regions us-east-1

# Generate EKS credentials for a cluster
methodaws eks creds --regions us-east-1 --name my-cluster

# List objects in a specific S3 bucket
methodaws s3 list --regions us-east-1 --name my-bucket
```

### Available Resources and Commands

methodaws supports enumeration and management of the following AWS resources:

| Resource | Commands | Description |
|----------|----------|-------------|
| **api-gateway** (alias: `agw`) | `enumerate` | API Gateway REST and HTTP APIs |
| **cloudfront** | `enumerate` | CloudFront distributions |
| **ec2** | `enumerate` | EC2 instances |
| **eks** | `enumerate`, `creds` | EKS clusters and Kubernetes credentials |
| **iam** | `enumerate` | IAM users, roles, and policies |
| **lambda** | `enumerate` | Lambda functions |
| **load-balancer** | `enumerate` | Application and Network Load Balancers |
| **rds** | `enumerate` | RDS database instances |
| **route53** | `enumerate` | Route53 DNS records |
| **s3** | `enumerate`, `list`, `external` | S3 buckets and objects |
| **security-group** | `enumerate` | EC2 security groups |
| **sts** | `arn` | AWS Security Token Service |
| **vpc** | `enumerate` | Virtual Private Clouds |
| **waf** | `enumerate` | Web Application Firewalls |

## Contributing

Interested in contributing to methodaws? Please see our [Contribution](#) page.

## Want More?

If you're looking for an easy way to tie methodaws into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, see [https://method.security]

## Community

methodaws is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](github-org).

Have an idea for a Tool to contribute? Open a Discussion [here](discussion).

[verify]: https://github.com/Method-Security/methodaws/actions/workflows/verify.yml
[verify-img]: https://github.com/Method-Security/methodaws/actions/workflows/verify.yml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/Method-Security/methodaws
[go-report-img]: https://goreportcard.com/badge/github.com/Method-Security/methodaws
[release]: https://github.com/Method-Security/methodaws/releases
[releases]: https://github.com/Method-Security/methodaws/releases/latest
[release-img]: https://img.shields.io/github/release/Method-Security/methodaws.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/Method-Security/methodaws/total?logo=github
[docker-pulls-img]: https://img.shields.io/docker/pulls/methodsecurity/methodaws?logo=docker&label=docker%20pulls%20%2F%20methodaws
[docker-pull]: https://hub.docker.com/r/methodsecurity/methodaws
[license]: https://github.com/Method-Security/methodaws/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[homepage]: https://method.security
[docs-home]: https://method-security.github.io/methodaws
[docs-capabilities]: https://method-security.github.io/methodaws/docs/index.html
[discussion]: https://github.com/Method-Security/methodaws/discussions
[github-org]: https://github.com/Method-Security
[aws_env_vars]: https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html
