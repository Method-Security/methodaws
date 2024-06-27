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
methodaws <resource> enumerate --region <AWS Region>
```

#### Examples

```bash
methodaws s3 enumerate --region us-east-1
```

```bash
methodaws ec2 enumerate --region us-east-1
```

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
