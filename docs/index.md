# methodaws Documentation

Hello and welcome to the methodaws documentation. While we always want to provide the most comprehensive documentation possible, we thought you may find the below sections a helpful place to get started.

- The [Getting Started](./getting-started/basic-usage.md) section provides onboarding material
- The [Development](./development/setup.md) header is the best place to get started on developing on top of and with methodaws
- See the [Docs](./docs/index.md) section for a comprehensive rundown of methodaws capabilities

# About methodaws

methodaws provides security operators with a number of data-rich AWS enumeration capabilities to help them gain visibility into their AWS environments. Designed with data-modeling and data-integration needs in mind, methodaws can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The number of security-relevant AWS resources that methodaws can enumerate are constantly growing. For the most up to date listing, please see the documentation [here](./docs/index.md)

To learn more about methodaws, please see the [Documentation site](https://method-security.github.io/methodaws/) for the most detailed information.

## Quick Start

### Get methodaws

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/methodaws`
- `docker run ghcr.io/method-security/methodaws`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/methodaws/releases/latest) page
- [Installation documentation](./getting-started/installation.md)

### Authentication

methodaws is built using the AWS Go SDK and leverages the same AWS Credentials that are used by the AWS CLI. Specifically, it looks for the proper environment variables to be exported with credential information. For more information, please see the AWS documentation on how to [export AWS credentials as environment variables](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).

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

Interested in contributing to methodaws? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie methodaws into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

methodaws is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).
