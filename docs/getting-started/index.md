# Getting Started

If you are just getting started with methodaws, welcome! This guide will walk you through the process of going zero to one with the tool.

## Installation

methodaws is provided in several convenient form factors, including statically compiled binary images on a variety of architectures as well as a Docker image for both x86 and ARM machines.

If you do not see an architecture that you require, please open a [Discussion](../community/contribute/discussions.md) to propose adding it.

### Binaries

methodaws currently supports statically compiled binaries across the following operating systems and architectures:

| OS      | Architecture  |
| ------- | ------------- |
| Linux   | 386           |
| Linux   | arm (goarm 7) |
| Linux   | amd64         |
| Linux   | arm64         |
| MacOS   | amd64         |
| MacOS   | arm64         |
| Windows | amd64         |

The latest binaries can be downloaded directly from [Github](releases).

### Docker

Docker images for methodaws are hosted in both Github Container Registry as well as on Docker Hub and can be pulled via:

```bash
docker pull ghcr.io/method-security/methodaws
```

```bash
docker pull methodsecurity/methodaws
```

## Usage

Before you get started, you will need to export AWS credentials that you want methodaws to utilize as environment variables. For more documentation on how to do this, please see the Amazon documentation [here](aws_env_vars).

### Binaries

Running as a binary means you don't need to do anything additional for methodaws to leverage the environment variables you have already exported. You can test that things are working properly by running:

```bash
methodaws sts arn --region us-east-1
```

### Docker

Running methodaws within a Docker container requires that you pass the AWS credential environment variables into the container. This can be done with the following command:

```bash
docker run \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
  ghcr.io/method-security/methodaws:0.0.1 methodaws sts arn --region us-east-1 --output json
```

[releases]: https://github.com/Method-Security/methodaws/releases/latest
[aws_env_vars]: https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html
