# Basic Usage

Before you get started, you will need to export AWS credentials that you want methodaws to utilize as environment variables. For more documentation on how to do this, please see the Amazon documentation [here](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).

## Binaries

Running as a binary means you don't need to do anything additional for methodaws to leverage the environment variables you have already exported. You can test that things are working properly by running:

```bash
methodaws sts arn --region us-east-1
```

## Docker

Running methodaws within a Docker container requires that you pass the AWS credential environment variables into the container. This can be done with the following command:

```bash
docker run \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
  methodsecurity/methodaws sts arn --region us-east-1 --output json
```
