# Capabilities

methodaws provides a number of capabilities to cyber security professionals working within AWS, spanning many of Amazon's most important resource types. Each of the below pages will provide you with a more in depth look at the methodaws capabilities related the specified resource.

- [Current Instance](./current.md)
- [EC2](./ec2.md)
- [EKS](./eks.md)
- [IAM](./iam.md)
- [RDS](./rds.md)
- [Route53](./route53.md)
- [S3](./s3.md)
- [Security Group](./securitygroup.md)
- [STS](./sts.md)
- [VPC](./vpc.md)

## Top Level Flags

methodaws has several top level flags that can be used on any subcommand. These include:

```bash
Flags:
  -h, --help                 help for methodaws
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```

## Version Command

Run `methodaws version` to get the exact version information for your binary

## Output Formats

For more information on the various output formats that are supported by methodaws, see the [Output Formats](https://method-security.github.io/docs/output.html) page in our organization wide documentation.
