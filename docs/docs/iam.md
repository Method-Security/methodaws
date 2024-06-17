# IAM

The `methodaws iam` family of commands provide information about an account's IAM roles and policies.

## Enumerate

The enumerate command will gather information about all of the IAM roles, along with their attached and/or inline policies, that the provided credentials have access to.

### Usage

```bash
methodaws iam enumerate --region us-east-1 --output json

```

### Help Text

```bash
$ methodaws iam enumerate -h
Enumerate IAM resources

Usage:
  methodaws iam enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```
