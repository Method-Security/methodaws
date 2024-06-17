# Route53

The `methodaws route53` family of commands provide information about an account's Route53 DNS entries and hosted zones.

## Enumerate

The enumerate command will gather information about all of the Route53 hosted zones and DNS entries, that the provided credentials have access to.

### Usage

```bash
methodaws route53 enumerate --region us-east-1 --output json

```

### Help Text

```bash
$ methodaws route53 enumerate --help
Enumerate Route53 records

Usage:
  methodaws route53 enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```
