# S3

The `methodaws s3` family of commands provide information about an account's S3 buckets and their contents.

## Enumerate

The enumerate command will gather information about all of the S3 buckets that the provided credentials have access to.

### Usage

```bash
methodaws s3 enumerate --region us-east-1 --output json
```

### Help Text

```bash
$ methodaws s3 enumerate -h
Enumerate all S3 buckets in your AWS account.

Usage:
  methodaws s3 enumerate [flags]

Flags:
  -h, --help   help for enumerate

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```

## ls

### Usage

```bash
methodaws s3 ls --region us-east-1 --output json --name <bucket name>
```

### Help Text

```bash
$ methodaws s3 ls -h
List all objects in a single S3 bucket.

Usage:
  methodaws s3 ls [flags]

Flags:
  -h, --help          help for ls
      --name string   Name of the S3 bucket

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -r, --region string        AWS region
  -v, --verbose              Verbose output
```
