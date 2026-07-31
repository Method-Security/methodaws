# methodaws Project Context

## Overview

methodaws is a comprehensive AWS security scanning and enumeration tool that provides security teams with data-rich insights into AWS cloud environments. It follows the CLI Development Conventions for attack stage organization and implements discover, enumerate, and pentest capabilities.

## Architecture

The tool follows the standard CLI Development Conventions with clear separation by attack stages:

### Attack Stages

1. **Discover Stage** (`internal/*/`)
   - AWS service discovery and basic reconnaissance
   - Credential validation and account enumeration
   - Service availability and region mapping

2. **Enumerate Stage** (`internal/*/`)
   - Deep inspection of AWS resources
   - Configuration extraction and analysis
   - Permission and policy enumeration

3. **Pentest Stage** (`internal/*/`)
   - Active testing of AWS security configurations
   - Privilege escalation testing
   - Security control bypass attempts

### Core Components

1. **AWS Service Modules** (`internal/*/`)
   - EC2, S3, IAM, RDS, EKS, Lambda, Route53
   - VPC, Security Groups, Load Balancers
   - API Gateway, CloudFront, WAF, Elastic Beanstalk

2. **Authentication** (`internal/sts/`)
   - AWS credential management
   - Role assumption and cross-account access
   - Session token handling

3. **Common Utilities** (`internal/common/`)
   - AWS region handling
   - Shared AWS client configurations
   - Error handling patterns

### CLI Structure (`cmd/`)
- `root.go` - Main CLI setup with Cobra
- `<service>.go` - Individual service command implementations
- Following naming convention: `<stage><Service>Cmd` pattern

### Generated Code (`generated/go/`)
- Fern-generated Go types and clients
- AWS service definitions and data structures
- Type-safe AWS API interfaces

## Project Structure

- **Language**: Go
- **Module**: github.com/Method-Security/methodaws
- **CLI Framework**: Cobra
- **Type Generation**: Fern
- **AWS SDK**: AWS SDK for Go v2
- **Testing**: Standard Go testing + AWS integration tests

## Key AWS Services Supported

- **Compute**: EC2, EKS, Lambda, Elastic Beanstalk
- **Storage**: S3
- **Networking**: VPC, Security Groups, Load Balancers, Route53
- **Security**: IAM, WAF, CloudFront
- **Database**: RDS
- **API**: API Gateway

## Development Patterns

### CLI Command Structure
Follow CLI Development Conventions:
- Use `<stage>Cmd` in camelCase for top-level commands
- Use `<stage><Component>Cmd` for subcommands
- Implement Run functions with action verbs (e.g., `RunEc2Discovery`)

### Flag Naming
- Use kebab-case for CLI flags: `--scan-type`
- Use camelCase when extracting flags: `scanType, err := cmd.Flags().GetString("scan-type")`
- Always check errors when extracting flags
- Use `.GetStringSlice` for slice inputs with plural flag names

### AWS Integration
- Use AWS SDK v2 for all AWS interactions
- Implement proper credential chain handling
- Support cross-account role assumption
- Handle AWS region selection properly
- Implement rate limiting and error retry logic

### Error Handling
```go
if err != nil {
    a.OutputSignal.AddError(err)
    return
}
```

### Fern Type Requirements
- **MANDATORY**: Every CLI command with output must have a corresponding Fern report structure
- **Three-Part Structure Pattern**: All commands must define:
  ```yaml
  # 1. Config type for input parameters
  <Stage><Component>Config:
    properties:
      # AWS-specific configuration parameters
      region: optional<AwsRegion>
      profile: optional<string>
      roleArn: optional<string>
  
  # 2. Result type for output data
  <Stage><Component>Result:
    properties:
      # AWS service-specific result data
      instances: optional<list<Ec2Instance>>
      buckets: optional<list<S3Bucket>>
  
  # 3. Report type wrapping config, result, and errors
  <Stage><Component>Report:
    properties:
      config: <Stage><Component>Config
      result: <Stage><Component>Result
      errors: optional<list<string>>
  ```
- **AWS Example Implementation**:
  ```yaml
  Ec2EnumerateConfig:
    properties:
      region: optional<AwsRegion>
      instanceIds: optional<list<string>>
  
  Ec2EnumerateResult:
    properties:
      instances: optional<list<Ec2Instance>>
  
  Ec2EnumerateReport:
    properties:
      config: Ec2EnumerateConfig
      result: Ec2EnumerateResult
      errors: optional<list<string>>
  ```
- **AWS-Specific Types**: Include AWS-specific enums and objects:
  ```yaml
  AwsRegion:
    enum: [US_EAST_1, US_WEST_2, EU_WEST_1, ...]
  InstanceType:
    enum: [T2_MICRO, T3_SMALL, M5_LARGE, ...]
  ```
- **Type Organization**: Follow the CLI Development Conventions type ordering:
  1. ENUMs (e.g., `AwsRegion`, `InstanceState`)
  2. Common Objects (e.g., `AwsCredential`, `Ec2Instance`)
  3. Config Types (e.g., `Ec2EnumerateConfig`)
  4. Result Types (e.g., `Ec2EnumerateResult`)
  5. Report Types (e.g., `Ec2EnumerateReport`)

### Output Structure
```go
a.OutputSignal.Content = report
```

## Important Notes

- **AWS Credentials**: Requires proper AWS credentials configured (environment variables, profile, or IAM role)
- **Permissions**: Different commands require different AWS permissions
- **Rate Limits**: Be mindful of AWS API rate limits
- **Cross-Account**: Support for cross-account role assumption
- **Regions**: Handle multi-region scanning appropriately

## Development Commands

```bash
# MANDATORY: Run after completing TODOs to ensure code can be merged
./godelw verify

# Build the binary
./godelw build
```

## Development Workflow

1. Follow CLI Development Conventions for new commands
2. Use Fern definitions for type safety
3. Implement proper AWS error handling
4. Test with multiple AWS accounts and regions
5. Follow existing patterns for consistency
6. **CRITICAL**: Always run `./godelw verify` after TODO completion before merging

## File Structure Conventions

- `/cmd/` - CLI command implementations
- `/internal/<service>/` - AWS service implementations
- `/fern/definition/` - Fern API definitions
- `/generated/go/` - Generated Go code
- `/docs/` - Documentation

## Development Practices

- Follow CLI Development Conventions exactly
- Use proper AWS SDK patterns
- Implement comprehensive error handling
- Support multiple AWS regions
- Handle AWS rate limiting gracefully
- Always end files with a single newline