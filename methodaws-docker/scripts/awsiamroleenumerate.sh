#!/bin/bash

# Run methodaws ec2
methodaws iam enumerate --output signal --output-file /mnt/output/output.json "$@"
