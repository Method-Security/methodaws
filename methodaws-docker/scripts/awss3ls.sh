#!/bin/bash

# Run methodaws s3 ls
methodaws s3 ls --output signal --output-file /mnt/output/output.json "$@"
