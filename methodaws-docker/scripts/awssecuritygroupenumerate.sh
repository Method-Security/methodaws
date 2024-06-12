#!/bin/bash

# Run methodaws securitygroup enumerate
methodaws securitygroup enumerate --output signal --output-file /mnt/output/output.json "$@"
