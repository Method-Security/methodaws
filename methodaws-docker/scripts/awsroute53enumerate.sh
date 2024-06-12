#!/bin/bash

# Run methodaws route 53
methodaws route53 enumerate --output signal --output-file /mnt/output/output.json "$@"
