#!/bin/bash

# Run methodaws ec2
methodaws ec2 enumerate --output signal --output-file /mnt/output/output.json "$@"
