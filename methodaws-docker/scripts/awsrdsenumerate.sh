#!/bin/bash

# Run methodaws rds enumerate
methodaws rds enumerate --output signal --output-file /mnt/output/output.json "$@"
