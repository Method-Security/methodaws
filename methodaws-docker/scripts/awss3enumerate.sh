#!/bin/bash

# Run methodaws s3 enumerate
methodaws s3 enumerate --output signal --output-file /mnt/output/output.json "$@"
