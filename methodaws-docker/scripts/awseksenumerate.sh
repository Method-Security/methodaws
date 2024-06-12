#!/bin/bash

# Run methodaws eks enumerate
methodaws eks enumerate --output signal --output-file /mnt/output/output.json "$@"
