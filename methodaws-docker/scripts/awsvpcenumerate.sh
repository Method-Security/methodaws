#!/bin/bash

# Run methodaws vpc enumerate
methodaws vpc enumerate --output signal --output-file var/data/raw_output "$@"
