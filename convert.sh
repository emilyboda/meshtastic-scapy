#!/bin/bash

# Initialize an array to hold all .proto files
files=()

# Add all .proto files from meshtastic/protobufs/meshtastic
files+=($(find meshtastic -type f -name "*.proto"))

# Add all .proto files from meshtastic/protobufs/google/protobuf
files+=($(find google/protobuf -type f -name "*.proto"))

# Add the specific file at /meshtastic/protobufs/nanopb.proto
if [ -f "nanopb.proto" ]; then
    files+=("nanopb.proto")
fi


# Process each file
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        protoc --python_out=. "$file"
    fi
done