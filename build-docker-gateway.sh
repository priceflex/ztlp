#!/bin/bash
docker build -t priceflex/ztlp-node:hermes-quic-routing -f proto/Dockerfile.devbinary proto/
docker push priceflex/ztlp-node:hermes-quic-routing
