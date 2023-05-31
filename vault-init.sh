#!/bin/sh

set -e

export VAULT_ADDR=http://vault:8200

sleep 5

vault login root
vault secrets enable transit
