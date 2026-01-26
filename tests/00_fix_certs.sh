#!/bin/bash
set -e

# Copy certificates and fix permissions
cp /tmp/certs/server.key /etc/postgresql/server.key
cp /tmp/certs/server.crt /etc/postgresql/server.crt
cp /tmp/certs/root.crt /etc/postgresql/root.crt

chown postgres:postgres /etc/postgresql/server.key /etc/postgresql/server.crt /etc/postgresql/root.crt
chmod 600 /etc/postgresql/server.key
chmod 644 /etc/postgresql/server.crt /etc/postgresql/root.crt
