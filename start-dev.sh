#!/usr/bin/env bash

set -eu -o pipefail

docker-compose down -t0
docker-clean
aws-vault exec "biotz/hydrogen" --no-session --duration 12h -- bash -c \
    "docker/docker-env-vars.sh; docker-compose up --build --detach --force-recreate --renew-anon-volumes"
docker-compose logs -ft
