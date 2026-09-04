#!/bin/sh
set -eu

until mc alias set root http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1; do
  sleep 1
done

mc mb --ignore-existing root/platform-objects >/dev/null
mc admin user add root "$MINIO_APP_USER" "$MINIO_APP_PASSWORD" >/dev/null
mc admin policy create root platform-app-bounded /config/platform-app-policy.json >/dev/null
mc admin policy attach root platform-app-bounded --user "$MINIO_APP_USER" >/dev/null

echo "MinIO application identity and bounded object policy are ready."
