#!/bin/sh
set -eu

# Kubernetes ConfigMap volumes are read-only, so render templates from their
# fixed mount path to application-owned fixed paths. If a template is absent,
# direct mounts under /config retain the legacy behaviour.
if [ -r /config-templates/common-configuration.properties ]; then
    envsubst < /config-templates/common-configuration.properties > /config/common-configuration.properties
fi

if [ -r "/config-templates/${PROPERTY_FILE}" ]; then
    envsubst < "/config-templates/${PROPERTY_FILE}" > "/config/${PROPERTY_FILE}"
fi

exec java -cp "$JAVA_CLASSPATH" ${PROPERTIES:-} "$JAVA_MAIN_CLASS" ${ARGS:-} "$@"



