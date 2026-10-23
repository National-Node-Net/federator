#!/bin/sh
set -eu

# Kubernetes ConfigMap volumes are read-only, so render templates from their
# fixed mount path to application-owned fixed paths. ${VAR} placeholders (for
# example the ${IDP_*} identity provider settings) are substituted from the
# container environment. If a template is absent, direct mounts under /config
# retain the legacy behaviour.
if [ -r "/config-templates/${PROPERTY_FILE}" ]; then
    envsubst < "/config-templates/${PROPERTY_FILE}" > "/config/${PROPERTY_FILE}"
fi

# Deprecated: older setups mount a separate common-configuration.properties and
# reference it from ${PROPERTY_FILE} via common.configuration. It is still
# rendered so those setups keep working; move its idp.* properties into
# ${PROPERTY_FILE} instead.
if [ -r /config-templates/common-configuration.properties ]; then
    echo "WARNING: /config-templates/common-configuration.properties is deprecated; move its idp.* properties into ${PROPERTY_FILE}" >&2
    envsubst < /config-templates/common-configuration.properties > /config/common-configuration.properties
fi

exec java -cp "$JAVA_CLASSPATH" ${PROPERTIES:-} "$JAVA_MAIN_CLASS" ${ARGS:-} "$@"
