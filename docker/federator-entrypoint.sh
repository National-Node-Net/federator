#!/bin/sh
set -eu

# Kubernetes ConfigMap volumes are read-only, so properties files mounted under
# /config-templates/ are copied to the application-owned /config/ directory.
# ${VAR} / ${VAR:default} placeholders in the files are resolved by the
# application at startup from environment variables and system properties.
# If a template is absent, direct mounts under /config retain the legacy behaviour.
if [ -r "/config-templates/${PROPERTY_FILE}" ]; then
    cp "/config-templates/${PROPERTY_FILE}" "/config/${PROPERTY_FILE}"
fi

# Deprecated: older setups mount a separate common-configuration.properties and
# reference it from ${PROPERTY_FILE} via common.configuration. It is still
# copied so those setups keep working; move its idp.* properties into
# ${PROPERTY_FILE} instead.
if [ -r /config-templates/common-configuration.properties ]; then
    echo "WARNING: /config-templates/common-configuration.properties is deprecated; move its idp.* properties into ${PROPERTY_FILE}" >&2
    cp /config-templates/common-configuration.properties /config/common-configuration.properties
fi

exec java -cp "$JAVA_CLASSPATH" ${PROPERTIES:-} "$JAVA_MAIN_CLASS" ${ARGS:-} "$@"
