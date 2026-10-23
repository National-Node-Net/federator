/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */
package uk.gov.dbt.ndtp.federator.common.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.function.UnaryOperator;

/**
 * Resolves Spring-style placeholders in property values.
 * <p>
 *   Supported syntax:
 * </p>
 * <ul>
 *   <li>{@code ${NAME}} - replaced with the value of {@code NAME}; left as-is if {@code NAME} cannot be resolved</li>
 *   <li>{@code ${NAME:default}} - replaced with {@code default} when {@code NAME} cannot be resolved
 *       ({@code ${NAME:}} defaults to an empty string)</li>
 *   <li>nested placeholders, e.g. {@code ${PRIMARY:${SECONDARY:fallback}}}, and several placeholders in one value</li>
 *   <li>{@code \${...}} - an escaped, literal {@code ${...}} (write {@code \\${...}} in a .properties file, since
 *       {@link Properties#load} consumes one backslash)</li>
 * </ul>
 * <p>
 *   {@code NAME} is looked up, in order, as a system property, an environment variable and another property in the
 *   same file. A variable that is set to an empty string counts as set, as in Spring.
 * </p>
 */
public final class PropertyPlaceholderResolver {

    private static final String PREFIX = "${";
    private static final char SUFFIX = '}';
    private static final char DEFAULT_SEPARATOR = ':';
    private static final char ESCAPE = '\\';
    private static final int MAX_DEPTH = 10;

    private final UnaryOperator<String> systemProperties;
    private final UnaryOperator<String> environment;

    public PropertyPlaceholderResolver(UnaryOperator<String> systemProperties, UnaryOperator<String> environment) {
        this.systemProperties = systemProperties;
        this.environment = environment;
    }

    /**
     * Creates a resolver backed by the JVM system properties and the process environment.
     */
    public static PropertyPlaceholderResolver fromSystem() {
        return new PropertyPlaceholderResolver(System::getProperty, System::getenv);
    }

    /**
     * Resolves placeholders in every value of the given properties, in place. References to other properties always
     * see the original (unresolved) values, so the result does not depend on iteration order.
     *
     * @return the keys whose values still contain unresolved placeholders
     */
    public List<String> resolveAll(Properties properties) {
        Properties original = new Properties();
        original.putAll(properties);
        List<String> unresolved = new ArrayList<>();
        for (String key : original.stringPropertyNames()) {
            Result result = resolve(original.getProperty(key), original, 0);
            properties.setProperty(key, result.value);
            if (result.unresolved) {
                unresolved.add(key);
            }
        }
        return unresolved;
    }

    /**
     * Resolves placeholders in a single value, using {@code properties} for references to other properties.
     */
    public String resolve(String value, Properties properties) {
        return resolve(value, properties, 0).value;
    }

    private Result resolve(String value, Properties properties, int depth) {
        if (value == null || value.indexOf(PREFIX) < 0) {
            return new Result(value, false);
        }
        StringBuilder out = new StringBuilder(value.length());
        boolean unresolved = false;
        int i = 0;
        while (i < value.length()) {
            int start = value.indexOf(PREFIX, i);
            if (start < 0) {
                out.append(value, i, value.length());
                break;
            }
            if (start > 0 && value.charAt(start - 1) == ESCAPE) {
                // Escaped: drop the backslash and keep the placeholder text literally
                out.append(value, i, start - 1);
                int end = findClosingBrace(value, start);
                int literalEnd = end < 0 ? value.length() : end + 1;
                out.append(value, start, literalEnd);
                i = literalEnd;
                continue;
            }
            out.append(value, i, start);
            int end = findClosingBrace(value, start);
            if (end < 0) {
                // Unterminated placeholder: keep the remainder as-is
                out.append(value, start, value.length());
                unresolved = true;
                break;
            }
            String placeholder = value.substring(start, end + 1);
            Result replacement = resolvePlaceholder(placeholder, properties, depth);
            out.append(replacement.value);
            unresolved |= replacement.unresolved;
            i = end + 1;
        }
        return new Result(out.toString(), unresolved);
    }

    private Result resolvePlaceholder(String placeholder, Properties properties, int depth) {
        if (depth >= MAX_DEPTH) {
            // Guards against circular references such as a=${b} and b=${a}
            return new Result(placeholder, true);
        }
        String content = placeholder.substring(PREFIX.length(), placeholder.length() - 1);
        int separator = findDefaultSeparator(content);
        String name = (separator < 0 ? content : content.substring(0, separator)).trim();
        String defaultValue = separator < 0 ? null : content.substring(separator + 1);

        String found = lookup(name, properties);
        if (found != null) {
            return resolve(found, properties, depth + 1);
        }
        if (defaultValue != null) {
            return resolve(defaultValue, properties, depth + 1);
        }
        return new Result(placeholder, true);
    }

    private String lookup(String name, Properties properties) {
        if (name.isEmpty()) {
            return null;
        }
        String value = systemProperties.apply(name);
        if (value == null) {
            value = environment.apply(name);
        }
        if (value == null) {
            value = properties.getProperty(name);
        }
        return value;
    }

    /** Returns the index of the '}' matching the '${' at {@code start}, honouring nested placeholders. */
    private static int findClosingBrace(String value, int start) {
        int depth = 0;
        for (int i = start + PREFIX.length(); i < value.length(); i++) {
            if (value.startsWith(PREFIX, i)) {
                depth++;
                i++;
            } else if (value.charAt(i) == SUFFIX) {
                if (depth == 0) {
                    return i;
                }
                depth--;
            }
        }
        return -1;
    }

    /** Returns the index of the first ':' that is not inside a nested placeholder. */
    private static int findDefaultSeparator(String content) {
        int depth = 0;
        for (int i = 0; i < content.length(); i++) {
            if (content.startsWith(PREFIX, i)) {
                depth++;
                i++;
            } else if (content.charAt(i) == SUFFIX) {
                depth--;
            } else if (content.charAt(i) == DEFAULT_SEPARATOR && depth == 0) {
                return i;
            }
        }
        return -1;
    }

    private record Result(String value, boolean unresolved) {}
}
