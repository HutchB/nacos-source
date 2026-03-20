/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.sys.env;

import com.alibaba.nacos.common.utils.StringUtils;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.jasypt.salt.RandomSaltGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * DecryptingPropertySource.
 *
 * @author nacos
 */
public class DecryptingPropertySource extends PropertySource<Object> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptingPropertySource.class);

    public static final String PROPERTY_SOURCE_NAME = "nacosDecryptingPropertySource";

    public static final String JASYPT_ENCRYPTOR_ALGORITHM_KEY = "jasypt.encryptor.algorithm";

    public static final String JASYPT_ENCRYPTOR_STRING_OUTPUT_TYPE_KEY = "jasypt.encryptor.string-output-type";

    private static final String DEFAULT_ALGORITHM = "PBEWITHHMACSHA512ANDAES_256";

    private static final String DEFAULT_STRING_OUTPUT_TYPE = "base64";

    private static final String ENC_PREFIX = "ENC(";

    private static final String ENC_SUFFIX = ")";

    private static final Set<String> SKIP_PROPERTY_SOURCE_NAMES = new HashSet<>(Arrays.asList(PROPERTY_SOURCE_NAME));

    /**
     * wrapper property source class name.
     */
    private static final String BOOT_CONFIGURATION_PROPERTY_SOURCES_PROPERTY_SOURCE =
            "org.springframework.boot.context.properties.source.ConfigurationPropertySourcesPropertySource";

    private static final String BOOT_CONFIGURATION_PROPERTIES_PROPERTY_SOURCE_NAME = "configurationProperties";

    /**
     * property sources.
     */
    private final MutablePropertySources propertySources;

    /**
     * decrypt password.
     */
    private final String password;

    /**
     * jasypt encryptor.
     */
    private final StandardPBEStringEncryptor encryptor;

    public DecryptingPropertySource(MutablePropertySources propertySources, String password, String algorithm,
            String stringOutputType) {
        super(PROPERTY_SOURCE_NAME, new Object());
        this.propertySources = propertySources;
        this.password = password;
        this.encryptor = buildEncryptor(password, algorithm, stringOutputType);
    }

    @Override
    public Object getProperty(String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }
        Object raw = getRawProperty(name);
        if (!(raw instanceof String)) {
            return raw;
        }
        String value = (String) raw;
        if (!isEncryptedValue(value)) {
            return value;
        }
        if (StringUtils.isBlank(password)) {
            LOGGER.error("Find encrypted property value but decrypt password is empty, key={}", name);
            return value;
        }
        String cipherText = unwrapEncryptedValue(value);
        try {
            return encryptor.decrypt(cipherText);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt property, key={}", name, e);
            return value;
        }
    }

    private Object getRawProperty(String name) {
        for (PropertySource<?> ps : propertySources) {
            if (ps == null) {
                continue;
            }
            if (SKIP_PROPERTY_SOURCE_NAMES.contains(ps.getName())) {
                continue;
            }
            if (BOOT_CONFIGURATION_PROPERTIES_PROPERTY_SOURCE_NAME.equals(ps.getName())) {
                continue;
            }
            String psClassName = ps.getClass().getName();
            if (BOOT_CONFIGURATION_PROPERTY_SOURCES_PROPERTY_SOURCE.equals(psClassName)
                    || psClassName.contains("ConfigurationPropertySources")) {
                continue;
            }
            Object value = ps.getProperty(name);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private boolean isEncryptedValue(String value) {
        return StringUtils.isNotBlank(value) && value.startsWith(ENC_PREFIX) && value.endsWith(ENC_SUFFIX);
    }

    private String unwrapEncryptedValue(String value) {
        return value.substring(ENC_PREFIX.length(), value.length() - ENC_SUFFIX.length());
    }

    private StandardPBEStringEncryptor buildEncryptor(String password, String algorithm, String stringOutputType) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(StringUtils.isBlank(algorithm) ? DEFAULT_ALGORITHM : algorithm);
        encryptor.setPassword(password);
        encryptor.setSaltGenerator(new RandomSaltGenerator());
        encryptor.setIvGenerator(new RandomIvGenerator());
        encryptor.setStringOutputType(
                StringUtils.isBlank(stringOutputType) ? DEFAULT_STRING_OUTPUT_TYPE : stringOutputType);
        return encryptor;
    }

    /**
     * Add decrypting property source at the highest priority.
     *
     * @param environment environment
     * @param password decrypt password
     */
    public static void addFirstIfNeeded(ConfigurableEnvironment environment, String password) {
        if (environment == null) {
            return;
        }
        if (StringUtils.isBlank(password)) {
            LOGGER.warn("Skip DecryptingPropertySource because decrypt password is empty");
            return;
        }
        MutablePropertySources sources = environment.getPropertySources();
        if (sources.contains(PROPERTY_SOURCE_NAME)) {
            return;
        }
        String algorithm = environment.getProperty(JASYPT_ENCRYPTOR_ALGORITHM_KEY);
        String stringOutputType = environment.getProperty(JASYPT_ENCRYPTOR_STRING_OUTPUT_TYPE_KEY);
        sources.addFirst(new DecryptingPropertySource(sources, password, algorithm, stringOutputType));
    }
}
