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
import org.springframework.core.env.PropertySource;

/**
 * DecryptingPropertySourceWrapper.
 *
 * @author nacos
 */
public class DecryptingPropertySourceWrapper extends PropertySource<Object> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptingPropertySourceWrapper.class);

    public static final String JASYPT_ENCRYPTOR_ALGORITHM_KEY = "jasypt.encryptor.algorithm";

    public static final String JASYPT_ENCRYPTOR_STRING_OUTPUT_TYPE_KEY = "jasypt.encryptor.string-output-type";

    private static final String ENC_PREFIX = "ENC(";

    private static final String ENC_SUFFIX = ")";

    private final PropertySource<?> delegate;

    private final StandardPBEStringEncryptor encryptor;

    public DecryptingPropertySourceWrapper(PropertySource<?> delegate, String password, String algorithm,
            String stringOutputType) {
        super(delegate.getName(), delegate.getSource());
        this.delegate = delegate;
        this.encryptor = buildEncryptor(password, algorithm, stringOutputType);
    }

    @Override
    public Object getProperty(String name) {
        Object raw = delegate.getProperty(name);
        if (!(raw instanceof String)) {
            return raw;
        }
        String value = (String) raw;
        if (!isEncryptedValue(value)) {
            return value;
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Decrypt property value detected, key={} propertySource={}", name, delegate.getName());
        }
        String cipherText = unwrapEncryptedValue(value);
        try {
            String plain = encryptor.decrypt(cipherText);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Decrypt property value success, key={} propertySource={}", name, delegate.getName());
            }
            return plain;
        } catch (Exception e) {
            LOGGER.warn("Failed to decrypt property value, key={} propertySource={}", name, delegate.getName(), e);
            return value;
        }
    }

    private boolean isEncryptedValue(String value) {
        return StringUtils.isNotBlank(value) && value.startsWith(ENC_PREFIX) && value.endsWith(ENC_SUFFIX);
    }

    private String unwrapEncryptedValue(String value) {
        return value.substring(ENC_PREFIX.length(), value.length() - ENC_SUFFIX.length());
    }

    private StandardPBEStringEncryptor buildEncryptor(String password, String algorithm, String stringOutputType) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(StringUtils.isBlank(algorithm) ? "PBEWITHHMACSHA512ANDAES_256" : algorithm);
        encryptor.setPassword(password);
        encryptor.setSaltGenerator(new RandomSaltGenerator());
        encryptor.setIvGenerator(new RandomIvGenerator());
        encryptor.setStringOutputType(StringUtils.isBlank(stringOutputType) ? "base64" : stringOutputType);
        return encryptor;
    }

    public static boolean isWrapped(PropertySource<?> ps) {
        return ps instanceof DecryptingPropertySourceWrapper;
    }
}
