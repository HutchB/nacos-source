/*
 * Copyright 1999-2023 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.persistence.datasource;

import com.alibaba.nacos.common.utils.CollectionUtils;
import com.alibaba.nacos.common.utils.Preconditions;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.sys.env.EnvUtil;
import com.zaxxer.hikari.HikariDataSource;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.jasypt.salt.RandomSaltGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static com.alibaba.nacos.common.utils.CollectionUtils.getOrDefault;

/**
 * Properties of external DataSource.
 *
 * @author Nacos
 */
public class ExternalDataSourceProperties {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalDataSourceProperties.class);
    
    private static final String JDBC_DRIVER_NAME = "com.mysql.cj.jdbc.Driver";
    
    private static final String TEST_QUERY = "SELECT 1";
    
    private static final String ENC_PREFIX = "ENC(";
    
    private static final String ENC_SUFFIX = ")";
    
    private static final String JASYPT_ENCRYPTOR_PASSWORD_KEY = "jasypt.encryptor.password";
    
    private static final String NACOS_ENCRYPTOR_PASSWORD_KEY = "nacos.encryptor.password";
    
    private static final String JASYPT_ENCRYPTOR_ALGORITHM_KEY = "jasypt.encryptor.algorithm";
    
    private static final String JASYPT_ENCRYPTOR_STRING_OUTPUT_TYPE_KEY = "jasypt.encryptor.string-output-type";
    
    private static final String DEFAULT_ALGORITHM = "PBEWITHHMACSHA512ANDAES_256";
    
    private static final String DEFAULT_STRING_OUTPUT_TYPE = "base64";
    
    private Integer num;
    
    private List<String> url = new ArrayList<>();
    
    private List<String> user = new ArrayList<>();
    
    private List<String> password = new ArrayList<>();
    
    public void setNum(Integer num) {
        this.num = num;
    }
    
    public void setUrl(List<String> url) {
        this.url = url;
    }
    
    public void setUser(List<String> user) {
        this.user = user;
    }
    
    public void setPassword(List<String> password) {
        this.password = password;
    }
    
    /**
     * Build serveral HikariDataSource.
     *
     * @param environment {@link Environment}
     * @param callback    Callback function when constructing data source
     * @return List of {@link HikariDataSource}
     */
    List<HikariDataSource> build(Environment environment, Callback<HikariDataSource> callback) {
        List<HikariDataSource> dataSources = new ArrayList<>();
        Binder.get(environment).bind("db", Bindable.ofInstance(this));

        // db.* 绑定可能走 Spring Boot configurationProperties 包装链路，导致 ENC(...) 未被 PropertySource wrapper 解密。
        // 因此外置数据源场景在绑定后对 user/password/url 做一次解密，确保连接参数是明文。
        decryptDbPropertiesIfNeeded(environment);

        Preconditions.checkArgument(Objects.nonNull(num), "db.num is null");
        Preconditions.checkArgument(CollectionUtils.isNotEmpty(user), "db.user or db.user.[index] is null");
        Preconditions.checkArgument(CollectionUtils.isNotEmpty(password), "db.password or db.password.[index] is null");
        for (int index = 0; index < num; index++) {
            int currentSize = index + 1;
            Preconditions.checkArgument(url.size() >= currentSize, "db.url.%s is null", index);
            DataSourcePoolProperties poolProperties = DataSourcePoolProperties.build(environment);
            if (StringUtils.isEmpty(poolProperties.getDataSource().getDriverClassName())) {
                poolProperties.setDriverClassName(JDBC_DRIVER_NAME);
            }
            poolProperties.setJdbcUrl(url.get(index).trim());
            poolProperties.setUsername(getOrDefault(user, index, user.get(0)).trim());
            poolProperties.setPassword(getOrDefault(password, index, password.get(0)).trim());
            HikariDataSource ds = poolProperties.getDataSource();
            if (StringUtils.isEmpty(ds.getConnectionTestQuery())) {
                ds.setConnectionTestQuery(TEST_QUERY);
            }
            
            dataSources.add(ds);
            callback.accept(ds);
        }
        Preconditions.checkArgument(CollectionUtils.isNotEmpty(dataSources), "no datasource available");
        return dataSources;
    }

    private void decryptDbPropertiesIfNeeded(Environment environment) {
        if (environment == null) {
            return;
        }
        String passwordKey = environment.getProperty(JASYPT_ENCRYPTOR_PASSWORD_KEY);
        if (StringUtils.isBlank(passwordKey)) {
            passwordKey = EnvUtil.getSystemEnv("JASYPT_ENCRYPTOR_PASSWORD");
        }
        if (StringUtils.isBlank(passwordKey)) {
            passwordKey = environment.getProperty(NACOS_ENCRYPTOR_PASSWORD_KEY);
        }
        if (StringUtils.isBlank(passwordKey)) {
            return;
        }
        String algorithm = environment.getProperty(JASYPT_ENCRYPTOR_ALGORITHM_KEY, DEFAULT_ALGORITHM);
        String stringOutputType = environment.getProperty(JASYPT_ENCRYPTOR_STRING_OUTPUT_TYPE_KEY,
                DEFAULT_STRING_OUTPUT_TYPE);
        StandardPBEStringEncryptor encryptor = buildEncryptor(passwordKey, algorithm, stringOutputType);

        int urlEncCount = countEncrypted(url);
        int userEncCount = countEncrypted(user);
        int pwdEncCount = countEncrypted(password);
        if (urlEncCount + userEncCount + pwdEncCount > 0) {
            LOGGER.info("Detect encrypted db properties, will decrypt now. urlCount={} userCount={} passwordCount={}",
                    urlEncCount, userEncCount, pwdEncCount);
        }

        url = decryptListIfNeeded(url, encryptor, "db.url");
        user = decryptListIfNeeded(user, encryptor, "db.user");
        password = decryptListIfNeeded(password, encryptor, "db.password");

        if (urlEncCount + userEncCount + pwdEncCount > 0) {
            LOGGER.info("Decrypt db properties finished.");
        }
    }

    private List<String> decryptListIfNeeded(List<String> values, StandardPBEStringEncryptor encryptor,
            String propertyKeyPrefix) {
        if (CollectionUtils.isEmpty(values)) {
            return values;
        }
        List<String> result = new ArrayList<>(values.size());
        for (String v : values) {
            result.add(decryptValueIfNeeded(v, encryptor, propertyKeyPrefix));
        }
        return result;
    }

    private String decryptValueIfNeeded(String value, StandardPBEStringEncryptor encryptor, String propertyKeyPrefix) {
        if (!isEncryptedValue(value) || encryptor == null) {
            return value;
        }
        String cipherText = value.substring(ENC_PREFIX.length(), value.length() - ENC_SUFFIX.length());
        try {
            return encryptor.decrypt(cipherText);
        } catch (Exception e) {
            LOGGER.warn("Failed to decrypt db property, keyPrefix={}", propertyKeyPrefix, e);
            return value;
        }
    }

    private int countEncrypted(List<String> values) {
        if (CollectionUtils.isEmpty(values)) {
            return 0;
        }
        int count = 0;
        for (String v : values) {
            if (isEncryptedValue(v)) {
                count++;
            }
        }
        return count;
    }

    private boolean isEncryptedValue(String value) {
        return StringUtils.isNotBlank(value) && value.startsWith(ENC_PREFIX) && value.endsWith(ENC_SUFFIX);
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
    
    interface Callback<D> {
        
        /**
         * Perform custom logic.
         *
         * @param datasource dataSource.
         */
        void accept(D datasource);
    }
}
