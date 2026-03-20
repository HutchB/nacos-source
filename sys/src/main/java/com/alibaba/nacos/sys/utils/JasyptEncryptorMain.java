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

package com.alibaba.nacos.sys.utils;

import com.alibaba.nacos.common.utils.StringUtils;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.jasypt.salt.RandomSaltGenerator;

/**
 * JasyptEncryptorMain.
 * mvn -DskipTests -Dcheckstyle.skip=true -Dpmd.skip=true -Drat.skip=true -Drat.skip=true -Prelease-nacos clean install
 * startup.cmd -m standalone
 */
public class JasyptEncryptorMain {

    /**
     * encrypt password.
     */
    private static final String PASSWORD = "nacos@jasypt#2026!ChangeIt";

    private static final String DEFAULT_ALGORITHM = "PBEWITHHMACSHA512ANDAES_256";

    private static final String DEFAULT_STRING_OUTPUT_TYPE = "base64";

    private static final String ENC_PREFIX = "ENC(";

    private static final String ENC_SUFFIX = ")";

    /**
     * plaintext list.
     */
    private static final String[] PLAINTEXTS = new String[] {
            "root",
            "Gfg5xw_gcD",
    };

    public static void main(String[] args) {
        String password = PASSWORD;
        if (StringUtils.isBlank(password)) {
            throw new IllegalArgumentException("Missing PASSWORD in JasyptEncryptorMain");
        }

        // 可选：-Djasypt.encryptor.algorithm / -Djasypt.encryptor.string-output-type
        String algorithm = System.getProperty("jasypt.encryptor.algorithm", DEFAULT_ALGORITHM);
        String stringOutputType = System.getProperty("jasypt.encryptor.string-output-type", DEFAULT_STRING_OUTPUT_TYPE);

        String[] plaintextList = (args == null || args.length == 0) ? PLAINTEXTS : args;

        StandardPBEStringEncryptor encryptor = buildEncryptor(password, algorithm, stringOutputType);

        for (String plain : plaintextList) {
            String cipher = encryptor.encrypt(plain);
            System.out.println("原文: " + plain + "：" + "密文: " + ENC_PREFIX + cipher + ENC_SUFFIX);
        }
    }

    private static StandardPBEStringEncryptor buildEncryptor(String password, String algorithm, String stringOutputType) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(algorithm);
        encryptor.setPassword(password);
        encryptor.setSaltGenerator(new RandomSaltGenerator());
        encryptor.setIvGenerator(new RandomIvGenerator());
        encryptor.setStringOutputType(stringOutputType);
        return encryptor;
    }
}
