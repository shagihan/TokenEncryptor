/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.token.encryptor.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.token.encryptor.ClientSecretDTO;
import org.wso2.carbon.token.encryptor.Database;
import org.wso2.carbon.token.encryptor.TokenDTO;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;

import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.List;
import java.util.ListIterator;

/**
 * @scr.component name="org.wso2.carbon.token.encryptor" immediate="true"
 */

public class ActivatorComponent {
    private static final Log log = LogFactory.getLog(ActivatorComponent.class);
    Database database;
    private static boolean[] validKeyChars = new boolean[128];

    static {
        char[] validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_".toCharArray();

        for (char validChar : validChars) {
            validKeyChars[validChar] = true;
        }
    }

    /**
     * Method to activate bundle.
     *
     * @param context OSGi component context.
     */
    protected void activate(ComponentContext context) {
        log.info("Token Encryptor activates");

        database = new Database();

        try {
            List<TokenDTO> tokens = database.getTokens();

            for (TokenDTO token : tokens) {
                log.info("Token entry -  Access Token :" + token.getAccessToken() +
                        ", Refresh Token :" + token.getRefreshToken() +
                        ", Primary Key :" + token.getTokenID());
            }


            List<ClientSecretDTO> clientSecrets = database.getClientSecrets();

            for (ClientSecretDTO clientSecret : clientSecrets) {
                log.info("Client Secret entry - Client Secret :" + clientSecret.getClientSecret() +
                        ", Primary Key :" + clientSecret.getConsumerAppID());
            }

        } catch (SQLException e) {
            log.error("Error detected when accessing database", e);
        }

        //*******************
        try {
            List<ClientSecretDTO> clientSecretDTOList = database.getClientSecrets();
            List<TokenDTO> tokenDTOList = database.getTokens();
            List resultsList = iterator(clientSecretDTOList, tokenDTOList);
            log.info("updating client secrets in db");
            database.updateClientSecrets(resultsList);
        } catch (SQLException e) {
            log.error("Error while accessing database", e);
        }
    }

    public static List iterator(List<ClientSecretDTO> clientSecretDTOList, List<TokenDTO> tokenDTOList) {
        for (final ListIterator<ClientSecretDTO> i = clientSecretDTOList.listIterator(); i.hasNext(); ) {
            final ClientSecretDTO element = i.next();
            if (!isEncrypted(element)) {
                log.info(element.getClientSecret() + "is not encrypted");
                i.set(encryptUtil(element));
            }
        }
        return clientSecretDTOList;
    }

    public static boolean isEncrypted(ClientSecretDTO clientSecretDTO) {
        try {
            byte[] decryptedKey = CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(clientSecretDTO.getClientSecret());
            String decryptedKeyValue = new String(decryptedKey, Charset.defaultCharset());

            return isKeyValid(decryptedKeyValue);
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static ClientSecretDTO encryptUtil(ClientSecretDTO clientSecretDTO) {
        log.info("Encrypting: " + clientSecretDTO.getClientSecret());
        byte[] clientSecret = clientSecretDTO.getClientSecret().getBytes();//if not working use another Byte conversion mmethod
        try {
            String encryptedKey = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(clientSecret);
            clientSecretDTO.setClientSecret(encryptedKey);//set encrypted value
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        return clientSecretDTO;
    }

    public static boolean isKeyValid(String decryptedKeyValue) {
        for (int i = 0; i < decryptedKeyValue.length(); ++i) {
            char keyChar = decryptedKeyValue.charAt(i);

            if (validKeyChars.length <= keyChar) {
                return false;
            }

            if (!validKeyChars[keyChar]) {
                return false;
            }
        }

        return true;
    }


}
