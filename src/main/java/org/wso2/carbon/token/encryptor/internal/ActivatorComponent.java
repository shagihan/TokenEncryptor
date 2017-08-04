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
import org.wso2.carbon.token.encryptor.Utils;

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
        List[] resultsList;

        database = new Database();

        try {
            //Retrieving tokens and client secrets
            List<ClientSecretDTO> clientSecretDTOList = database.getClientSecrets();
            List<TokenDTO> tokenDTOList = database.getTokens();

            //Processing client secrets and tokens
            resultsList = iterator(clientSecretDTOList, tokenDTOList);

            log.info("updating(encrypting) client secrets in db...");
            database.updateClientSecrets(resultsList[0]);

            log.info("updating(encrypting) tokens secrets in db...");
            database.updateTokens(resultsList[1]);
        } catch (SQLException e) {
            log.error("Error while accessing the database", e);
        }
    }

    public static List[] iterator(List<ClientSecretDTO> clientSecretDTOList, List<TokenDTO> tokenDTOList) {
        for (final ListIterator<ClientSecretDTO> i = clientSecretDTOList.listIterator(); i.hasNext(); ) {
            final ClientSecretDTO element = i.next();
            if (!Utils.isEncrypted(element.getClientSecret())) {
                log.info("Client secret: " + element.getClientSecret() + " is not encrypted");
                element.setClientSecret(Utils.encryptionUtil(element.getClientSecret()));
                i.set(element);
            }
        }
        for (final ListIterator<TokenDTO> i = tokenDTOList.listIterator(); i.hasNext(); ) {
            final TokenDTO element = i.next();
            //Checking both access and refresh tokens for if encrypted
            if (!Utils.isEncrypted(element.getAccessToken())) {
                log.info("Access token: " + element.getAccessToken() + " is not encrypted");
                element.setAccessToken(Utils.encryptionUtil(element.getAccessToken()));
                i.set(element);
            }
            if (!Utils.isEncrypted(element.getRefreshToken())) {
                log.info("Refresh token: " + element.getRefreshToken() + " is not encrypted");
                element.setRefreshToken(Utils.encryptionUtil(element.getRefreshToken()));
                i.set(element);
            }
        }
        List[] resultsList = {clientSecretDTOList, tokenDTOList};
        return resultsList;
    }
}
