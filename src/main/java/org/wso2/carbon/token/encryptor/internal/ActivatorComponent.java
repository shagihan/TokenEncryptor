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
import org.wso2.carbon.token.encryptor.TokenProcessor;
import java.sql.SQLException;
import java.util.*;

/**
 * @scr.component name="org.wso2.carbon.token.encryptor" immediate="true"
 */

public class ActivatorComponent {
    private static final Log log = LogFactory.getLog(ActivatorComponent.class);
    private boolean isDbConnected = false;
    /**
     * Method to activate bundle.
     *
     * @param context OSGi component context.
     */
    protected void activate(ComponentContext context) {
        if (System.getProperty("encrypt") == null) {
            return;
        }
        log.info("Token Encryptor activates");
        Database database = new Database();
        TokenProcessor processor = TokenProcessor.getSharedProcessor();
        try {
            List<TokenDTO> tokens = database.getTokens();
            List<ClientSecretDTO> clientSecrets = database.getClientSecrets();
            processor.processEncryptionOnToken(tokens,clientSecrets,database);
        } catch (SQLException e) {
            log.error("Error detected when accessing database", e);
        }
    }

}
