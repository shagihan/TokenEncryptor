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

package org.wso2.carbon.token.encryptor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class Database {
    private static final Log log = LogFactory.getLog(Database.class);


    public Database() {
        try {
            APIMgtDBUtil.initialize();
        } catch (APIManagerDatabaseException e) {
            log.error("Error while initializing AM DB", e);
        }
    }

    public List<TokenDTO> getTokens() throws SQLException {
        final String query = "SELECT TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN FROM IDN_OAUTH2_ACCESS_TOKEN";

        List<TokenDTO> tokens = new ArrayList<>();

        try (Connection connection = APIMgtDBUtil.getConnection();
             PreparedStatement statement = connection.prepareStatement(query)) {

            statement.execute();

            try (ResultSet rs =  statement.getResultSet()) {
                while (rs.next()) {
                    TokenDTO tokenDTO = new TokenDTO();
                    tokenDTO.setTokenID(rs.getString("TOKEN_ID"));
                    tokenDTO.setAccessToken(rs.getString("ACCESS_TOKEN"));
                    tokenDTO.setRefreshToken(rs.getString("REFRESH_TOKEN"));

                    tokens.add(tokenDTO);
                }
            }
        }
        log.info("FETCHING TOKENDTOS --------------");
        return tokens;
    }

    public List<ClientSecretDTO> getClientSecrets() throws SQLException {
        final String query = "SELECT ID, CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS";

        List<ClientSecretDTO> clientSecrets = new ArrayList<>();

        try (Connection connection = APIMgtDBUtil.getConnection();
             PreparedStatement statement = connection.prepareStatement(query)) {

            statement.execute();

            try (ResultSet rs =  statement.getResultSet()) {
                while (rs.next()) {
                    ClientSecretDTO clientSecretDTO = new ClientSecretDTO();
                    clientSecretDTO.setConsumerAppID(rs.getInt("ID"));
                    clientSecretDTO.setClientSecret(rs.getString("CONSUMER_SECRET"));

                    clientSecrets.add(clientSecretDTO);
                }
            }
        }
        log.info("FETCHING CLIENTSECRETDTOS");
        return clientSecrets;
    }


    public void updateTokens(List<TokenDTO> tokens) throws SQLException {
        final String query = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET ACCESS_TOKEN = ?, REFRESH_TOKEN = ?" +
                " WHERE TOKEN_ID = ?";

        try (Connection connection = APIMgtDBUtil.getConnection();
             PreparedStatement statement = connection.prepareStatement(query)) {
            try {
                for (TokenDTO token : tokens) {
                    connection.setAutoCommit(false);
                    statement.setString(1, token.getAccessToken());
                    statement.setString(2, token.getRefreshToken());
                    statement.setString(3, token.getTokenID());

                    statement.addBatch();
                }

                statement.executeBatch();
                connection.commit();
                log.info("UPDATE KEY QUERY EXECUTED-----");
            }
            catch (SQLException e) {
                connection.rollback();
            }
        }
    }


    public void updateClientSecrets(List<ClientSecretDTO> clientSecrets) throws SQLException {
        final String query = "UPDATE IDN_OAUTH_CONSUMER_APPS SET CONSUMER_SECRET = ? WHERE ID = ?";

        try (Connection connection = APIMgtDBUtil.getConnection();
             PreparedStatement statement = connection.prepareStatement(query)) {
            try {
                for (ClientSecretDTO clientSecret : clientSecrets) {
                    connection.setAutoCommit(false);
                    statement.setString(1, clientSecret.getClientSecret());
                    statement.setInt(2, clientSecret.getConsumerAppID());

                    statement.addBatch();
                }

                statement.executeBatch();
                connection.commit();
                log.info("UPDATE SECRET KEY QUERY EXECUTED-----");

            } catch (SQLException e) {
                connection.rollback();
            }
        }
    }

}
