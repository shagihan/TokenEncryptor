package org.wso2.carbon.token.encryptor;
import org.wso2.carbon.core.util.CryptoException;

import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.*;
import org.wso2.carbon.core.util.CryptoUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @description This class is responsible
 * for the encryption of unencrypted tokens and secrets
 */

public class TokenProcessor {
    private static TokenProcessor processor = new TokenProcessor();
    private static final Log log = LogFactory.getLog(TokenProcessor.class);
    private static boolean[] validChars = new boolean[128];
    private List<TokenDTO> updatedTokens = new ArrayList<>();
    private List<ClientSecretDTO> updatedSecrets = new ArrayList<>();
    static {
        //possible chars that would get generated by api manager for tokens and client secrets
        char[] validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-".toCharArray();
        for (char validChar : validChars) {
            TokenProcessor.validChars[validChar] = true;
        }
    }
    private TokenProcessor(){
    }
    public static TokenProcessor getSharedProcessor(){
        return processor;
    }
    public void processEncryptionOnToken(final List<TokenDTO>tokens, final List<ClientSecretDTO>secrets,final Database database) {
        try {
           for (TokenDTO token : tokens) {
               try {
                   log.info("Before token encryption " + token.getAccessToken() + ",  " + token.getRefreshToken());
                   encrypt(token);
                   log.info("After token encryption " + token.getAccessToken() + ",  " + token.getRefreshToken());
               } catch (CryptoException e) {
                   log.info("Ignoring the encryption " + token.getAccessToken() + ",  " + token.getRefreshToken(), e);
               }
           }
           for (ClientSecretDTO clientSecret : secrets) {
               try {
                   log.info("Before secret encryption "+clientSecret.getClientSecret());
                   encrypt(clientSecret);
                   log.info("After secret encryption "+clientSecret.getClientSecret());
               } catch (CryptoException e){
                   log.info("Ignoring the encryption "+clientSecret.getClientSecret(),e);
               }
           }
           database.updateTokens(updatedTokens);
           database.updateClientSecrets(updatedSecrets);
       } catch (SQLException e) {
           log.error(e);
       }
    }

    private void encrypt(TokenDTO dto) throws CryptoException {
        boolean isEncrypted =false;
        if (isValidCharSet(dto.getRefreshToken())){//is a plain text
             String value = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(dto.getRefreshToken().getBytes(Charset.defaultCharset()));
             dto.setRefreshToken(value);
             isEncrypted = true;
        }
        if (isValidCharSet(dto.getAccessToken())){//is a plain text
            String value = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(dto.getAccessToken().getBytes(Charset.defaultCharset()));
            dto.setAccessToken(value);
            isEncrypted = true;
        }
        if(isEncrypted) {
            updatedTokens.add(dto);
        }
    }

    private void encrypt(ClientSecretDTO dto) throws CryptoException {
        if (isValidCharSet(dto.getClientSecret())){//is a plain text
            String value = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(dto.getClientSecret().getBytes(Charset.defaultCharset()));
            dto.setClientSecret(value);
            updatedSecrets.add(dto);
        }
    }

    /**
     * Cross validating the chas of the databse keys with the valid char set
     * @param key Raw key from database
     * @return
     */
    private static boolean isValidCharSet(final String key) {
        for (int i = 0; i < key.length(); ++i) {
            char keyChar = key.charAt(i);
            if (validChars.length <= keyChar) {
                return false;
            }
            if (!validChars[keyChar]) {
                return false;
            }
        }
        return true;
    }

}
