package org.wso2.carbon.token.encryptor;

import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.apimgt.migration.util.ResourceUtil;
import java.util.ArrayList;
import java.nio.charset.Charset;

/**
 * @description This class is responsible
 * for the encryption of unencrypted tokens and secrets
 */

public class TokenProcessor {
    private String accessToken;
    private String RefreshToken;
    private String clientSecret;
    private ArrayList<TokenDTO> encryptedTokenKeys = new ArrayList<>();
    private ArrayList<ClientSecretDTO> encryptedSecretKeys = new ArrayList<>();
    private static TokenProcessor processor = new TokenProcessor();
    private TokenProcessor(){
    }
    public static TokenProcessor getSharedProcessor(){
        return processor;
    }
    public void setAccessToken(final String accessToken) {
        this.accessToken = accessToken;
    }
    public void setRefreshToken(final String refreshToken) {
        RefreshToken = refreshToken;
    }
    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }
    public String getAccessToken() {
        return accessToken;
    }
    public String getRefreshToken() {
        return RefreshToken;
    }
    public String getClientSecret() {
        return clientSecret;
    }
    public void processEncryptionOnToken(final String primary) {
        byte []accessTokenByteArray = this.getAccessToken().getBytes();
        byte []refreshTokenByteArray = this.getRefreshToken().getBytes();
        byte []clientSecretByteArray = this.getClientSecret().getBytes();
        try {
            TokenDTO tokenDto = null;
            if (accessTokenByteArray.length > 0 || refreshTokenByteArray.length > 0) {
                tokenDto = new TokenDTO();
                tokenDto.setTokenID(primary);
            }
            if (!this.isTokenAlreadyEncrypted(this.getAccessToken())) {
                String accessKeyEncrypted = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(accessTokenByteArray).toString();
                tokenDto.setAccessToken(accessKeyEncrypted);
            }
            if (!this.isTokenAlreadyEncrypted(this.getRefreshToken())) {
                String refreshKeyEncrypted = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(refreshTokenByteArray).toString();
                tokenDto.setRefreshToken(refreshKeyEncrypted);
            }
            if (tokenDto != null){
                this.setEncryptedKeys(tokenDto);
            }
            if (!this.isTokenAlreadyEncrypted(this.getClientSecret())) {
                ClientSecretDTO secretDto = new ClientSecretDTO();
                secretDto.setConsumerAppID(Integer.parseInt(primary));
                String clientKeyEncrypted = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(clientSecretByteArray).toString();
                secretDto.setClientSecret(clientKeyEncrypted);
                this.setEncryptedKeys(secretDto);
            }
        }catch (CryptoException e) {
            e.printStackTrace();
        }
    }

    private void setEncryptedKeys(TokenDTO token) {
        this.encryptedTokenKeys.add(token);
    }

    private void setEncryptedKeys(ClientSecretDTO token) {
        this.encryptedSecretKeys.add(token);
    }


    public ArrayList<TokenDTO> returnEncryptedTokenKeys(){
        return this.encryptedTokenKeys;
    }

    public ArrayList<ClientSecretDTO> returnEncryptedSecretKeys(){
        return this.encryptedSecretKeys;
    }

    private boolean isTokenAlreadyEncrypted(final String token) throws CryptoException{
        byte[] decryptedKey =  CryptoUtil.getDefaultCryptoUtil().
                base64DecodeAndDecrypt(token);
        String decryptedValue = new String(decryptedKey, Charset.defaultCharset());
        if (ResourceUtil.isConsumerKeyValid(decryptedValue)) {
            return true;
        }
        return false;
    }



}
