package org.wso2.carbon.token.encryptor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;

import java.nio.charset.Charset;

public class Utils {
    private static final Log log = LogFactory.getLog(Utils.class);
    private static boolean[] validKeyChars = new boolean[128];

    static {
        char[] validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_".toCharArray();

        for (char validChar : validChars) {
            validKeyChars[validChar] = true;
        }
    }

    public static String encryptionUtil(String plainTextKey) {
        log.info("Encrypting: " + plainTextKey);
        String encryptedKey = null;
        byte[] byteKey = plainTextKey.getBytes();
        try {
            encryptedKey = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(byteKey);
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        return encryptedKey;
    }

    public static boolean isEncrypted(String key) {
        try {
            byte[] decryptedKey = CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(key);
            String decryptedKeyValue = new String(decryptedKey, Charset.defaultCharset());
            return isKeyValid(decryptedKeyValue);
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        return false;
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
