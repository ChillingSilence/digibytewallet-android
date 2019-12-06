package io.digibyte.tools.security;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.RequiresApi;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.Entity;
import com.facebook.crypto.keychain.KeyChain;
import com.platform.entities.WalletInfo;
import com.platform.tools.KVStoreManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import io.digibyte.DigiByte;
import io.digibyte.R;
import io.digibyte.exceptions.BRKeystoreErrorException;
import io.digibyte.tools.animation.BRDialog;
import io.digibyte.tools.manager.BRReportsManager;
import io.digibyte.tools.manager.BRSharedPrefs;
import io.digibyte.tools.util.BytesUtil;
import io.digibyte.tools.util.TypesConverter;
import io.digibyte.tools.util.Utils;
import io.digibyte.wallet.BRWalletManager;

/**
 * BreadWallet
 * <p/>
 * Created by Mihail Gutan <mihail@breadwallet.com> on 9/29/15.
 * Copyright (c) 2016 breadwallet LLC
 * <p/>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p/>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p/>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

public class BRKeyStore {
    private static final String TAG = BRKeyStore.class.getName();

    private static final String KEY_STORE_PREFS_NAME = "keyStorePrefs";
    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    public static final String PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7;
    public static final String BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC;

    public static final String NEW_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    public static final String NEW_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE;
    public static final String NEW_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM;

    public static Map<String, AliasObject> aliasObjectMap;

    private static final String PHRASE_IV = "ivphrase";
    private static final String CANARY_IV = "ivcanary";
    private static final String PUB_KEY_IV = "ivpubkey";
    private static final String WALLET_CREATION_TIME_IV = "ivtime";
    private static final String PASS_CODE_IV = "ivpasscode";
    private static final String FAIL_COUNT_IV = "ivfailcount";
    private static final String SPENT_LIMIT_IV = "ivspendlimit";
    private static final String TOTAL_LIMIT_IV = "ivtotallimit";
    private static final String FAIL_TIMESTAMP_IV = "ivfailtimestamp";
    private static final String AUTH_KEY_IV = "ivauthkey";
    private static final String TOKEN_IV = "ivtoken";
    private static final String PASS_TIME_IV = "passtimetoken";

    public static final String PHRASE_ALIAS = "phrase";
    public static final String CANARY_ALIAS = "canary";
    public static final String PUB_KEY_ALIAS = "pubKey";
    public static final String WALLET_CREATION_TIME_ALIAS = "creationTime";
    public static final String PASS_CODE_ALIAS = "passCode";
    public static final String FAIL_COUNT_ALIAS = "failCount";
    public static final String SPEND_LIMIT_ALIAS = "spendlimit";
    public static final String TOTAL_LIMIT_ALIAS = "totallimit";
    public static final String FAIL_TIMESTAMP_ALIAS = "failTimeStamp";
    public static final String AUTH_KEY_ALIAS = "authKey";
    public static final String TOKEN_ALIAS = "token";
    public static final String PASS_TIME_ALIAS = "passTime";

    private static final String PHRASE_FILENAME = "my_phrase";
    private static final String CANARY_FILENAME = "my_canary";
    private static final String PUB_KEY_FILENAME = "my_pub_key";
    private static final String WALLET_CREATION_TIME_FILENAME = "my_creation_time";
    private static final String PASS_CODE_FILENAME = "my_pass_code";
    private static final String FAIL_COUNT_FILENAME = "my_fail_count";
    private static final String SPEND_LIMIT_FILENAME = "my_spend_limit";
    private static final String TOTAL_LIMIT_FILENAME = "my_total_limit";
    private static final String FAIL_TIMESTAMP_FILENAME = "my_fail_timestamp";
    private static final String AUTH_KEY_FILENAME = "my_auth_key";
    private static final String TOKEN_FILENAME = "my_token";
    private static final String PASS_TIME_FILENAME = "my_pass_time";
    private static KeyStore keyStore = null;
    private static Crypto crypto;
    private static KeyChain keyChain;

    public static final int AUTH_DURATION_SEC = 300;

    static {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Creates a new Crypto object with default implementations of a key chain
        keyChain = new SharedPrefsBackedKeyChain(DigiByte.getContext(), CryptoConfig.KEY_256);
        attemptToLoadCrypto();

        aliasObjectMap = new HashMap<>();
        aliasObjectMap.put(PHRASE_ALIAS, new AliasObject(PHRASE_ALIAS, PHRASE_FILENAME, PHRASE_IV));
        aliasObjectMap.put(CANARY_ALIAS, new AliasObject(CANARY_ALIAS, CANARY_FILENAME, CANARY_IV));
        aliasObjectMap.put(PUB_KEY_ALIAS,
                new AliasObject(PUB_KEY_ALIAS, PUB_KEY_FILENAME, PUB_KEY_IV));
        aliasObjectMap.put(WALLET_CREATION_TIME_ALIAS,
                new AliasObject(WALLET_CREATION_TIME_ALIAS, WALLET_CREATION_TIME_FILENAME,
                        WALLET_CREATION_TIME_IV));
        aliasObjectMap.put(PASS_CODE_ALIAS,
                new AliasObject(PASS_CODE_ALIAS, PASS_CODE_FILENAME, PASS_CODE_IV));
        aliasObjectMap.put(FAIL_COUNT_ALIAS,
                new AliasObject(FAIL_COUNT_ALIAS, FAIL_COUNT_FILENAME, FAIL_COUNT_IV));
        aliasObjectMap.put(FAIL_COUNT_ALIAS,
                new AliasObject(FAIL_COUNT_ALIAS, FAIL_COUNT_FILENAME, FAIL_COUNT_IV));
        aliasObjectMap.put(SPEND_LIMIT_ALIAS,
                new AliasObject(SPEND_LIMIT_ALIAS, SPEND_LIMIT_FILENAME, SPENT_LIMIT_IV));
        aliasObjectMap.put(FAIL_TIMESTAMP_ALIAS,
                new AliasObject(FAIL_TIMESTAMP_ALIAS, FAIL_TIMESTAMP_FILENAME, FAIL_TIMESTAMP_IV));
        aliasObjectMap.put(AUTH_KEY_ALIAS,
                new AliasObject(AUTH_KEY_ALIAS, AUTH_KEY_FILENAME, AUTH_KEY_IV));
        aliasObjectMap.put(TOKEN_ALIAS, new AliasObject(TOKEN_ALIAS, TOKEN_FILENAME, TOKEN_IV));
        aliasObjectMap.put(PASS_TIME_ALIAS,
                new AliasObject(PASS_TIME_ALIAS, PASS_TIME_FILENAME, PASS_TIME_IV));
        aliasObjectMap.put(TOTAL_LIMIT_ALIAS,
                new AliasObject(TOTAL_LIMIT_ALIAS, TOTAL_LIMIT_FILENAME, TOTAL_LIMIT_IV));
    }

    private static void attemptToLoadCrypto() {
        int instantiationAttempts = 5;
        while (crypto == null && instantiationAttempts > 0) {
            crypto = AndroidConceal.get().createDefaultCrypto(keyChain);
            instantiationAttempts--;
        }
    }

    private static boolean useNewStorage(Context context) {
        if (BRSharedPrefs.useNewStorageSet(context)) {
            return BRSharedPrefs.getUseNewStorage(context);
        } else {
            try {
                PackageInfo pInfo = context.getPackageManager().getPackageInfo(
                        context.getPackageName(), 0);
                boolean useNewStorage = pInfo.versionCode > 2147 && BRSharedPrefs.getLastSyncTime(
                        context) == 0;
                BRSharedPrefs.setUseNewStorage(context, useNewStorage);
            } catch (Exception e) {
                BRSharedPrefs.setUseNewStorage(context,
                        BRSharedPrefs.getLastSyncTime(context) == 0);
            }
            return BRSharedPrefs.getUseNewStorage(context);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private synchronized static boolean _setData(Context context, byte[] data, String alias,
            String alias_file, String alias_iv,
            int request_code, boolean auth_required) throws InvalidKeyException {

        if (useNewStorage(context)) {
            try {
                attemptToLoadCrypto();
                storeEncryptedData(context, crypto.encrypt(data, Entity.create(alias)), alias_iv);
                return true;
            } catch (Exception e) {
                return false;
            }
        } else {

            validateSet(data, alias, alias_file, alias_iv, auth_required);

            try {
                SecretKey secretKey = (SecretKey) keyStore.getKey(alias, null);
                Cipher inCipher = Cipher.getInstance(NEW_CIPHER_ALGORITHM);

                if (secretKey == null) {
                    //create key if not present
                    secretKey = createKeys(alias, auth_required);
                    inCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                } else {
                    //see if the key is old format, create a new one if it is
                    try {
                        inCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    } catch (InvalidKeyException ignored) {
                        if (ignored instanceof InvalidKeyException) {
                            throw ignored;
                        }
                        Log.e(TAG, "_setData: OLD KEY PRESENT: " + alias);
                        //create new key and reinitialize the cipher
                        secretKey = createKeys(alias, auth_required);
                        inCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    }
                }

                //the key cannot still be null
                if (secretKey == null) {
                    BRKeystoreErrorException ex = new BRKeystoreErrorException(
                            "secret is null on _setData: " + alias);
                    BRReportsManager.reportBug(ex);
                    return false;
                }

                byte[] iv = inCipher.getIV();
                if (iv == null) throw new NullPointerException("iv is null!");

                //store the iv
                storeEncryptedData(context, iv, alias_iv);
                byte[] encryptedData = inCipher.doFinal(data);
                //store the encrypted data
                storeEncryptedData(context, encryptedData, alias);
                return true;
            } catch (InvalidKeyException e) {
                Log.e(TAG, "_setData: showAuthenticationScreen: " + alias);
                showAuthenticationScreen(context, request_code, alias);
                throw e;
            } catch (Exception e) {
                BRReportsManager.reportBug(e);
                e.printStackTrace();
                return false;
            }
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private static SecretKey createKeys(String alias, boolean auth_required)
            throws InvalidAlgorithmParameterException, KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEY_STORE);

        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constrains (purposes) in the constructor of the Builder
        keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(NEW_BLOCK_MODE)
                .setUserAuthenticationRequired(auth_required)
                .setUserAuthenticationValidityDurationSeconds(AUTH_DURATION_SEC)
                .setRandomizedEncryptionRequired(false)
                .setEncryptionPaddings(NEW_PADDING)
                .build());
        return keyGenerator.generateKey();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private synchronized static byte[] _getData(final Context context, String alias,
            String alias_file, String alias_iv, int request_code) throws InvalidKeyException {

        if (useNewStorage(context)) {
            try {
                attemptToLoadCrypto();
                return crypto.decrypt(retrieveEncryptedData(context, alias_iv), Entity.create(alias));
            } catch (Exception e) {
                return null;
            }
        } else {

            validateGet(alias, alias_file, alias_iv);//validate entries

            try {
                SecretKey secretKey = (SecretKey) keyStore.getKey(alias, null);

                byte[] encryptedData = retrieveEncryptedData(context, alias);
                if (encryptedData != null) {
                    //new format data is present, good
                    byte[] iv = retrieveEncryptedData(context, alias_iv);
                    if (iv == null) {
                        throw new NullPointerException("iv is missing when data isn't: " + alias);
                    }
                    Cipher outCipher;

                    outCipher = Cipher.getInstance(NEW_CIPHER_ALGORITHM);
                    outCipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                    try {
                        byte[] decryptedData = outCipher.doFinal(encryptedData);
                        if (decryptedData != null) {
                            return decryptedData;
                        }
                    } catch (IllegalBlockSizeException | BadPaddingException e) {
                        e.printStackTrace();
                        return null;
                    }
                }
                //no new format data, get the old one and migrate it to the new format
                String encryptedDataFilePath = getFilePath(alias_file, context);

                if (secretKey == null) {
                    /* no such key, the key is just simply not there */
                    boolean fileExists = new File(encryptedDataFilePath).exists();
//                Log.e(TAG, "_getData: " + alias + " file exist: " + fileExists);
                    if (!fileExists) {
                        return null;/* file also not there, fine then */
                    }
                    BRKeystoreErrorException ex = new BRKeystoreErrorException(
                            "file is present but the key is gone: " + alias);
                    BRReportsManager.reportBug(ex);
                    return null;
                }

                boolean ivExists = new File(getFilePath(alias_iv, context)).exists();
                boolean aliasExists = new File(getFilePath(alias_file, context)).exists();
                //cannot happen, they all should be present
                if (!ivExists || !aliasExists) {
                    removeAliasAndFiles(alias, context);
                    //report it if one exists and not the other.
                    if (ivExists != aliasExists) {
                        BRKeystoreErrorException ex = new BRKeystoreErrorException(
                                "alias or iv isn't on the disk: " + alias + ", aliasExists:"
                                        + aliasExists);
                        BRReportsManager.reportBug(ex);
                        return null;
                    } else {
                        BRKeystoreErrorException ex = new BRKeystoreErrorException(
                                "!ivExists && !aliasExists: " + alias);
                        BRReportsManager.reportBug(ex);
                        return null;
                    }
                }

                byte[] iv = readBytesFromFile(getFilePath(alias_iv, context));
                if (Utils.isNullOrEmpty(iv)) {
                    throw new RuntimeException("iv is missing for " + alias);
                }
                Cipher outCipher = Cipher.getInstance(CIPHER_ALGORITHM);
                outCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
                CipherInputStream cipherInputStream = new CipherInputStream(
                        new FileInputStream(encryptedDataFilePath), outCipher);
                byte[] result = BytesUtil.readBytesFromStream(cipherInputStream);
                if (result == null) {
                    throw new RuntimeException(
                            "Failed to read bytes from CipherInputStream for alias " + alias);
                }

                //create the new format key
                SecretKey newKey = createKeys(alias,
                        (alias.equals(PHRASE_ALIAS) || alias.equals(CANARY_ALIAS)));
                if (newKey == null) {
                    throw new RuntimeException("Failed to create new key for alias " + alias);
                }
                Cipher inCipher = Cipher.getInstance(NEW_CIPHER_ALGORITHM);
                //init the cipher
                inCipher.init(Cipher.ENCRYPT_MODE, newKey);
                iv = inCipher.getIV();
                //store the new iv
                storeEncryptedData(context, iv, alias_iv);
                //encrypt the data
                encryptedData = inCipher.doFinal(result);
                //store the new data
                storeEncryptedData(context, encryptedData, alias);
                return result;

            } catch (InvalidKeyException e) {
                /** user not authenticated, ask the system for authentication */
                Log.e(TAG, "_getData: showAuthenticationScreen: " + alias);
                showAuthenticationScreen(context, request_code, alias);
                throw (InvalidKeyException) e;
            } catch (IOException | KeyStoreException e) {
                /** keyStore.load(null) threw the Exception, meaning the keystore is unavailable */
                Log.e(TAG,
                        "_getData: keyStore.load(null) threw the Exception, meaning the keystore "
                                + "is "
                                + "unavailable",
                        e);
                BRReportsManager.reportBug(e);
                if (e instanceof FileNotFoundException) {
                    Log.e(TAG, "_getData: File not found exception", e);

                    RuntimeException ex = new RuntimeException(
                            "the key is present but the phrase on the disk no");
                    BRReportsManager.reportBug(ex);
                    throw new RuntimeException(e.getMessage());
                } else {
                    BRReportsManager.reportBug(e);
                    throw new RuntimeException(e.getMessage());
                }

            } catch (UnrecoverableKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
                    InvalidAlgorithmParameterException e) {
                /** if for any other reason the keystore fails, crash! */
                Log.e(TAG, "getData: error: " + e.getClass().getSuperclass().getName());
                BRReportsManager.reportBug(e);
                return null;
            } catch (BadPaddingException | IllegalBlockSizeException | NoSuchProviderException e) {
                e.printStackTrace();
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    private static void validateGet(String alias, String alias_file, String alias_iv)
            throws IllegalArgumentException {
        AliasObject obj = aliasObjectMap.get(alias);
        if (!obj.alias.equals(alias) || !obj.datafileName.equals(alias_file)
                || !obj.ivFileName.equals(alias_iv)) {
            String err = alias + "|" + alias_file + "|" + alias_iv + ", obj: " + obj.alias + "|"
                    + obj.datafileName + "|" + obj.ivFileName;
            throw new IllegalArgumentException("keystore insert inconsistency in names: " + err);
        }
    }

    private static void validateSet(byte[] data, String alias, String alias_file, String alias_iv,
            boolean auth_required) throws IllegalArgumentException {
        if (data == null) throw new IllegalArgumentException("keystore insert data is null");
        AliasObject obj = aliasObjectMap.get(alias);
        if (!obj.alias.equals(alias) || !obj.datafileName.equals(alias_file)
                || !obj.ivFileName.equals(alias_iv)) {
            String err = alias + "|" + alias_file + "|" + alias_iv + ", obj: " + obj.alias + "|"
                    + obj.datafileName + "|" + obj.ivFileName;
            throw new IllegalArgumentException("keystore insert inconsistency in names: " + err);
        }

        if (auth_required) {
            if (!alias.equals(PHRASE_ALIAS) && !alias.equals(CANARY_ALIAS)) {
                throw new IllegalArgumentException(
                        "keystore auth_required is true but alias is: " + alias);
            }
        }
    }

    private synchronized static String getFilePath(String fileName, Context context) {
        String filesDirectory = context.getFilesDir().getAbsolutePath();
        return filesDirectory + File.separator + fileName;
    }

    public synchronized static boolean putPhrase(byte[] strToStore, Context context,
            int requestCode) throws InvalidKeyException {
        if (PostAuth.isStuckWithAuthLoop) {
            showLoopBugMessage(context);
            throw new InvalidKeyException();
        }
        AliasObject obj = aliasObjectMap.get(PHRASE_ALIAS);
        return !(strToStore == null || strToStore.length == 0) && _setData(context, strToStore,
                obj.alias, obj.datafileName, obj.ivFileName, requestCode, true);
    }

    public synchronized static byte[] getPhrase(final Context context, int requestCode)
            throws InvalidKeyException {
        if (PostAuth.isStuckWithAuthLoop) {
            showLoopBugMessage(context);
            throw new InvalidKeyException();
        }
        AliasObject obj = aliasObjectMap.get(PHRASE_ALIAS);
        return _getData(context, obj.alias, obj.datafileName, obj.ivFileName, requestCode);
    }

    public synchronized static boolean putMasterPublicKey(byte[] masterPubKey, Context context) {
        AliasObject obj = aliasObjectMap.get(PUB_KEY_ALIAS);
        try {
            return masterPubKey != null && masterPubKey.length != 0 && _setData(context,
                    masterPubKey, obj.alias, obj.datafileName, obj.ivFileName, 0, false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static byte[] getMasterPublicKey(final Context context) {
        AliasObject obj = aliasObjectMap.get(PUB_KEY_ALIAS);
        try {
            return _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public synchronized static boolean putAuthKey(byte[] authKey, Context context) {
        AliasObject obj = aliasObjectMap.get(AUTH_KEY_ALIAS);
        try {
            return authKey != null && authKey.length != 0 && _setData(context, authKey, obj.alias,
                    obj.datafileName, obj.ivFileName, 0, false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static byte[] getAuthKey(final Context context) {
        AliasObject obj = aliasObjectMap.get(AUTH_KEY_ALIAS);
        try {
            return _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public synchronized static boolean putWalletCreationTime(int creationTime, Context context) {
        AliasObject obj = aliasObjectMap.get(WALLET_CREATION_TIME_ALIAS);
        byte[] bytesToStore = TypesConverter.intToBytes(creationTime);
        try {
            return bytesToStore.length != 0 && _setData(context, bytesToStore, obj.alias,
                    obj.datafileName, obj.ivFileName, 0, false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static int getWalletCreationTime(final Context context) {
        AliasObject obj = aliasObjectMap.get(WALLET_CREATION_TIME_ALIAS);
        byte[] result = null;
        try {
            result = _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        if (Utils.isNullOrEmpty(result)) {
            //if none, try getting from KVStore
            WalletInfo info = KVStoreManager.getInstance().getWalletInfo(context);
            if (info != null) {
                int creationDate = info.creationDate;
                putWalletCreationTime(creationDate, context);
                return creationDate;
            } else {
                return 0;
            }
        } else {
            return TypesConverter.bytesToInt(result);
        }
    }

    public synchronized static boolean putPinCode(String pinCode, Context context) {
        AliasObject obj = aliasObjectMap.get(PASS_CODE_ALIAS);
        byte[] bytesToStore = pinCode.getBytes();
        try {
            return _setData(context, bytesToStore, obj.alias, obj.datafileName, obj.ivFileName, 0,
                    false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static String getPinCode(final Context context) {
        AliasObject obj = aliasObjectMap.get(PASS_CODE_ALIAS);
        byte[] result = null;
        try {
            result = _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        String pinCode = result == null ? "" : new String(result);
        try {
            Integer.parseInt(pinCode);
        } catch (Exception e) {
            Log.e(TAG, "getPinCode: WARNING passcode isn't a number: " + pinCode);
            pinCode = "";
            putPinCode(pinCode, context);
            putFailCount(0, context);
            putFailTimeStamp(0, context);
            return pinCode;
        }
        if (pinCode.length() != 6 && pinCode.length() != 4) {
            pinCode = "";
            putPinCode(pinCode, context);
            putFailCount(0, context);
            putFailTimeStamp(0, context);
        }
        return pinCode;
    }

    public synchronized static boolean putFailCount(int failCount, Context context) {
        AliasObject obj = aliasObjectMap.get(FAIL_COUNT_ALIAS);
        if (failCount >= 3) {
            long time = BRSharedPrefs.getSecureTime(context);
            putFailTimeStamp(time, context);
        }
        byte[] bytesToStore = TypesConverter.intToBytes(failCount);
        try {
            return bytesToStore.length != 0 && _setData(context, bytesToStore, obj.alias,
                    obj.datafileName, obj.ivFileName, 0, false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static int getFailCount(final Context context) {
        AliasObject obj = aliasObjectMap.get(FAIL_COUNT_ALIAS);
        byte[] result = null;
        try {
            result = _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return result != null && result.length > 0 ? TypesConverter.bytesToInt(result) : 0;
    }

    public synchronized static boolean putSpendLimit(long spendLimit, Context context) {
        AliasObject obj = aliasObjectMap.get(SPEND_LIMIT_ALIAS);
        byte[] bytesToStore = TypesConverter.long2byteArray(spendLimit);
        try {
            return bytesToStore.length != 0 && _setData(context, bytesToStore, obj.alias,
                    obj.datafileName, obj.ivFileName, 0, false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static long getSpendLimit(final Context context) {
        AliasObject obj = aliasObjectMap.get(SPEND_LIMIT_ALIAS);
        byte[] result = null;
        try {
            result = _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        if (result == null) {
            return 0;
        }
        long limit = TypesConverter.byteArray2long(result);
        return result != null && result.length > 0 ? limit : 0;
    }

    public synchronized static boolean putFailTimeStamp(long spendLimit, Context context) {
        AliasObject obj = aliasObjectMap.get(FAIL_TIMESTAMP_ALIAS);
        byte[] bytesToStore = TypesConverter.long2byteArray(spendLimit);
        try {
            return bytesToStore.length != 0 && _setData(context, bytesToStore, obj.alias,
                    obj.datafileName, obj.ivFileName, 0, false);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public synchronized static long getFailTimeStamp(final Context context) {
        AliasObject obj = aliasObjectMap.get(FAIL_TIMESTAMP_ALIAS);
        byte[] result = null;
        try {
            result = _getData(context, obj.alias, obj.datafileName, obj.ivFileName, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return result != null && result.length > 0 ? TypesConverter.byteArray2long(result) : 0;
    }

    public synchronized static boolean resetWalletKeyStore(Context context) {
        try {
            int count = 0;
            while (keyStore.aliases().hasMoreElements()) {
                String alias = keyStore.aliases().nextElement();
                removeAliasAndFiles(alias, context);
                destroyEncryptedData(context, alias);
                count++;
            }
            for (AliasObject aliasObject : aliasObjectMap.values()) {
                destroyEncryptedData(context, aliasObject.ivFileName);
            }
            Log.e(TAG, "resetWalletKeyStore: removed:" + count);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        } catch (NullPointerException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private synchronized static void removeAliasAndFiles(String alias, Context context) {
        try {
            keyStore.deleteEntry(alias);
            String dataFileString = getFilePath(aliasObjectMap.get(alias).datafileName, context);
            if (!TextUtils.isEmpty(dataFileString)) {
                new File(dataFileString).delete();
            }
            String ivFileString = getFilePath(aliasObjectMap.get(alias).ivFileName, context);
            if (!TextUtils.isEmpty(ivFileString)) {
                new File(ivFileString).delete();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void storeEncryptedData(Context ctx, byte[] data, String name) {
        SharedPreferences pref = ctx.getSharedPreferences(KEY_STORE_PREFS_NAME,
                Context.MODE_PRIVATE);
        String base64 = Base64.encodeToString(data, Base64.DEFAULT);
        SharedPreferences.Editor edit = pref.edit();
        edit.putString(name, base64);
        edit.apply();
    }

    private static void destroyEncryptedData(Context ctx, String name) {
        SharedPreferences pref = ctx.getSharedPreferences(KEY_STORE_PREFS_NAME,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor edit = pref.edit();
        edit.remove(name);
        edit.apply();
    }

    private static byte[] retrieveEncryptedData(Context ctx, String name) {
        SharedPreferences pref = ctx.getSharedPreferences(KEY_STORE_PREFS_NAME,
                Context.MODE_PRIVATE);
        String base64 = pref.getString(name, null);
        if (base64 == null) return null;
        return Base64.decode(base64, Base64.DEFAULT);
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private synchronized static void showAuthenticationScreen(Context context, int requestCode,
            String alias) {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        if (!alias.equalsIgnoreCase(PHRASE_ALIAS) && !alias.equalsIgnoreCase(CANARY_ALIAS)) {
            BRReportsManager.reportBug(
                    new IllegalArgumentException("requesting auth for: " + alias), true);
        }
        if (context instanceof Activity) {
            Activity app = (Activity) context;
            KeyguardManager mKeyguardManager = (KeyguardManager) app.getSystemService(
                    Context.KEYGUARD_SERVICE);
            if (mKeyguardManager == null) {
                NullPointerException ex = new NullPointerException(
                        "KeyguardManager is null in showAuthenticationScreen");
                BRReportsManager.reportBug(ex, true);
                return;
            }
            String message = context.getString(R.string.UnlockScreen_touchIdPrompt_android);
            if (Utils.isEmulatorOrDebug(app)) {
                message = alias;
            }
            Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(
                    context.getString(R.string.UnlockScreen_touchIdTitle_android), message);

            if (Utils.isEmulatorOrDebug(context)) {
                intent = mKeyguardManager.createConfirmDeviceCredentialIntent(alias,
                        context.getString(R.string.UnlockScreen_touchIdPrompt_android));
            }
            if (intent != null) {
                app.startActivityForResult(intent, requestCode);
            } else {
                Log.e(TAG, "showAuthenticationScreen: failed to create intent for auth");
                BRReportsManager.reportBug(new RuntimeException(
                        "showAuthenticationScreen: failed to create intent for auth"));
                app.finish();
            }
        } else {
            BRReportsManager.reportBug(
                    new RuntimeException("showAuthenticationScreen: context is not activity!"));
            Log.e(TAG, "showAuthenticationScreen: context is not activity!");
        }
    }

    private static byte[] readBytesFromFile(String path) {
        byte[] bytes = null;
        FileInputStream fin = null;
        try {
            File file = new File(path);
            fin = new FileInputStream(file);
            bytes = BytesUtil.readBytesFromStream(fin);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    private static void showLoopBugMessage(final Context app) {
        Log.e(TAG, "showLoopBugMessage: ");
        String mess = app.getString(R.string.ErrorMessages_loopingLockScreen_android);
        mess = mess.substring(0, mess.indexOf("[") - 1);
        BRDialog.showCustomDialog(app, app.getString(R.string.JailbreakWarnings_title), mess,
                app.getString(R.string.AccessibilityLabels_close), null,
                brDialogView -> {
                    if (app instanceof Activity) ((Activity) app).finish();
                }, null, null, 0);
    }


    public static class AliasObject {
        public String alias;
        public String datafileName;
        public String ivFileName;

        AliasObject(String alias, String datafileName, String ivFileName) {
            this.alias = alias;
            this.datafileName = datafileName;
            this.ivFileName = ivFileName;
        }
    }
}