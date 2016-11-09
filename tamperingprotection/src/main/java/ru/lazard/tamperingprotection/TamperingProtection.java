package ru.lazard.tamperingprotection;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.text.TextUtils;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Class for check is application tampered or not.<br> TamperingProtection check: <br>
 * 1) application signature - protection from resign you app. <br>
 * 2) installer store - app must be inbstalled only from store (not by hand).<br>
 * 3) package name - sometimes malefactor change package name and sells your application as its.<br>
 * 4) debug mode - production version of app mustn't run in debug mode.
 * <p>
 * <br><br>
 * Simple usage:<br>
 * <code>
 * TamperingProtection protection = new TamperingProtection(this);<br>
 * protection.setAcceptedDexCrcs(); // don't validate classes.dex CRC code.
 * protection.setAcceptedStores(); // install from any where <br>
 * protection.setAcceptedPackageNames("ru.lazard.sample"); // your package name<br>
 * protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"); // MD5 fingerprint<br>
 * protection.setAcceptStartOnEmulator(true);// allow run on emulator <br>
 * protection.setAcceptStartInDebugMode(true);// allow run in debug mode <br>
 * <p>
 * protection.validateAll();<br>
 * </code>
 * <br><br>
 * Created by Egor on 08.11.2016.<br><br>
 */

public class TamperingProtection {

    /**
     * Package name of Google play installer.
     */
    public static final String GOOGLE_PLAY_STORE_PACKAGE = "com.android.vending";
    /**
     * Package name of Amazon app store installer.
     */
    public static final String AMAZON_APP_STORE_PACKAGE = "com.amazon.venezia";
    /**
     * Package name of Samsung app store installer.
     */
    public static final String SAMSUNG_APP_STORE_PACKAGE = "com.sec.android.app.samsungapps";

    private final Context context;
    private List<String> stores = Arrays.asList();
    private List<String> packageNames = Arrays.asList();
    private List<String> signatures = Arrays.asList();
    private long[] dexCrcs = {};
    private boolean isEmulatorAvailable = true;
    private boolean isDebugAvailable = true;


    public TamperingProtection(Context context) {
        this.context = context;
    }

    /**
     * Stores are allowed to install the application. You must set their package names.<br> For example for Google Play must be <code>"com.android.vending"</code>
     *
     * @param stores - Package names of stores. <br>By default allowed installation from anywhere. For production recommended next stores:  Google play, Amazon and Samsung store. Their package names are: <br>{@link #GOOGLE_PLAY_STORE_PACKAGE},<br>{@link #AMAZON_APP_STORE_PACKAGE},<br>{@link #SAMSUNG_APP_STORE_PACKAGE}.
     */
    public void setAcceptedStores(String... stores) {
        this.stores = Arrays.asList(stores);
    }

    /**
     * Package name of you app (or many package names for Pro and Lite versions).
     *
     * @param packageNames - List of package names.
     */
    public void setAcceptedPackageNames(String... packageNames) {
        this.packageNames = Arrays.asList(packageNames);
    }

    /**
     * Md5 fingerprint of you app (or many fingerprints for release and debug keystore).<br><br>
     * For get MD5 fingerprint use command line:<br><code>
     * keytool -list -v -keystore &lt;YOU_PATH_TO_KEYSTORE&gt; -alias &lt;YOU_ALIAS&gt; -storepass &lt;YOU_STOREPASS&gt; -keypass &lt;YOU_KEYPASS&gt;
     * </code><br>
     * For get MD5 fingerprint for debug keystore:<br><code>
     * keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
     * </code>
     *
     * @param signatures - list of signatures ( <b>MD5</b> fingerprint of keystore ). Each looks like: <code>"CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"</code>
     */
    public void setAcceptedSignatures(String... signatures) {
        this.signatures = Arrays.asList(signatures);
    }

    /**
     * Is allow start app on emulator or not.
     *
     * @param isEmulatorAvailable - by default true
     */
    public void setAcceptStartOnEmulator(boolean isEmulatorAvailable) {
        this.isEmulatorAvailable = isEmulatorAvailable;
    }

    /**
     * Is allow start app in debug mode or not.
     *
     * @param isDebugAvailable - by default true
     */
    public void setAcceptStartInDebugMode(boolean isDebugAvailable) {
        this.isDebugAvailable = isDebugAvailable;
    }

    /**
     * Check Crc (checksum) of classes.dex file in apk. <br><b>Note:</> don't keep CRC codes hardcoded in java classes! Keep it in resources (strings.xml) or in JNI code.
     *
     * @param crcs - by default empty (no crc check).
     */
    public void setAcceptedDexCrcs(long... crcs) {
        this.dexCrcs =  crcs;
    }

    /**
     * Check is app valid or tampered.
     *
     * @return - True if valid. False if tampered.
     */
    public boolean validateAll() {
        try {
            validateAllOrThrowException();
            return true;
        } catch (ValidationException exception) {
            return false;
        }
    }

    /**
     * Check is app valid or tampered. If validation fail, then method throw
     * <code>ValidationException</code> with detail description of fail reason.
     *
     * @return - nothing if valid. Throw <code>ValidationException</code> if tampered.
     */
    public void validateAllOrThrowException() throws ValidationException {
        validateDebugMode();
        validateEmulator();
        validatePackage();
        validateStore();
        validateSignature();
        validateDexCRC();

    }

    private void validateDebugMode() throws ValidationException {
        if (isDebugAvailable) return; // // validation success (no validation need)

        // check by BuildConfig
        if (BuildConfig.DEBUG)
            throw new ValidationException(ValidationException.ERROR_CODE_DEBUG_MODE, "Run in debug mode checked by BuildConfig.");

        // check by ApplicationInfo
        boolean isDebuggable =  ( 0 != ( context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE ) );
        if (isDebuggable) throw new ValidationException(ValidationException.ERROR_CODE_DEBUG_MODE, "Run in debug mode checked by ApplicationInfo. Flags="+context.getApplicationInfo().flags);
    }

    private void validateEmulator() throws ValidationException {
        if (isEmulatorAvailable) return; // validation success (no validation need)

        // received from this project: https://github.com/gingo/android-emulator-detector
        int rating = 0;
        if (Build.PRODUCT.equals("sdk") ||
                Build.PRODUCT.equals("google_sdk") ||
                Build.PRODUCT.equals("sdk_x86") ||
                Build.PRODUCT.equals("vbox86p")) {
            rating++;
        }
        if (Build.MANUFACTURER.equals("unknown") ||
                Build.MANUFACTURER.equals("Genymotion")) {
            rating++;
        }
        if (Build.BRAND.equals("generic") ||
                Build.BRAND.equals("generic_x86")) {
            rating++;
        }
        if (Build.DEVICE.equals("generic") ||
                Build.DEVICE.equals("generic_x86") ||
                Build.DEVICE.equals("vbox86p")) {
            rating++;
        }
        if (Build.MODEL.equals("sdk") ||
                Build.MODEL.equals("google_sdk") ||
                Build.MODEL.equals("Android SDK built for x86")) {
            rating++;
        }
        if (Build.HARDWARE.equals("goldfish") ||
                Build.HARDWARE.equals("vbox86")) {
            rating++;
        }
        if (Build.FINGERPRINT.contains("generic/sdk/generic") ||
                Build.FINGERPRINT.contains("generic_x86/sdk_x86/generic_x86") ||
                Build.FINGERPRINT.contains("generic/google_sdk/generic") ||
                Build.FINGERPRINT.contains("generic/vbox86p/vbox86p")) {
            rating++;
        }
        boolean isEmulator = rating > 4;

        if (isEmulator)
            throw new ValidationException(ValidationException.ERROR_CODE_RUN_ON_EMULATOR, "Device looks like emulator.\n" +
                    "Build.PRODUCT: " + Build.PRODUCT + "\n" +
                    "Build.MANUFACTURER: " + Build.MANUFACTURER + "\n" +
                    "Build.BRAND: " + Build.BRAND + "\n" +
                    "Build.DEVICE: " + Build.DEVICE + "\n" +
                    "Build.MODEL: " + Build.MODEL + "\n" +
                    "Build.HARDWARE: " + Build.HARDWARE + "\n" +
                    "Build.FINGERPRINT: " + Build.FINGERPRINT);
    }

    private void validatePackage() throws ValidationException {
        if (packageNames == null || packageNames.size() <= 0)
            return;// validation success (no validation need)
        String packageName = context.getApplicationContext().getPackageName();
        if (TextUtils.isEmpty(packageName))
            throw new ValidationException(ValidationException.ERROR_CODE_PACKAGE_NAME_IS_EMPTY, "Current package name is empty: packageName=\"" + packageName + "\";");
        for (String allowedPackageName : packageNames) {
            if (packageName.equalsIgnoreCase(allowedPackageName)) return;// validation success
        }
        throw new ValidationException(ValidationException.ERROR_CODE_PACKAGE_NAME_NOT_VALID, "Not valid package name:  CurrentPackageName=\"" + packageName + "\";  validPackageNames=" + packageNames.toString() + ";");
    }

    private void validateStore() throws ValidationException {
        if (stores == null || stores.size() <= 0) return;// validation success (no validation need)
        final String installer = context.getPackageManager().getInstallerPackageName(context.getPackageName());
        if (TextUtils.isEmpty(installer))
            throw new ValidationException(ValidationException.ERROR_CODE_STORE_IS_EMPTY, "Current store is empty: store=\"" + installer + "\"; App installed by user (not by store).");
        for (String allowedStore : stores) {
            if (installer.equalsIgnoreCase(allowedStore)) return;// validation success
        }
        throw new ValidationException(ValidationException.ERROR_CODE_STORE_NOT_VALID, "Not valid store:  CurrentStore=\"" + installer + "\";  validStores=" + stores.toString() + ";");
    }

    private void validateDexCRC() throws ValidationException {
        if (dexCrcs == null || dexCrcs.length <= 0)
            return;// validation success (no validation need)
        try {
            ZipFile zf = new ZipFile(context.getPackageCodePath());
            ZipEntry ze = zf.getEntry("classes.dex");
            long crc = ze.getCrc();
            for (long allowedDexCrc : dexCrcs) {
                if (allowedDexCrc == crc) return;// validation success
            }
            throw new ValidationException(ValidationException.ERROR_CODE_CRC_NOT_VALID, "Crc code of .dex not valid. CurrentDexCrc=" + crc + "  acceptedDexCrcs=" + Arrays.toString(dexCrcs) + ";");
        } catch (IOException e) {
            e.printStackTrace();
            throw new ValidationException(ValidationException.ERROR_CODE_CRC_UNKNOWN_EXCEPTION, "Exception on .dex CNC validation.", e);
        }
    }

    private void validateSignature() throws ValidationException {
        if (signatures == null || signatures.size() <= 0)
            return;// validation success (no validation need)
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);

            if (packageInfo.signatures == null || packageInfo.signatures.length <= 0) {
                throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_IS_EMPTY, "No signatures found.");
            }
            // TODO Maybe multiple signatures is a type of tampering, but im not sure. If you sure then uncomment next rows.
            // if (packageInfo.signatures.length != 1) {
            //     throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_MULTIPLE, "Multiple signatures found. Total signatures=" + packageInfo.signatures.length + ";");
            // }

            Signature signature = packageInfo.signatures[0];
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(signature.toByteArray());
            byte[] digits = md.digest();

            char[] hexArray = "0123456789ABCDEF".toCharArray();
            String md5String = "";
            for (byte digit : digits) {
                int pos = digit & 0xFF;
                md5String += "" + hexArray[pos >> 4] + hexArray[pos & 0x0f] + ":";
            }
            if (md5String.length() > 0) {
                md5String = md5String.substring(0, md5String.length() - 1);
            }


            for (String allowedSignature : signatures) {
                if (md5String.equalsIgnoreCase(allowedSignature)) return;// validation success
            }
            throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_NOT_VALID, "Not valid signature: CurrentSignature=\"" + md5String + "\";  validSignatures=" + signatures.toString() + ";");
        } catch (PackageManager.NameNotFoundException exception) {
            throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_UNKNOWN_EXCEPTION, "Exception on signature validation.", exception);
        } catch (NoSuchAlgorithmException exception) {
            throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_UNKNOWN_EXCEPTION, "Exception on signature validation.", exception);
        }

    }

    /**
     * Exception with detailed description of validation fail reason.<br>
     * Look to {@link #getErrorCode} for get fail reason details ( and {@link #getMessage} for get text description).
     */
    public static final class ValidationException extends Exception {
        public static final int ERROR_CODE_UNKNOWN_EXCEPTION = 1;
        public static final int ERROR_CODE_DEBUG_MODE = 2;
        public static final int ERROR_CODE_RUN_ON_EMULATOR = 3;
        public static final int ERROR_CODE_PACKAGE_NAME_IS_EMPTY = 4;
        public static final int ERROR_CODE_PACKAGE_NAME_NOT_VALID = 5;
        public static final int ERROR_CODE_STORE_IS_EMPTY = 6;
        public static final int ERROR_CODE_STORE_NOT_VALID = 7;
        public static final int ERROR_CODE_SIGNATURE_IS_EMPTY = 8;
        public static final int ERROR_CODE_SIGNATURE_MULTIPLE = 9;
        public static final int ERROR_CODE_SIGNATURE_NOT_VALID = 10;
        public static final int ERROR_CODE_SIGNATURE_UNKNOWN_EXCEPTION = 11;
        public static final int ERROR_CODE_CRC_NOT_VALID = 12;
        public static final int ERROR_CODE_CRC_UNKNOWN_EXCEPTION = 13;
        private final int code;

        public ValidationException(int code, String message) {
            super(message);
            this.code = code;
        }

        public ValidationException(int code, String message, Throwable cause) {
            super(message, cause);
            this.code = code;
        }

        /**
         * Get code of fail reason
         *
         * @return code of fail reason - one of:
         * <br>{@link #ERROR_CODE_UNKNOWN_EXCEPTION},
         * <br>{@link #ERROR_CODE_DEBUG_MODE},
         * <br>{@link #ERROR_CODE_RUN_ON_EMULATOR},
         * <br>{@link #ERROR_CODE_PACKAGE_NAME_IS_EMPTY},
         * <br>{@link #ERROR_CODE_PACKAGE_NAME_NOT_VALID},
         * <br>{@link #ERROR_CODE_STORE_IS_EMPTY},
         * <br>{@link #ERROR_CODE_STORE_NOT_VALID},
         * <br>{@link #ERROR_CODE_SIGNATURE_IS_EMPTY},
         * <br>{@link #ERROR_CODE_SIGNATURE_MULTIPLE},
         * <br>{@link #ERROR_CODE_SIGNATURE_NOT_VALID}
         */
        public int getErrorCode() {
            return code;
        }
    }
}
