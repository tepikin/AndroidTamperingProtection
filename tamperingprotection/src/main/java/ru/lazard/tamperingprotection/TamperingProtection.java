package ru.lazard.tamperingprotection;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.NonNull;


import com.layapp.collages.BuildConfig;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Class for check is application tampered or not.<br> TamperingProtection check: <br>
 * 1) CRC code of classes.dex - protection from code modification.<br>
 * 2) application signature - protection from resign you app. <br>
 * 3) installer store - app must be inbstalled only from store (not by hand).<br>
 * 4) package name - sometimes malefactor change package name and sells your application as its.<br>
 * 5) debug mode - production version of app mustn't run in debug mode.<br>
 * 6) run on emulator - user musn't run app on emulator.<br>
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
     * Get CRC code of resources.arsc file.<br><b>Note:</b> CRC code of .arsc modified each time when you modify resources.
     *
     * @param context
     * @return - CRC code of resources.arsc file in apk.
     * @throws IOException
     */
    @NonNull
    public static long getResCRC(@NonNull Context context) throws IOException {
        ZipFile zf = new ZipFile(context.getPackageCodePath());
        long crc = 0;
        ZipEntry ze2 = zf.getEntry("resources.arsc");
        if (ze2 != null) {
            crc+=ze2.getCrc();
        }
        Log.e("Crc", "RES's summ = " + ze2.getCrc());
        return crc;
    }


    public static long getTotalCRC(@NonNull Context context) throws IOException {
        ZipFile zf = new ZipFile(context.getPackageCodePath());
        long crc = 0;
        Enumeration<? extends ZipEntry> entries = zf.entries();
        while(entries.hasMoreElements()){
            ZipEntry zipEntry = entries.nextElement();
            crc+=zipEntry.getCrc();
        }
        Log.e("Crc", "Total summ = " +crc);
        return crc;
    }


    /**
     * Get CRC code of classes.dex file.<br><b>Note:</b> CRC code of .dex modified each time when you modify java code.
     *
     * @param context
     * @return - CRC code of classes.dex file in apk.
     * @throws IOException
     */
    @NonNull
    public static long getDexCRC(@NonNull Context context) throws IOException {
        ZipFile zf = new ZipFile(context.getPackageCodePath());
        long crc = 0;
        for (int i = 1; i < 1000; i++) {
            String index = ""+i;
            if (i==1){
                index="";
            }
            String name = "classes" + index + ".dex";
            ZipEntry ze = zf.getEntry(name);
            if (ze !=null){
                crc+=ze.getCrc();
            }else{
                Log.e("Crc","DEX's summ = "+crc);
                return crc;
            }
        }
        Log.e("Crc","DEX's summ = "+crc);
        return crc;
    }


    /**
     * Get Md5 fingerprint of you app. Method return fingerprint of current signature.<br>
     * If app signed by debug keystore then method return debug fingerprint
     * (if signed by release keystore then return release fingerprint).<br><br>
     * For get MD5 fingerprint from command line:<br><code>
     * keytool -list -v -keystore &lt;YOU_PATH_TO_KEYSTORE&gt; -alias &lt;YOU_ALIAS&gt; -storepass &lt;YOU_STOREPASS&gt; -keypass &lt;YOU_KEYPASS&gt;
     * </code><br>
     * For get MD5 fingerprint for debug keystore:<br><code>
     * keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
     * </code><br>
     * Use only <b>MD5</b> fingerprint. They looks like: <code>"CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"</code>.
     *
     * @param context
     */
    @NonNull
    public static String[] getSignatures(@NonNull Context context) throws PackageManager.NameNotFoundException, NoSuchAlgorithmException {
        // Avoid expliot or fake signature on Android 8.0 or higher
        Signature[] signatures;
        if (Build.VERSION.SDK_INT >= 26) {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            signatures = packageInfo.signingInfo.getApkContentsSigners();
        } else {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            signatures = packageInfo.signatures;
        }
        
        if (signatures == null || signatures.length <= 0) {
            return new String[]{};
        }

        String[] md5Signatures = new String[signatures.length];

        for (int i = 0; i < signatures.length; i++) {
            Signature signature = signatures[i];
            if (signature == null) continue;

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

            md5Signatures[i] = md5String;
        }


        return md5Signatures;
    }

    /**
     * Check is current device is emulator.
     *
     * @return
     */
    public static boolean isEmulator() {
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
        return rating > 4;
    }

    /**
     * Check is running in debug mode.
     *
     * @param context
     * @return
     */
    public static boolean isDebug(Context context) {
        boolean isDebuggable = (0 != (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
        return isDebuggable;
    }

    /**
     * Get package name of app Installer. Known installers (public Stores) is Google play, Amazon and Samsung store.<br>
     * Their package names are: <br>{@link #GOOGLE_PLAY_STORE_PACKAGE},<br>{@link #AMAZON_APP_STORE_PACKAGE},<br>{@link #SAMSUNG_APP_STORE_PACKAGE}.
     *
     * @param context - package name of app Installer. If return null then app was installed by user (not by store).
     * @return
     */
    public static String getCurrentStore(Context context) {
        return context.getPackageManager().getInstallerPackageName(context.getPackageName());
    }

    /**
     * Get current app package name.
     *
     * @param context
     * @return - current package name
     */
    public static String getPackageName(Context context) {
        return context.getApplicationContext().getPackageName();
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
     * Check Crc (checksum) of classes.dex file in apk. It's protection from code modification. <br><b>Note:</b> don't keep CRC codes hardcoded in java classes! Keep it in resources (strings.xml), or in JNI code, or WebServer.
     *
     * @param crcs - by default empty (no crc check).
     */
    public void setAcceptedDexCrcs(long... crcs) {
        this.dexCrcs = crcs;
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

        // check by ApplicationInfo
        if (isDebug(context))
            throw new ValidationException(ValidationException.ERROR_CODE_DEBUG_MODE, "Run in debug mode checked by ApplicationInfo. Flags=" + context.getApplicationInfo().flags);

        // check by BuildConfig
        if (BuildConfig.DEBUG)
            throw new ValidationException(ValidationException.ERROR_CODE_DEBUG_MODE, "Run in debug mode checked by BuildConfig.");
    }

    private void validateEmulator() throws ValidationException {
        if (isEmulatorAvailable) return; // validation success (no validation need)
        boolean isEmulator = isEmulator();


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
        String packageName = getPackageName(context);
        if (TextUtils.isEmpty(packageName))
            throw new ValidationException(ValidationException.ERROR_CODE_PACKAGE_NAME_IS_EMPTY, "Current package name is empty: packageName=\"" + packageName + "\";");
        for (String allowedPackageName : packageNames) {
            if (packageName.equalsIgnoreCase(allowedPackageName)) return;// validation success
        }
        throw new ValidationException(ValidationException.ERROR_CODE_PACKAGE_NAME_NOT_VALID, "Not valid package name:  CurrentPackageName=\"" + packageName + "\";  validPackageNames=" + packageNames.toString() + ";");
    }

    private void validateStore() throws ValidationException {
        if (stores == null || stores.size() <= 0) return;// validation success (no validation need)
        final String installer = getCurrentStore(context);
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
            long crc = getDexCRC(context);
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
            String[] md5Signatures = getSignatures(context);

            if (md5Signatures == null || md5Signatures.length <= 0) {
                throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_IS_EMPTY, "No signatures found.");
            }

            // Check all signatures
            boolean allowed = false;
            for (String md5Signature : md5Signatures) {
                for (String allowedSignature : signatures) {
                    if (md5Signature.equalsIgnoreCase(allowedSignature)) {
                        allowed = true;
                        break;
                    }
                    allowed = false;
                }
            }
            if (!allowed)
                throw new ValidationException(ValidationException.ERROR_CODE_SIGNATURE_NOT_VALID, "Not valid signature: CurrentSignatures=" + md5Signatures + ";  validSignatures=" + signatures.toString() + ";");
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
