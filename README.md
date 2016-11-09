# AndroidTamperingProtection

Protect you android app from tampering.<br>
<br>
This Library check is application tampered or not.<br>
<br>
TamperingProtection check: <br>
1) CRC code of classes.dex - protection from code modification.<br>
2) application signature - protection from resign you app. <br>
3) installer store - app must be inbstalled only from store (not by hand).<br>
4) package name - sometimes malefactor change package name and sells your application as its.<br>
5) debug mode - production version of app mustn't run in debug mode.<br>
6) run on emulator - user musn't run app on emulator.<br>
<br>
You can choose not all of this protection types. Most usefull is <i>"application signature"</i> and <i>"package name"</i>.<br>
<br>
<b>How get Signature code:</b><br>
Use method <code>TamperingProtection.getSignatures(context)</code>. This method return fingerprint of current signature.<br>
If app signed by debug keystore then method return debug fingerprint 
(if signed by release keystore then return release fingerprint).<br>
Also you can get signature by command line on PC. For get MD5 fingerprint from command line use:<br><code>
keytool -list -v -keystore &lt;YOU_PATH_TO_KEYSTORE&gt; -alias &lt;YOU_ALIAS&gt; -storepass &lt;YOU_STOREPASS&gt; -keypass &lt;YOU_KEYPASS&gt;
</code><br>
For get MD5 fingerprint for debug keystore:<br><code>
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
</code><br>
Use only <b>MD5</b> fingerprint. They looks like: <code>"CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"</code>.
<br><br>
<b>How get CRC code:</b><br> 
Use method `TamperingProtection.getDexCRC(context)` for get CRC code of classes.dex.<br> 
<b>Note:</b> don't keep CRC codes hardcoded in java classes! Keep it in resources (strings.xml), or in JNI code, or WebServer.<br>
CRC code of .dex modified each time when you modify java code.

## How to use
Simple usage:<br>
```java
TamperingProtection protection = new TamperingProtection(context);
protection.setAcceptedPackageNames("ru.lazard.sample"); // your package name
protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"); // MD5 fingerprint

protection.validateAll();// <- bool is valid or tampered.
```


Max protection varian:
```java
// Keep dexCrc in resources (strings.xml) or in JNI code. Don't hardcode it in java classes, because it's changes checksum.
long dexCrc = Long.parseLong(this.getResources().getString(R.string.dexCrc)); 

TamperingProtection protection = new TamperingProtection(context);
protection.setAcceptedDexCrcs(dexCrc);
protection.setAcceptedStores(TamperingProtection.GOOGLE_PLAY_STORE_PACKAGE); // apps installed only from google play
protection.setAcceptedPackageNames("ru.lazard.sample.Lite_Version","ru.lazard.sample.Pro_Version"); // lite and pro package names
protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"); // only release md5 fingerprint
protection.setAcceptStartOnEmulator(false); // not allowed for emulators
protection.setAcceptStartInDebugMode(false); // not allowed run in debug mode

protection.validateAllOrThrowException(); // detailed fail information in Exception.
```

## How to install (Gradle)
To get a Git project into your build:

**Step 1.** Add the JitPack repository to your build file <br \>
Add it in your root build.gradle at the end of repositories:

```gradle
allprojects {
	repositories {
		...
		maven { url "https://jitpack.io" }
	}
}
```
**Step 2.** Add the dependency
```gradle
dependencies {
    compile 'com.github.tepikin:AndroidTamperingProtection:0.11'
}
```
---
**PS** or just copy file [TamperingProtection.java](https://github.com/tepikin/AndroidTamperingProtection/blob/master/tamperingprotection/src/main/java/ru/lazard/tamperingprotection/TamperingProtection.java) to you project.  :)
