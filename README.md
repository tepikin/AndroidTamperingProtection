# AndroidTamperingProtection

Protect you android app from tampering. 


This Library check is application tampered or not.

TamperingProtection check: <br>
1) application signature - protection from resign you app. <br>
2) installer store - app must be inbstalled only from store (not by hand).<br>
3) package name - sometimes malefactor change package name and sells your application as its.<br>
4) debug mode - production version of app mustn't run in debug mode.

## How to use
Simple usage:<br>
```java
TamperingProtection protection = new TamperingProtection(context);
protection.setAcceptedStores(); // install from any where 
protection.setAcceptedPackageNames("ru.lazard.sample"); // your package name
protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32"); // MD5 fingerprint
protection.setAcceptStartOnEmulator(true);// allow run on emulator 
protection.setAcceptStartInDebugMode(true);// allow run in debug mode 

protection.validate();// <- bool is valid or tampered.
```


Max protection varian:
```java
TamperingProtection protection = new TamperingProtection(context);
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
    compile 'com.github.tepikin:AndroidTamperingProtection:0.1'
}
```

PS or just copy file [TamperingProtection.java](https://github.com/tepikin/AndroidTamperingProtection/blob/master/tamperingprotection/src/main/java/ru/lazard/tamperingprotection/TamperingProtection.java) to you project.
