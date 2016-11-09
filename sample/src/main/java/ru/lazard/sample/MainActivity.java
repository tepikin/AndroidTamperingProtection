package ru.lazard.sample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import ru.lazard.tamperingprotection.TamperingProtection;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private TextView textView;
    private View simpleValidationButton;
    private View detailedValidationButton;
    private View maxProtectionButton;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textView = (TextView) findViewById(R.id.textView);
        simpleValidationButton = findViewById(R.id.simpleValidation);
        detailedValidationButton = findViewById(R.id.detailedValidation);
        maxProtectionButton = findViewById(R.id.maxProtection);

        simpleValidationButton.setOnClickListener(this);
        detailedValidationButton.setOnClickListener(this);
        maxProtectionButton.setOnClickListener(this);

        detailedValidation();
    }

    private void showText(String message) {
        textView.setText(message);
    }


    @Override
    public void onClick(View view) {
        if (simpleValidationButton == view) {
            simpleValidation();
        }
        if (detailedValidationButton == view) {
            detailedValidation();
        }
        if (maxProtectionButton == view){
            maxProtectionExample();
        }
    }

    private void maxProtectionExample() {
        long dexCrc = Long.parseLong(this.getResources().getString(R.string.dexCrc)); // Keep dexCrc in resources (strings.xml) or in JNI code. Not hardcode in java classes.

        TamperingProtection protection = new TamperingProtection(this);
        protection.setAcceptedDexCrcs(dexCrc);
        protection.setAcceptedStores(TamperingProtection.GOOGLE_PLAY_STORE_PACKAGE);
        protection.setAcceptedPackageNames("ru.lazard.sample","ru.lazard.sample.Lite_Version","ru.lazard.sample.Pro_Version");
        protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32","AC:aC:aB:a3:aC:88:A9:66:aB:0D:C9:a8:aB:A6:aF:a2");
        protection.setAcceptStartOnEmulator(false);
        protection.setAcceptStartInDebugMode(false);

        try {
            protection.validateAllOrThrowException();
            showText("Valid");
        } catch (TamperingProtection.ValidationException e) {
            e.printStackTrace();
            showText("FAILED   "+ e.getMessage());
        }
    }

    private void detailedValidation() {
        TamperingProtection protection = new TamperingProtection(this);
        protection.setAcceptedDexCrcs(); // don't validate classes.dex CRC code.
        protection.setAcceptedStores(); // allow all stores
        protection.setAcceptedPackageNames("ru.lazard.sample");
        protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32");
        protection.setAcceptStartOnEmulator(true);
        protection.setAcceptStartInDebugMode(true);

        try {
            protection.validateAllOrThrowException();
            showText("Valid");
        } catch (TamperingProtection.ValidationException e) {
            e.printStackTrace();
            showText("FAILED   "+e.getMessage());
        }
    }

    private void simpleValidation() {
        TamperingProtection protection = new TamperingProtection(this);
        protection.setAcceptedDexCrcs(); // don't validate classes.dex CRC code.
        protection.setAcceptedStores(); // allow all stores
        protection.setAcceptedPackageNames("ru.lazard.sample");
        protection.setAcceptedSignatures("CC:0C:FB:83:8C:88:A9:66:BB:0D:C9:C8:EB:A6:4F:32");
        protection.setAcceptStartOnEmulator(true);
        protection.setAcceptStartInDebugMode(true);
        boolean isValid = protection.validateAll();

        showText(isValid ? "Valid" : "Tampered");
    }
}
