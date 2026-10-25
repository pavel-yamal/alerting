package me.yamal.alert.devicevault;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.security.KeyStore;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The decision-maker's signing key, kept behind a strong biometric. docs/adr/0016.
 *
 * <p>The Ed25519 key itself is stored encrypted under an AES-256-GCM key that lives in
 * the Android Keystore (StrongBox where the phone has one) and is usable only:
 * <ul>
 *   <li>after a STRONG biometric (class 3), for exactly one operation -- the cipher is
 *       bound to the prompt through a CryptoObject; the screen-lock PIN is not a way in;</li>
 *   <li>while the set of enrolled biometrics is unchanged -- adding a fingerprint
 *       invalidates the key for good, and the way back is a new enrolment.</li>
 * </ul>
 * The ciphertext and the public facts about each key sit in SharedPreferences: without
 * the Keystore key they are worth nothing, and the facts sign nothing.
 */
@CapacitorPlugin(name = "DeviceVault")
public class DeviceVaultPlugin extends Plugin {

    private static final String PREFS = "alerting.device-vault";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_PREFIX = "alerting.vault.";
    private static final String META = "meta:";
    private static final String DATA = "data:";
    private static final int B64 = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

    private interface WithCipher {
        void run(Cipher cipher) throws Exception;
    }

    // ---- status ----------------------------------------------------------------------

    @PluginMethod
    public void status(PluginCall call) {
        int result = BiometricManager.from(getContext()).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        JSObject out = new JSObject();
        out.put("available", result == BiometricManager.BIOMETRIC_SUCCESS);
        // Android does not say which biometric a class-3 check will use.
        out.put("biometry", result == BiometricManager.BIOMETRIC_SUCCESS ? "biometric" : "none");
        if (result == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
            out.put("reason", "not_enrolled");
        } else if (result != BiometricManager.BIOMETRIC_SUCCESS) {
            out.put("reason", "unavailable");
        }
        call.resolve(out);
    }

    // ---- list ------------------------------------------------------------------------

    @PluginMethod
    public void list(PluginCall call) {
        Map<String, String> metas = new TreeMap<>();
        for (Map.Entry<String, ?> entry : prefs().getAll().entrySet()) {
            if (entry.getKey().startsWith(META) && entry.getValue() instanceof String) {
                metas.put(entry.getKey().substring(META.length()), (String) entry.getValue());
            }
        }
        JSArray items = new JSArray();
        for (Map.Entry<String, String> entry : metas.entrySet()) {
            JSObject item = new JSObject();
            item.put("alias", entry.getKey());
            item.put("meta", entry.getValue());
            items.put(item);
        }
        JSObject out = new JSObject();
        out.put("items", items);
        call.resolve(out);
    }

    // ---- store -----------------------------------------------------------------------

    @PluginMethod
    public void store(PluginCall call) {
        String alias = call.getString("alias");
        String secretText = call.getString("secret");
        if (alias == null || alias.isEmpty() || secretText == null) {
            call.reject("alias и secret обязательны", "failed");
            return;
        }
        String meta = call.getString("meta", "{}");
        byte[] secret;
        try {
            secret = Base64.decode(secretText, B64);
        } catch (IllegalArgumentException e) {
            call.reject("secret — не base64url", "failed");
            return;
        }
        int available = BiometricManager.from(getContext()).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (available != BiometricManager.BIOMETRIC_SUCCESS) {
            call.reject("биометрия недоступна",
                available == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ? "not_enrolled" : "unavailable");
            return;
        }
        Cipher cipher;
        try {
            SecretKey key = createKey(KEY_PREFIX + alias);
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception e) {
            call.reject("ключ хранилища не создан: " + e.getMessage(), "unavailable");
            return;
        }
        String reason = call.getString("reason", "Защитить ключ подписи биометрией");
        prompt(call, reason, cipher, (unlocked) -> {
            byte[] sealed = unlocked.doFinal(secret);
            String record = Base64.encodeToString(unlocked.getIV(), B64) + "." + Base64.encodeToString(sealed, B64);
            prefs().edit().putString(DATA + alias, record).putString(META + alias, meta).apply();
            call.resolve();
        });
    }

    // ---- load ------------------------------------------------------------------------

    @PluginMethod
    public void load(PluginCall call) {
        String alias = call.getString("alias");
        if (alias == null || alias.isEmpty()) {
            call.reject("alias обязателен", "failed");
            return;
        }
        String record = prefs().getString(DATA + alias, null);
        if (record == null || !record.contains(".")) {
            call.reject("ключа нет", "not_found");
            return;
        }
        String[] parts = record.split("\\.", 2);
        Cipher cipher;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_PREFIX + alias, null);
            if (key == null) {
                call.reject("ключ хранилища исчез", "invalidated");
                return;
            }
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Base64.decode(parts[0], B64)));
        } catch (KeyPermanentlyInvalidatedException e) {
            // The set of fingerprints or faces changed: this key is gone for good.
            call.reject("набор биометрии изменился", "invalidated");
            return;
        } catch (Exception e) {
            call.reject("ключ не открыт: " + e.getMessage(), "unavailable");
            return;
        }
        byte[] sealed = Base64.decode(parts[1], B64);
        String reason = call.getString("reason", "Подтвердите, что это вы");
        prompt(call, reason, cipher, (unlocked) -> {
            JSObject out = new JSObject();
            out.put("secret", Base64.encodeToString(unlocked.doFinal(sealed), B64));
            call.resolve(out);
        });
    }

    // ---- remove ----------------------------------------------------------------------

    @PluginMethod
    public void remove(PluginCall call) {
        String alias = call.getString("alias");
        if (alias == null || alias.isEmpty()) {
            call.reject("alias обязателен", "failed");
            return;
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_PREFIX + alias);
        } catch (Exception ignored) {
            // Nothing to delete is fine: the prefs below go either way.
        }
        prefs().edit().remove(DATA + alias).remove(META + alias).apply();
        call.resolve();
    }

    // ---- helpers ---------------------------------------------------------------------

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private SecretKey createKey(String name) throws Exception {
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
                name, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Every use needs its own strong biometric; the device PIN does not count.
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            spec.setUserAuthenticationValidityDurationSeconds(-1);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            spec.setIsStrongBoxBacked(true);
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(spec.build());
        return generator.generateKey();
    }

    private void prompt(PluginCall call, String reason, Cipher cipher, WithCipher onUnlocked) {
        FragmentActivity activity = (FragmentActivity) getActivity();
        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Оповещение ЛПР")
            .setSubtitle(reason)
            .setNegativeButtonText("Отмена")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build();
        activity.runOnUiThread(() -> {
            BiometricPrompt prompt = new BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                        if (crypto == null || crypto.getCipher() == null) {
                            call.reject("биометрия не выдала ключ", "failed");
                            return;
                        }
                        try {
                            onUnlocked.run(crypto.getCipher());
                        } catch (Exception e) {
                            call.reject("операция с ключом не удалась: " + e.getMessage(), "failed");
                        }
                    }

                    @Override
                    public void onAuthenticationError(int code, @NonNull CharSequence message) {
                        call.reject(message.toString(), errorCode(code));
                    }
                    // onAuthenticationFailed: one unrecognised attempt; the prompt stays up.
                });
            prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
        });
    }

    /** The codes app.js turns into words (logic.js: VAULT_ERRORS). */
    private static String errorCode(int code) {
        switch (code) {
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
            case BiometricPrompt.ERROR_CANCELED:
                return "cancelled";
            case BiometricPrompt.ERROR_LOCKOUT:
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                return "locked";
            case BiometricPrompt.ERROR_NO_BIOMETRICS:
                return "not_enrolled";
            case BiometricPrompt.ERROR_HW_UNAVAILABLE:
            case BiometricPrompt.ERROR_HW_NOT_PRESENT:
                return "unavailable";
            default:
                return "failed";
        }
    }
}
