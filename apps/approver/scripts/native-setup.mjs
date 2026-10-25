// What the generated native projects need and `npx cap sync` does not write.
// Run after `npx cap add ios` / `npx cap add android`; safe to re-run.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");

// iOS refuses Face ID to an app without this string -- and the vault refuses to
// work without Face ID.
const plist = join(app, "ios", "App", "App", "Info.plist");
if (existsSync(plist)) {
  let text = readFileSync(plist, "utf8");
  if (!text.includes("NSFaceIDUsageDescription")) {
    text = text.replace(/<\/dict>\s*<\/plist>\s*$/,
      "\t<key>NSFaceIDUsageDescription</key>\n" +
      "\t<string>Face ID защищает ключ, которым вы подписываете приказы.</string>\n" +
      "</dict>\n</plist>\n");
    writeFileSync(plist, text);
    console.log("ios: NSFaceIDUsageDescription added");
  }
} else {
  console.log("ios: no project yet (npx cap add ios)");
}

// Screenshots and the app switcher thumbnail would show the order being signed.
const activity = join(app, "android", "app", "src", "main", "java", "me", "yamal", "alerting", "MainActivity.java");
if (existsSync(activity)) {
  let text = readFileSync(activity, "utf8");
  if (!text.includes("FLAG_SECURE")) {
    text = text
      .replace("import com.getcapacitor.BridgeActivity;",
        "import android.os.Bundle;\nimport android.view.WindowManager;\nimport com.getcapacitor.BridgeActivity;")
      .replace(/public class MainActivity extends BridgeActivity \{\s*\}/,
        "public class MainActivity extends BridgeActivity {\n" +
        "    @Override\n" +
        "    public void onCreate(Bundle savedInstanceState) {\n" +
        "        super.onCreate(savedInstanceState);\n" +
        "        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);\n" +
        "    }\n" +
        "}");
    writeFileSync(activity, text);
    console.log("android: FLAG_SECURE set in MainActivity");
  }
} else {
  console.log("android: no project yet (npx cap add android)");
}
