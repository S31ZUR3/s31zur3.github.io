android
## Challenge Description

An Android APK with root detection that requires finding a password to access a vault. The challenge hints at using Frida (the name "freeda2" is a play on "Frida").

## Initial Analysis

### 1. APK Installation & Basic Recon

bash

```bash
# Install the APK
adb install app-release.apk

# Check package name
aapt dump badging app-release.apk | grep package
# Output: package:com.heroctf.freeda2
```

### 2. Decompile the APK

bash

```bash
# Decompile with apktool
apktool d app-release.apk -o decompiled/
```

### 3. Static Analysis

Examining the decompiled smali code reveals:

**MainActivity.smali**: The main UI with a password input field and submit button.

**CheckFlag.smali**: Contains the password validation logic:

java

```java
public static checkFlag(String input) {
    // Uses reflection to call Vault.get_flag()
    // Compares input with the result
}
```

**Vault.smali**: Contains an obfuscated `get_flag()` method that:

- Uses encrypted Base64 data: `fH6Da4rCaxDW/lvs32vwcvJcmy9TgPQaLHfJuw==`
- Decryption key: `0x5f9d7bc3`
- Complex decryption involving:
    - Permutation arrays
    - Bit rotation
    - XOR operations
    - Custom PRNG (method X)

**Security.smali**: Root detection using RootBeer library:

java

```java
public static detectRoot(Context context) {
    return new RootBeer(context).isRooted();
}
```

## Solution Approach

### Attempt 1: Manual Decryption (Failed)

Tried to manually implement the decryption algorithm by analyzing methods K(), E(), P(), B(), X(), and I(). The algorithm was too complex with multiple layers of obfuscation.

### Attempt 2: APK Patching (Failed)

Attempted to:

- Add logging code to print the flag on app startup
- Modify the CheckFlag to always return true
- Repackage and sign the APK

Issues encountered:

- Native library extraction failures
- APK signature verification problems

### Attempt 3: Frida on Production Build (Failed)

Initial attempts to use Frida failed because:

- The default emulator was a production build
- `adb root` returned: "adbd cannot run as root in production builds"
- Frida requires root access to hook system processes

### Solution: Frida with Rooted Emulator ✅

## Step-by-Step Solution

### 1. Create a Rootable Android Emulator

bash

```bash
# Set up SDK paths
export ANDROID_HOME=$HOME/Android/Sdk
export ANDROID_SDK_ROOT=$HOME/Android/Sdk

# Download a rootable system image (default, not google_apis_playstore)
sdkmanager --install "system-images;android-34;default;x86_64"

# Create AVD
avdmanager create avd -n rootable_emu \
    -k "system-images;android-34;default;x86_64" \
    -d pixel_5 --force

# Start emulator
export QT_QPA_PLATFORM=xcb
emulator -avd rootable_emu &
```

### 2. Root the Emulator

bash

```bash
# Wait for boot
adb wait-for-device
sleep 30

# Get root access
adb root

# Verify root
adb shell id
# Output: uid=0(root) gid=0(root) ...
```

### 3. Install Frida Server

bash

```bash
# Download frida-server
wget https://github.com/frida/frida/releases/download/17.5.1/frida-server-17.5.1-android-x86_64.xz
unxz frida-server-17.5.1-android-x86_64.xz

# Push to device
adb push frida-server-17.5.1-android-x86_64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start frida-server
adb shell "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
```

### 4. Install the Target App

bash

```bash
adb install app-release.apk
```

### 5. Create Frida Bypass Script

Create `bypass_root.js`:

javascript

```javascript
Java.perform(function() {
    console.log("[*] Bypassing root detection...");
    
    // Bypass Security.detectRoot
    var Security = Java.use("com.heroctf.freeda2.utils.Security");
    Security.detectRoot.implementation = function(context) {
        console.log("[*] Root detection bypassed!");
        return false;  // Always return not rooted
    };
    
    // Bypass RootBeer directly
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            return false;
        };
    } catch(e) {}
    
    // Hook CheckFlag to extract the password
    var CheckFlag = Java.use("com.heroctf.freeda2.utils.CheckFlag");
    CheckFlag.checkFlag.implementation = function(input) {
        console.log("[*] Input password: " + input);
        
        // Call Vault.get_flag() to get the actual password
        var Vault = Java.use("com.heroctf.freeda2.utils.Vault");
        var correctPassword = Vault.get_flag();
        
        console.log("========================================");
        console.log("[+] FLAG: " + correctPassword);
        console.log("========================================");
        
        return this.checkFlag(input);
    };
    
    console.log("[*] All hooks installed!");
});
```

### 6. Run Frida and Get the Flag

bash

````bash
# Spawn the app with Frida hooks
frida -U -f com.heroctf.freeda2 -l bypass_root.js
```

In the app, enter any password (e.g., "test") and click submit.

**Output:**
```
[*] Bypassing root detection...
[*] Root detection bypassed!
[*] All hooks installed!
[*] Input password: test
========================================
[+] FLAG: HERO{D1D_Y0U_U53_0BJ3C71ON?}
========================================
````
## Flag
```
HERO{D1D_Y0U_U53_0BJ3C71ON?}
```


[[HeroCTF 2025]]
