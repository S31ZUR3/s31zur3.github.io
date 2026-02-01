#android 
 ## Overview 
 This document outlines the methods used to analyze the Android application artifacts and recover the 6-digit passcode required to decrypt the private gallery database. 
 ## 1. Initial Reconnaissance - 
 **File System Exploration**: We started by listing the files in the `extracted_apk` directory. - 
 
 **Key Artifacts Identified**: 
 -  `extracted_apk/assets/index.android.bundle`: The compiled JavaScript bundle for the React Native application. 
 -  `extracted_apk/res/Bk.db`: An SQLite database containing encrypted image data. 
 ## 2. Static Analysis (`index.android.bundle`) 
  performed extensive static analysis on the JavaScript bundle to understand the encryption logic and find secrets. 
 - **Tools Used**: `strings`, `grep`, `dd`. 
 - **Encryption Algorithm**: Searching for "Blowfish", "AES", and "CryptoJS" revealed that the app likely uses **Blowfish** in **CBC mode**. 
 -  *Keywords found*: "BlowFish", "BlowFish_Decrypting image", "CryptoJS". 
 - **Potential Passcodes**: We searched for 6-digit numeric strings (`[0-9]{6}`). 
 - *Candidates*: `333333`, `369963`, `476864`. - `369963` was a strong candidate due to its distinct pattern and location in the file. 
 -  **Secrets/Flags**: - Found the string `wh0_s3aid_r3act_n4t1v3`, which appears to be a flag component or a salt used in key derivation. 
  ## 3. Database Analysis (`Bk.db`) 
 - We analyzed the SQLite database to locate the target data. - 
 
 **Tools Used**: `sqlite3`. - **Schema**: Found a table named `images`. 
 
 I then used 369963 to unlock the app. found the second half in the last image
 
 `esch{wh0_said_r3act_n4t1v3_1s_s3cure?_k3y_w4s_369963}`