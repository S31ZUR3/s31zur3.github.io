web
## Challenge Overview
We are given a web application written in Pony, running on a Docker container. The goal is to read the `private/flag.html` file.
## Analysis
The source code (`app/main.pony`) reveals the following routing configuration:

```pony
    let server =
      Jennet(tcplauth, env.out)
        .> serve_file(fileauth, "/", "public/index.html")
        .> serve_file(fileauth, "/pony", "public/pony.html")
        .> post("/pony/find", PonyFind(fileauth))
        .> get("/flag", F(fileauth)) // Target handler
        .> get("/:name", H(fileauth))
```

The handler `F` is responsible for serving the flag. Let's examine its `apply` method:

```pony
  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
                                                                                                try                                                                                           conn = ctx.request.header("Host") as String
    end
                                                                                                let path: String = ctx.request.uri().string()
    // Vulnerable Check
    if (conn == "127.0.0.1") and not_starts_with(path, "flag") and not_starts_with(path, "/flag") then                                                                                        let fpath = FilePath(_fileauth, "private/flag.html")
      with file = File(fpath) do
        body = file.read_string(file.size()).string().array()                                     end
    end
    // ...                                                                                  ```

The conditions to get the flag are:                                                         1. The `Host` header must be `127.0.0.1`.
2. The request URI (as returned by `ctx.request.uri().string()`) must **not** start with `flag`.                                                                                        3. The request URI must **not** start with `/flag`.

The vulnerability lies in how `ctx.request.uri().string()` behaves compared to how the router routes the request.
If we send a request with an **absolute URI** (e.g., `GET http://target/flag HTTP/1.1`), standard HTTP servers (and `Jennet`/`pony-http`) route this based on the path component (`/flag`). However, `ctx.request.uri().string()` returns the *entire* URI string provided in the request line.

So, if we send `GET http://target/flag`, the variable `path` becomes `"http://target/flag"`.
- Does it start with `"flag"`? No.
- Does it start with `"/flag"`? No.

The check passes, and the router still invokes the `/flag` handler.

## Exploitation
We can use `curl` with the `--request-target` option to force sending the absolute URI in the request line, while manually setting the `Host` header to satisfy the first condition.

Command:                                                                                    ```bash                                                                                     curl -v -H "Host: 127.0.0.1" --request-target "http://public.ctf.r0devnull.team:3003/flag" "http://public.ctf.r0devnull.team:3003/flag"
```

## Flag                                                                                     `nullctf{n0w_w!th_99%_l3ss_un1nt3nd3d_s0lv3s_m4yb3!!!@}`