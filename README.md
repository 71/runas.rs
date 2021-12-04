`runas.rs`
==========

A Windows executable that can run apps with different credentials.

My Windows computer has different users for different purposes in order to
isolate their environments. In order to easily start apps with one of them, I
made this binary which can start apps with the credentials of any given user.

Note that while it may work for me, it may not work for you. I don't make any
guarantees in terms of compatibility or functionality.

Typically, I create a binary for each user:

```bash
$ cargo run --release -- --save-to=foo.exe --username=foo --password=foo
$ cargo run --release -- --save-to=bar.exe --username=bar --password=bar
```

Then I can use any of these binaries to start an app as another user:

```bash
# start "cmd.exe" as user "foo":
$ foo.exe cmd.exe

# open "https://github.com" as user "bar":
$ bar.exe "C:\Path\To\chrome.exe" "https://github.com"
```

Some shortcuts can be made even faster:

```bash
$ foo.exe --save-to=code.exe "C:\Path\To\Code.exe"
$ code.exe "C:\Path\To\Workspace"
```

## Disclaimers
- It works for me, but it may not work for you.
- Credentials are stored in plain-text both in the generated executable and in
  memory.
- It does not work for command-line applications.
