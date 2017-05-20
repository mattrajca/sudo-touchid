# sudo-touchid
`sudo-touchid` is a fork of `sudo` with Touch ID support on macOS (powered by the `LocalAuthentication` framework). Once compiled, it will allow you to authenticate `sudo` commands with Touch ID in the Terminal on supported Macs (such as the late 2016 MacBook Pros).

## Why an fork?

I like the idea of `sudo-touchid`, but the author doesn't merge the [existing password Fallback patch](https://github.com/mattrajca/sudo-touchid/pull/15) from [serverwentdown](https://github.com/serverwentdown).
So I merged that patch and did some tests. It works very well on MacOS 10.12. Tested it on 12.12.5 (16F73) and 10.12.6 Beta (16G8c).

There are no further changes at the moment.

## Screenshot

<img src="images/Screenshot.png?raw=true" width=556 height=284 />		

## Warning

- I am not a security expert. While I am using this as a fun experiment on my personal computer, your security needs may vary.
- This has only been tested on the 2016 15" MacBook Pro with Touch Bar running macOS 10.12.1.

## Building

To build `sudo-touchid`, simply open the included Xcode project file with Xcode 8+, select the `Build All` target, and click **Build**.

## Running

If we try running our newly-built `sudo` executable now, we'll get an error:

> sudo must be owned by uid 0 and have the setuid bit set

To fix this, we can use our system's `sudo` command and the `chown/chmod` commands to give our newly-built `sudo` the permissions it needs:

> cd (built-products-directory)

> sudo chown root:wheel sudo && sudo chmod 4755 sudo

Now if we try running our copy of `sudo`, it should work:

> cd (built-products-directory)

> ./sudo -s

If you don't have a Mac with a biometric sensor, `sudo-touchid` will fail. If you'd still like to test whether the `LocalAuthentication` framework is working correctly, you can change the `kAuthPolicy` constant to `LAPolicyDeviceOwnerAuthentication` in `sudo/plugins/sudoers/auth/sudo_auth.m`. This will present a dialog box asking the user for his or her password:		

<img src="images/auto_fallback.png?raw=true" width=556 height=301 />		

While not useful in practice, you can use this to verify that the `LocalAuthentication` code does in fact work.

## Installing using Homebrew

I didn't test this, and I have no idea if the patch is implemented here, or not. But I think not.

`Xcode` is not required (As long as *HOMEBREW_PREFIX* is default).

> brew tap paulche/sudo-touchid

> brew install sudo-touchid

Follow caveat message to change owner/mode.

## Installing from source code

Replacing the system's `sudo` program is quite risky (can prevent your Mac from booting) and requires disabling System Integrity Protection (aka "Rootless").

Instead of replacing `sudo`, we can install our build under `/usr/local/bin` and give the path precedence over `/usr/bin`, this way our build is found first.

> sudo cp (built-products-directory)/sudo /usr/local/bin/sudo

> sudo chown root:wheel /usr/local/bin/sudo && sudo chmod 4755 /usr/local/bin/sudo

You can set up your `PATH` by adding `export PATH=/usr/local/bin:$PATH` to `.bashrc` (thanks @edenzik).

Now you should be able to enter `sudo` in any Terminal (or iTerm) window and authenticate with Touch ID!
