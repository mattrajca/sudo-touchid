# sudo-touchid
`sudo-touchid` is a fork of `sudo` with Touch ID support (powered by the `LocalAuthentication` framework). Once compiled, it will allow you to authenticate `sudo` commands with Touch ID in the Terminal on supported Macs (such as the late 2016 MacBook Pros).

Since Darwin sources for macOS 10.12 are not available yet, this project is based on `sudo` sources corresponding to OS X 10.11.6 and obtained from [opensource.apple.com](http://opensource.apple.com).

## Warnings

Please note:

- Replacing your system's `sudo` program may prevent macOS from booting if permissions are not set up correctly.
- This version of `sudo` is based on OS X 10.11.6 sources. I am not sure if enough has changed in macOS 10.12 to cause any malfunctions.
- I am not a security expert. While I am using this as a fun experiment on my personal computer, your security needs may vary.   


