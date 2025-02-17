# Keystroke Logger
*Use this for educational purposes only.*

This Linux kernel module implements a combination of functionalities that include **keystroke logging**, **file hiding**, and **module hiding**.

It was tested on kernel version 6.8.0 and worked successfully.

## Overview
This kernel module intended to run on Linux systems (x86_64 is specifically supported). It registers as a miscellaneous device under the name kl and provides an IOCTL interface for controlling its functions from user space.

The primary functionalities include:
* **Keystroke Logging**: Capturing key presses via the Linux keyboard notifier.
* **File Hiding**: Intercepting file system operations (e.g. directory listing).
* **Module Hiding**: Removing the module from the kernel’s module list and sysfs entries to evade detection.
* Process Hiding (TODO)

## Building and Installation
#### build module
```
make
```

#### insert module
```
make load
```

#### remove module
```
make unload
```

## Usage
This module operates by a controller and a keylogging client.

#### Hide/Unhide module
```
./kl-controller hide mod
./kl-controller unhide mod
```
When the module is first inserted, it is automatically hidden.

#### Hide/Unhide file
```
./kl-controller hide file <file path>
./kl-controller unhide file <file path>
```

#### On/Off keystroke logging
```
./kl-controller keylog on
./kl-controller keylog off
```
When the `keylog on` command is entered, the keylogging client is automatically launched, and the input is saved to the `log.txt` file.   
When the `keylog off` command is entered, the client process is automatically terminated.

## Acknowledgements
The key mappinng and keylogging idea was inspired by the [jarun/spy](https://github.com/jarun/spy) project.
