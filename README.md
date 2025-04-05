<p align="center">
    <img src="https://github.com/HackLike-co/Cloak/blob/main/images/cloak_logo.png?raw=true">
</p>

# Cloak
Generate Secure Payloads

## Quick Start
Cloak is designed to be run on Debian based distros
```
sudo apt install -y mingw-w64
```
> mingw is a requirement for building cloak. If you don't have Go installed (and don't want to install it) you can download a compiled release

```
git clone https://github.com/HackLike-co/Cloak.git
cd Cloak
go build .
./cloak
```
> Note: The binary must be run within the "Cloak" directory to properly function

<p align="center">
    <img src="https://github.com/HackLike-co/Cloak/blob/main/images/cloak_ui.png?raw=true">
</p>

## Features
### Input Formats
- [X] Shellcode
- [ ] PE
- [ ] DLL

### Output Formats
- [X] EXE
- [X] DLL

### Execution Options
- [X] Fibers
- [X] CreateThreadPoolWait
- [X] Injection
    - [X] Local Thread
    - [ ] Remote Thread
    - [X] Local Thread Hijack (CreateThread)
    - [X] Local Thread Hijack (EnumThread)
    - [ ] Remote Thread Hijack
    - [X] APC
    - [ ] EarlyBird APC
    - [ ] EarlyCascade

### Evasion
- [X] Payload Encryption/Encoding
- [ ] AMSI Patching
- [ ] ETW Patching
- [ ] DLL Unhooking
- [ ] IAT Camouflage
- [X] API Hashing (Compile Time)
- [ ] Anti-Debug
    - [ ] Debugger Detection
    - [ ] Self-Delete
- [ ] Anti-VM
    - [ ] VM Detection
    - [X] Execution Delay
    - [ ] API Hammering
- [ ] File Bloating
- [ ] Entropy Reduction
- [X] Custom Binary Metadata
- [X] Custom Binary Icon
- [ ] Modify Creation Date/Time

### Guardrails
- [X] Hostname
- [ ] Domain Joined
- [ ] Domain Name
- [ ] Subnet

## Known Issues
- SetThreadpoolWait doesn't play nicely for API Hashing, need to figure out why

## References
This project was inspired by the amazing EvadeX from [PhantomSec](https://phantomsec.tools) and OST from [Outflank](https://www.outflank.nl/products/outflank-security-tooling/). If you and your team has the funds, I highly recommend them. This is just a shitty knock off because it seemed like a fun project.

- [tiny-AES-c](https://github.com/kokke/tiny-AES-c)

If you want to learn more, I recommend [ired.team](https://ired.team) and/or [Maldev Academy](https://maldevacademy.com)