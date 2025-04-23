<p align="center">
    <img src="https://github.com/HackLike-co/Cloak/blob/main/images/cloak_logo.png?raw=true">
</p>

# Cloak
Generate Secure, Polymorphic, Evasive Payloads

## Quick Start
The easiest way to run Cloak is with Docker. If you wish to install it locally, check the [wiki](https://github.com/HackLike-co/Cloak/wiki/Installation) for installation instructions
```
git clone https://github.com/HackLike-co/Cloak.git
cd Cloak
sudo docker build . --tag cloak
sudo docker run --publish 8080:8080 cloak
```
You can then navigate to http://127.0.0.1:8080/cloak to start generating payloads!

<p align="center">
    <img src="https://github.com/HackLike-co/Cloak/blob/main/images/cloak_ui.png?raw=true">
</p>

## Features
- [X] Convienent Web UI
- [X] View Generated Payloads
- [X] Simple to use REST API (Documentation Coming Soon...)

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
    - [ ] Remote Thread*
    - [X] Local Thread Hijack (CreateThread)
    - [X] Local Thread Hijack (EnumThread)
    - [ ] Remote Thread Hijack*
    - [X] APC
    - [ ] EarlyBird APC*
    - [ ] EarlyCascade

### Evasion
- [ ] Direct Syscalls*
- [ ] Indirect Syscalls*
- [ ] Callstack Spoofing
- [ ] Chunking
- [X] Payload Encryption/Encoding
    - [X] AES
    - [X] RC4
    - [X] Base64
    - [X] Base32
- [ ] AMSI Patching* (HWBP)
- [ ] ETW Patching* (HWBP)
- [ ] DLL Unhooking*
- [ ] IAT Camouflage*
- [X] API Hashing (Compile Time)
- [ ] String Hashing*
- [ ] Anti-Debug*
    - [X] Debugger Detection (Kinda)
    - [ ] Self-Delete
- [ ] Anti-VM
    - [X] VM Detection
        - [X] TPM Check
        - [X] CPU Count
        - [ ] RAM
        - [X] Resolution
    - [X] Execution Delay
        - [ ] API Hammering
        - [X] WaitForSingleObject
- [ ] File Bloating*
- [ ] Entropy Reduction*
- [X] Custom Binary Metadata
- [X] Custom Binary Icon
- [ ] Modify Creation Date/Time

### Guardrails
- [X] Hostname
- [X] Domain Joined*
- [ ] Domain Name*
- [ ] Subnet*

> *v1.0 Goals

## Community
[Discord](https://discord.gg/qNzsmPC3Kr)

## Known Issues
- SetThreadpoolWait doesn't play nicely for API Hashing, need to figure out why
- Checking the amount of memory acts funky in if statement

## References
This project was inspired by the amazing EvadeX from [PhantomSec](https://phantomsec.tools) and OST from [Outflank](https://www.outflank.nl/products/outflank-security-tooling/). If you and your team has the funds, I highly recommend them.

- [tiny-AES-c](https://github.com/kokke/tiny-AES-c)
- [VX-API](https://github.com/vxunderground/VX-API)
- [Rad98 Hooking Engine](https://github.com/vxunderground/VX-API#rad98-hooking-engine)

If you want to learn more, I recommend [ired.team](https://ired.team), [Maldev Academy](https://maldevacademy.com) or [White Knight Labs](https://whiteknightlabs.com)