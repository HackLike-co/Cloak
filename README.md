<p align="center">
    <img src="https://github.com/HackLike-co/Cloak/blob/main/images/cloak_logo.png?raw=true">
</p>

# Cloak
Generate "Secure" (ha) Stagers through a convienent Web UI. Will this evade EDRs? no. I'm not trying to burn my TTPs lmao.

## Quick Start
```
git clone https://github.com/HackLike-co/Cloak.git
cd Cloak
go build .
./cloak.exe
```

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
- [ ] DLL

### Evasion
- [ ] AMSI Patching
- [ ] ETW Patching
- [ ] API Hashing
- [X] Payload Encryption/Encoding
- [ ] Anti-Debug
- [ ] Anti-VM
- [ ] DLL Unhooking
- [ ] Modify Creation Date/Time

### Guardrails
- [X] Hostname
- [ ] Domain Joined
- [ ] Domain Name
- [ ] Subnet

## To Do
Most of these can be sumarized as I didn't want to add it the the frontend because I despise it.
- [ ] Remote Process Injection (I forgot to add a spot in the ui to specify pid/name and can't be bothered to add it yet)
- [ ] Different Ways to Create Alterable Thread for APC Injection (who doesn't love more options?)
- [ ] Anti-debugging (I hate html so much I don't want to add the options to the frontend yet)
- [ ] Anti-VM (same as above)
- [ ] New Execution Methods (callback functions, functions pointers, stuff for pes and dlls, idk)
- [ ] REGEX and case-insentivity
- [ ] Encrypt the key for encrypted shellcode
- [ ] More Guardrails
- [ ] More Input Formats
- [ ] More Output Formats
- [ ] AMSI / ETW Patching
- [ ] DLL Hooking
- [ ] API Hashing
- [ ] Modify Creation Date

## References
This project was inspired by the amazing EvadeX from [PhantomSec](https://phantomsec.tools) and OST from [Outflank](https://www.outflank.nl/products/outflank-security-tooling/). If you and your team has the funds, I highly recommend them. This is just a shitty knock off because it seemed like a fun project.

- [tiny-AES-c](https://github.com/kokke/tiny-AES-c)
- [Rad98 Hooking Engine From VX-API](https://github.com/vxunderground/VX-API#rad98-hooking-engine)

If you want to learn more, I recommend [ired.team](https://ired.team) and/or [Maldev Academy](https://maldevacademy.com)