# NetPuzz: Testing Network Printers via Fully Black-Box and Sequence-Tree-Based Protocol Fuzzing

## Experimental Environment

- Operating system: Ubuntu 20.04
- Physical memory: 32GB
- Computer: x86-64 desktop with AMD 8-Core Processor

## Usage

The fuzzing log will saved in `fuzz_data` folder. So we need to create a `fuzz_data` folder before running the fuzzer.

```shell
sudo apt update
sudo apt install snmp
pip install git+https://github.com/rytilahti/python-miio.git
cd bin && mkdir fuzz_data
```

Run the binary with following commands:

```shell
./netpuzz -p lpd -f lpd_template.xml -x lpd_reference.xml -t <printer_ip>
./netpuzz -p ipp -f ipp_template.xml -x ipp_reference.xml -t <printer_ip>
```

## Found vulnerabilities

The following table list all the vulnerabilities we found in this work. We also recorded a demo video for each vulnerability. Since some of the vulnerabilities are not yet fixed, we masked the parts of the video that contains PoCs.

| ID | Network Printer | Description | CVE/CNVD | Impact |
| :-- | :------------- | :---------- | :------- | :----- |
| Vul-1 | HP M202DW | Auto-reboot caused by crafted IPP packets | CNVD-2024-07425 | High |
| Vul-2 | HP M202DW | Auto-reboot caused by crafted IPP packets | CNVD-2024-07426 | High | 
| Vul-3 | HP M202DW | Auto-reboot caused by crafted IPP packets | CNVD-2024-25238 | High | 
| Vul-4 | HP M232DWC | Busy wait caused by crafted IPP packets | CVE-2024-9423 | Medium | 
| Vul-5 | HP M232DWC | Crash caused by crafted IPP packets | CNVD-2024-26735 | High | 
| Vul-6 | HP M232DWC | Crash caused by crafted IPP packets | - | - |
| Vul-7 | HP M227FDW | Auto-reboot caused by crafted IPP packets | CNVD-2024-17422 | High | 
| Vul-8 | HP M227FDW | Auto-reboot caused by crafted IPP packets | CNVD-2024-17672 | High | 
| Vul-9 | HP M227FDW | Auto-reboot caused by crafted IPP packets | CVE-2025-1004 | Medium | 
| Vul-10 | HP M227FDW | Auto-reboot caused by crafted IPP packets | CNVD-2024-25518 | High | 
| Vul-11 | HP M227FDW | Auto-reboot caused by crafted IPP packets | CNVD-2024-25683 | High | 
| Vul-12 | Lenovo M101DW | Crash caused by crafted LPD packets | CVE-2024-27912 | High | 
| Vul-13 | Lenovo M101DW | Crash caused by crafted LPD packets | CVE-2024-4782 | Medium |
| Vul-14 | Lenovo M101DW | Crash caused by crafted IPP packets | CVE-2024-5209 | Medium |
| Vul-15 | Lenovo M101DW | Hang caused by crafted LPD packets | CVE-2024-6004 | Medium |
| Vul-16 | Lenovo LJ2320DN | Crash caused by crafted LPD packets | CNVD-2024-23047 | High | 
| Vul-17 | Lenovo LJ2320DN | Hang caused by crafted LPD packets | CVE-2024-4781 | Medium |
| Vul-18 | Lenovo LJ2320DN | Hang caused by crafted LPD packets | CVE-2024-5210 | Medium |
| Vul-19 | Xerox CP228W | Hang caused by crafted LPD packets | CNVD-2024-45320 | High | 
| Vul-20 | Xerox CP228W | Busy wait caused by crafted IPP packets | CNVD-2024-18101 | High | 
| Vul-21 | Xerox CP228W | Crash caused by crafted IPP packets | CNVD-2024-24315 | High | 
| Vul-22 | Xerox CP228W | Crash caused by crafted LPD packets | CNVD-2024-34726 | High | 
| Vul-23 | Pantum M6760DW | Crash caused by crafted IPP packets | CNVD-2024-07423 | High | 
| Vul-24 | Pantum M6760DW | Hang caused by crafted LPD packets | CNVD-2024-21971 | High | 
| Vul-25 | Pantum M6760DW | Cartridge unusable caused by crafted IPP packets | - | - |
