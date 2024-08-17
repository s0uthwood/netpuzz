# NetPuzz: Testing Network Printers vis Fully Black-Box and Coverage-Guided Protocol Fuzzing

## Experimental Environment

- Operating system: Ubuntu 20.04
- Physical memory: 32GB
- Computer: x86-64 dwsktop with AMD 8-Core Processor

## Usage

The fuzzing log will saved in `fuzz_data` folder. Thus, create a new folder before running the fuzzer.

```shell
cd bin && mkdir fuzz_data
```

Run the binary with following commands:

```shell
./netpuzz -p lpd -f lpd_template.xml -x lpd_reference.xml -t <printer_ip>
./netpuzz -p ipp -f ipp_template.xml -x ipp_reference.xml -t <printer_ip>
```

## Found vulnerabilities

| ID | Network Printer | Description | CVE/CNVD | Impact |
| :-- | :------------- | :---------- | :------- | :----- |
| Vul-1 | HP M202DW | Auto-reboot caused by crafted IPP packets | CNVD-2024-07425 | High |

