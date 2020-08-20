This is the DISKSHIELD Host Code for SGX !!!

Preparing for ASIA'CCS

Jinwoo Ahn

****For evaluation

When you evaluate the DISKSHIELD, you should follow this steps at first.

1) Compile the OpenSSD(Jasmine)) with DISKSHIELD(DEVICE) codes.

2) debug the OpenSSD status.

    -$sudo putty
    -selects DISKSHIELD

3) debug the kernel codes (linux-4.10.16v)

    -$sudo tail -f /var/log/syslog 

4) Next steps are depends on your test types. 

    4.1) synthetic workload evaluation

    4.2) kernel & Device evaluation

    4.2.1) compile the application code

        -$make

    4.2.2) Execute the application code and validate DISKSHIELD.

        -$./DS_app_eval


****The codes consists of 6 directories:

0. linux_sgx_driver_master

The SGX driver. 
you have to check if the SGX driver is loaded
$lsmod | grep sgx

if there is no sgx, then install it.
$sh install_driver.sh

1. linux_sgx_master_DSFS

The SGX sdk which implements modifed IPFS.

To install DSFS, 
$sh install_sdk_psw.sh

2. linux_sgx_master_IPFS

The original sdk version which has original IPFS.
This is for baseline evaluation.

To install IPFS, 
$sh install_sdk_psw.sh


3. DSFS_APP

The synthetic workload benchmark for evaluating the performance of DISKSHIELD.

4. DS_kernel

To validate the kernel and device.
You can bypass the SGX library and check the validity of kernel and device.

>Compile the executable

$make

>>Run the executable

$./DS_app_eval $(MODE) $(ITERS)

MODE: 
'C': File Creation
'W': File Write
'R': File Read

ITERS: The number of files


5. AuthEnclave_client

The test code for validate the attestation between client and server.
Infact, the real client code is implemented under the modified IPFS in linux_sgx_master_DSFS

6. AuthEnclave_server

This is the Authentication Enclave which make a secure channel between host and device.


****Debugging the SGX

When you debug the SGX application and Modified IPFS, Execute Ecplise.
File > OpenProject > Directory > ...

Project (right mouse) > Debug Configurations > C/C++ Application: /home/jinu/Desktop/SGX/ASIACCS/DSFS_APP/app

Debug Configurations > Debugger > GDB debugger: /home/jinu/Desktop/SGX/ASIACCS/linux_sgx_master_DSFS/linux/installer/bin/sgxsdk/bin/sgx-gdb

Apply them.


