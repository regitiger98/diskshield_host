make clean
wait
#make -j12 
make -j12 DEBUG=1
wait
make sdk_install_pkg
wait
make psw_install_pkg
wait

#install sdk
cd linux/installer/bin
echo yes | ./sgx_linux_x64_sdk_*
wait
echo $(pwd)
source /home/jinu/Desktop/SGX/linux-sgx-master/linux/installer/bin/sgxsdk/environment
#source ./linux/installer/bin/sgxsdk/environment
#source $(pwd)/sgxsdk/environment

#install psw

sh /opt/intel/sgxpsw/uninstall.sh
wait
./sgx_linux_x64_psw*
wait

