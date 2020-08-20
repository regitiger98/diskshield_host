make
sleep 2
cd ../ 
make sdk_install_pkg
cd linux/installer/bin 
echo "yes" | ./sgx_linux_x64_sdk_2.1.3.44322.bin
sleep 2
#echo "yes" | ../linux/installer/bin/sgx_linux_x64_sdk_2.1.3.44322.bin 
#echo "yes" | ../linux/installer/bin/sgx_linux_x64_sdk_2.1.3.44322.bin
cd ./SampleDSFS_v5.0
make clean
make
#./app
