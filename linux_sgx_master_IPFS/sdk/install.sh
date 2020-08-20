make
sleep 3
cd ../ 
make sdk_install_pkg
cd linux/installer/bin 
echo "yes" | ./sgx_linux_x64_sdk_2.3.100.46354.bin
sleep 3
cd ./SampleIPFS
make clean
make
#./app
