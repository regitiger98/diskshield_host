#!/bin/bash

#sh mounting_ssd.sh
make clean
make

echo "Big File I/O Evaluation" > eval_IPFS_big.txt
#for thread in 1
#for thread in 1 2 4 8 16
for thread in 16 8 4 2 1
do
	#for each thread, initialize SSD
	rm -r ~/SSD/*

	#start evaluation
	echo "$thread threads 64MB I/O evaluation" >> eval_IPFS_big.txt
	#arguemnts: numofthreads, read(0)write(1), mode(seq(0),rand(1),small(3)), workload(IPFS(0), DISKSHIELD(1),IPFS_INIT(2))
	./app $thread 1 0 2	| grep seconds >> eval_IPFS_big.txt	#Initial Write
	./app $thread 0 0 0 | grep seconds >> eval_IPFS_big.txt	#Read
	./app $thread 1 0 0 | grep seconds >> eval_IPFS_big.txt #Overwrite
done

mv eval_IPFS_big.txt eval_IPFS_big$1.txt
#mv eval_IPFS_big.txt  eval_IPFS_SSDShield_big$1.txt 

