#!/bin/bash

#sh mounting_ssd.sh
make clean
make

echo "Small File I/O Evaluation" > eval_IPFS_small.txt
#for thread in 4 8 16
for thread in 1 2 4 8 16
do
	#for each thread, initialize SSD
	rm -r ~/SSD/*

	#start evaluation
	echo "$thread threads 4KB I/O evaluation" >> eval_IPFS_small.txt
	#arguemnts: numofthreads, read(0)write(1), mode(seq(0),rand(1),small(3)), workload(IPFS(0), DISKSHIELD(1),IPFS_INIT(2))
	./app $thread 1 3 2	| grep seconds >> eval_IPFS_small.txt	#Initial Write
	./app $thread 1 3 0 | grep seconds >> eval_IPFS_small.txt	#Overwrite
	./app $thread 0 3 0 | grep seconds >> eval_IPFS_small.txt 	#Read
done

mv eval_IPFS_small.txt $1

