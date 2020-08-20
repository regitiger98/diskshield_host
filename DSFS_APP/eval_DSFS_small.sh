#!/bin/bash

make clean
make

echo "Small File I/O Evaluation" > eval_DSFS_small.txt

./app 1 1 3 1	| grep EVAL >> eval_DSFS_small.txt	#Initial Write for 4096 files (0001.txt - 4095.txt)


for thread in 16 8 4 2 1
#for thread in 1 2 4 8 16
do
	#for each thread, initialize SSD
	rm -r ~/SSD/*

	#start evaluation
	echo "$thread threads 4KB I/O evaluation" >> eval_DSFS_small.txt
	#arguemnts: numofthreads, read(0)write(1), mode(seq(0),rand(1),small(3)), workload(IPFS(0), DISKSHIELD(1),IPFS_INIT(2))
	#./app $thread 1 3 1	| grep seconds >> eval_DSFS_small.txt	#Initial Write
	./app $thread 1 3 1 | grep EVAL >> eval_DSFS_small.txt	#Overwrite
	./app $thread 0 3 1 | grep EVAL >> eval_DSFS_small.txt 	#Read
done

mv eval_IPFS_small.txt eval_IPFS_small$1.txt

