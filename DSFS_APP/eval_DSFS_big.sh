#!/bin/bash

make clean
make

echo "Big File I/O Evaluation" > eval_DSFS_big.txt

#first, you make 64MBfiles and initial write for each threads!
./app 16 1 0 1 | grep seconds >> eval_DSFS_big.txt

#for thread in 1
#for thread in 1 2 4 8 16
for thread in 16 8 4 2 1
do

	#start evaluation
	echo "$thread threads 64MB I/O evaluation" >> eval_DSFS_big.txt
	#arguemnts: numofthreads, read(0)write(1), mode(seq(0),rand(1),small(3)), workload(IPFS(0), DISKSHIELD(1),IPFS_INIT(2))
	#./app $thread 1 0 1	| grep EVAL >> eval_DSFS_big.txt	#Initial Write
	./app $thread 0 0 1 | grep EVAL >> eval_DSFS_big.txt	#Read
	./app $thread 1 0 1 | grep EVAL >> eval_DSFS_big.txt #Overwrite
	#./app $thread 1 0 1	#Initial Write
	#./app $thread 0 0 1 #Read
	#./app $thread 1 0 1  #Overwrite
done

#mv eval_IPFS_big.txt $1

