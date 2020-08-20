#!/bin/bash
#first, big File 10G sequential write
#file_cnt=1
#second_size=4 #4KB
program="app"
#test_num=1
#first_size=524288 #1G
bench=$1
ssl=4
file_num=0

#file_num=0
#re=$2
#nu=$3

#gcc -o one one.c
gcc -o solve solve.c

if [ "$bench" = "1" ]; then
    bench_name="new_systemcall"
    bench_mode=1
else
    bench_name="original"
    bench_mode=0
fi

rm middle.txt


for repeat in 1 2 3 4 5 #$re  # 2 3 4
do
	for process in 1 2 4 8 16
	do
		for file_size in 8 32 128 512 2048 8192 65536
		do
			if [ "$process" != "1" ] && [ "$file_size" != "32768" ]; then
				continue
			fi
			for mode in 1 0
			do
				echo "we sleep $ssl s"
				echo 3 > /proc/sys/vm/drop_caches
				sleep $ssl
				echo "start!"
				./$program $bench_name $process $file_size $mode $bench_mode $file_num |tee -a middle.txt 
			#	ls -al /home/jinu/SSD/ |wc -l; ls -alh /home/jinu/SSD/ | grep "file_*" | head -n 5
			done
			file_num=$(expr $file_num + $process)
			echo "file num: $file_num "
		done
	done
#	echo "rm file_*.txt"
#	rm /home/jinu/SSD/file_*.txt
#	sleep $ssl

	./solve

	mv result.txt res$1/result$repeat.txt
	mv last.txt res$1/last$repeat.txt
	mv middle.txt res$1/middle$repeat.txt

done

