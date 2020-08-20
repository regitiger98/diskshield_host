
	//순서
	//1 1 0 1 (SeqWR) init write
	//1 0 0 1 (SeqRD)
	//1 1 0 1 (SeqWR) - overwrite
	//1 0 1 1 (RandRD)
	//1 1 1 1 (RandWR)

//	1 1 3 1(SmallWrite) initial write
	//	1 1 3 1(SmallWrite)0 OVERWRITE
	//  1 0 3 1	(SmallRead)