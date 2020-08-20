

#define MAX_MSG 1024
#define SIZE_PAYLOAD 100 //not decide yet.. 

//message queue
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
//#include <stdlib.h>
#include <string.h>

#include "sgx_eid.h"
#include "error_codes.h"
#include "datatypes.h"
#include "sgx_urts.h"
#include "UntrustedEnclaveMessageExchange.h"
#include "sgx_dh.h"
#include <map>

#ifndef AUTHENTICATIONENCLAVE_H_ 
#define AUTHENTICATIONENCLAVE_H_ 


//message type


typedef struct{
	long mtype;
	char msg[MAX_MSG];
}ANY_REQ;

typedef struct{
	long mtype;
	sgx_enclave_id_t src_enclave_id;
//	uint32_t session_id;
}SESS_REQ;


typedef struct{
	long mtype;
	sgx_dh_msg1_t dh_msg1;
	uint32_t session_id;
}SESS_REV;

typedef struct
{
	long mtype;
	sgx_dh_msg2_t dh_msg2;
	sgx_enclave_id_t src_enclave_id;
	uint32_t session_id;
}REPORT_REQ;

typedef struct{
	long mtype;
	sgx_dh_msg3_t dh_msg3;
}REPORT_REV;

typedef struct{
	long mtype;
	sgx_enclave_id_t src_enclave_id;
//	sgx_enclave_id_t dest_enclave_id;

}END_REQ;

typedef struct{
	long mtype;
	//int rtn;
}END_REV;
//req_message 는 flexible aaray member을 가지므로 대입이 안된다...
typedef struct{
	long mtype;
	uint8_t payload[SIZE_PAYLOAD];
	size_t req_message_size;
	size_t max_payload_size;
	size_t resp_message_size;
	sgx_enclave_id_t src_enclave_id;
	secure_message_t req_message;

}SEND_REQ;

typedef struct{
	long mtype;
	uint8_t payload[SIZE_PAYLOAD];
	secure_message_t resp_message;
}SEND_REV;

//std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

enum{ TYPE_ANY=0, TYPE_SESS_RQ, TYPE_SESS_RV,\
		TYPE_REPORT_RQ, TYPE_REPORT_RV, \
		TYPE_END_RQ, TYPE_END_RV, \
		TYPE_SEND_RQ, TYPE_SEND_RV};

class AuthenticationEnclave{

	private:

		key_t key_id_rq, key_id_rv;
		sgx_enclave_id_t enclave_id;
		//char msg[MAX_MSG];
		ANY_REQ any_req;
		SESS_REQ sess_req;
		SESS_REV sess_rev;
		REPORT_REQ report_req;
		REPORT_REV report_rev;
		SEND_REQ send_req;
		SEND_REV send_rev;
		END_REQ end_req;
		END_REV end_rev;
		
		ATTESTATION_STATUS AE_proc_sess();
	 	ATTESTATION_STATUS AE_proc_report();
		ATTESTATION_STATUS AE_proc_end();
		ATTESTATION_STATUS AE_proc_send();
	public:
		AuthenticationEnclave(sgx_enclave_id_t enclave_id);

};

#endif

