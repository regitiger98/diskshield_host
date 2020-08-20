
#ifndef U_AUTHENTICATIONENCLAVE_H_ 
#define U_AUTHENTICATIONENCLAVE_H_ 

#define MAX_MSG 1024
#define SIZE_PAYLOAD 100 //not decide yet.. 
#define SIZE_DH_MSG1 576
#define SIZE_DH_MSG2 512
#define SIZE_DH_MSG3 452
//message queue
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
//#include <stdlib.h>
#include <string.h> //memcpy

#include "sgx_eid.h"
//#include "error_codes.h"
//#include "datatypes.h"
#include "sgx_urts.h"
//#include "UntrustedEnclaveMessageExchange.h"
#include "sgx_dh.h"
#include <map>
#include <cstddef>
#include "../sgx_tprotected_fs/auth_enclave.h"

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


enum{ TYPE_ANY=0, TYPE_SESS_RQ, TYPE_SESS_RV,\
		TYPE_REPORT_RQ, TYPE_REPORT_RV, \
		TYPE_END_RQ, TYPE_END_RV, \
		TYPE_SEND_RQ, TYPE_SEND_RV};


#ifdef __cplusplus
extern "C" {
#endif

uint32_t AE_session_request_ocall(unsigned char* dh_msg1, uint32_t* session_id);
uint32_t AE_exchange_report_ocall(unsigned char* dh_msg2, unsigned char* dh_msg3, uint32_t session_id);
uint32_t AE_send_request_ocall(unsigned char* req_message, size_t req_message_size, size_t max_payload_size, unsigned char* resp_message, size_t resp_message_size);
uint32_t AE_end_session_ocall();


#ifdef __cplusplus
}
#endif

#endif














