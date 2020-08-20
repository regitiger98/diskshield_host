
//#include "AuthenticationEnclave.h"
#include "u_auth_enclave.h"

key_t key_id_rq, key_id_rv;

//Makes an sgx_ecall to the destination enclave to get session id and message1
ATTESTATION_STATUS AE_session_request_ocall(unsigned char* dh_msg1, uint32_t* session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	//uint32_t temp_enclave_no;
	SESS_REQ sess_req;
	SESS_REV sess_rev;
	int msg_rtn;
	//dest_enclave_id = dest_enclave_id;

	key_id_rq = 0x000D;
	key_id_rv = 0x000E;

	key_id_rq = msgget((key_t) key_id_rq, IPC_CREAT|0666);
	key_id_rv = msgget((key_t) key_id_rv, IPC_CREAT|0666);
	//현재 destination에 맵핑되는 애를 가리키는 iterator
	//지울 예정
	/*
	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
	*/

	//here, send message to server, and receive	
	sess_req.mtype = TYPE_SESS_RQ;
	//sess_req.src_enclave_id = src_enclave_id;
	sess_req.src_enclave_id = 1;
	//printf("request src enc id : %d\n", (int)src_enclave_id);

	ANY_REQ any_req;
	memcpy(&any_req, &sess_req, sizeof(sess_req));
	msg_rtn=msgsnd(key_id_rq, &any_req, sizeof(any_req)-sizeof(any_req.mtype), 0);
	//msg_rtn=msgsnd(key_id_rq, &sess_req, sizeof(sess_req)-sizeof(sess_req.mtype), 0);
	if(msg_rtn==-1)
	{
		printf("session_req : msg send fail!\n");
		return INVALID_SESSION;
	}
	printf("session_request_ocall) meesage sends!\n");	
	msg_rtn=msgrcv(key_id_rv, &sess_rev, sizeof(sess_rev)-sizeof(sess_rev.mtype), TYPE_SESS_RV, 0);
	//msg_rtn=msgrcv(key_id_rv, &sess_rev, sizeof(sess_rev)-sizeof(sess_rev.mtype), TYPE_SESS_RV, 0);

	if(msg_rtn==-1)
	{
		printf("session_req : msg rev fail!\n");
		return INVALID_SESSION;
	}
	printf("session_request_ocall) meesage receive!\n");	
	
	*session_id = sess_rev.session_id;
	//*dh_msg1 = (unsigned char*)sess_rev.dh_msg1;
	memcpy(dh_msg1, &sess_rev.dh_msg1, SIZE_DH_MSG1);
	
	/*	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave1_session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
			break;
		case 2:
			ret = Enclave2_session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
			break;
		case 3:
			ret = Enclave3_session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
			break;
	}
	*/
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else	
	    return INVALID_SESSION;
}
//Makes an sgx_ecall to the destination enclave sends message2 from the source enclave and gets message 3 from the destination enclave
ATTESTATION_STATUS AE_exchange_report_ocall(unsigned char *dh_msg2, unsigned char *dh_msg3, uint32_t session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	//int32_t temp_enclave_no;

	REPORT_REQ report_req;
	REPORT_REV report_rev;
	int msg_rtn;
	//dest_enclave_id = dest_enclave_id;
/*	
	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
	*/
	//printf("exchange src enc id : %d   %d \n", (int)src_enclave_id,(int)session_id);
	//here, send message to server, and receive	
	report_req.mtype = TYPE_REPORT_RQ;
	//report_req.src_enclave_id = src_enclave_id;
	report_req.src_enclave_id = 1;
	//report_req.dh_msg2 = *dh_msg2;
	memcpy(&report_req.dh_msg2, dh_msg2, SIZE_DH_MSG2);
	report_req.session_id = session_id;

	ANY_REQ any_req;
	memcpy(&any_req, &report_req, sizeof(report_req));
	msg_rtn=msgsnd(key_id_rq, &any_req, sizeof(any_req)-sizeof(any_req.mtype), 0);
	//msg_rtn=msgsnd(key_id_rq, &report_req, sizeof(report_req)-sizeof(report_req.mtype), 0);
	if(msg_rtn==-1)
	{
		printf("exchange_report : msg send fail!\n");
		return INVALID_SESSION;
	}
	printf("exchange_report_ocall) meesage sends!\n");	
	msg_rtn=msgrcv(key_id_rv, &report_rev, sizeof(report_rev)-sizeof(report_rev.mtype), TYPE_REPORT_RV, 0);

	if(msg_rtn==-1)
	{
		printf("exchange_report : msg rev fail!\n");
		return INVALID_SESSION;
	}
	printf("exchange_report_ocall) meesage receive!\n");	
	
	//*session_id = report_rev.session_id;
	//*dh_msg3 = report_rev.dh_msg3;
	memcpy(dh_msg3, &report_rev.dh_msg3, SIZE_DH_MSG3);

	/*
	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave1_exchange_report(dest_enclave_id, &status, src_enclave_id, dh_msg2, dh_msg3, session_id);
			break;
		case 2:
			ret = Enclave2_exchange_report(dest_enclave_id, &status, src_enclave_id, dh_msg2, dh_msg3, session_id);
			break;
		case 3:
			ret = Enclave3_exchange_report(dest_enclave_id, &status, src_enclave_id, dh_msg2, dh_msg3, session_id);
			break;
	}
*/
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else	
	    return INVALID_SESSION;

}


ATTESTATION_STATUS AE_send_request_ocall(unsigned char* req_message, size_t req_message_size, size_t max_payload_size, unsigned char* resp_message, size_t resp_message_size)
{
	uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;

	SEND_REQ send_req;
	SEND_REV send_rev;
	int msg_rtn;
	//std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    /*if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
	*/
	//here, send message to server, and receive	
	send_req.mtype = TYPE_SEND_RQ;
	//send_req.req_message = *req_message;
	memcpy(&send_req.req_message, req_message, sizeof(secure_message_t));
	memcpy(send_req.payload, ((secure_message_t*)req_message)->message_aes_gcm_data.payload, req_message_size-sizeof(secure_message_t));
	send_req.max_payload_size = max_payload_size;
	send_req.req_message_size = req_message_size;
	send_req.resp_message_size = resp_message_size;
	send_req.src_enclave_id = 1;
	//send_req.src_enclave_id = src_enclave_id;
	
	
	ANY_REQ any_req;
	memcpy(&any_req, &send_req, sizeof(send_req));
	msg_rtn=msgsnd(key_id_rq, &any_req, sizeof(any_req)-sizeof(any_req.mtype), 0);
	//msg_rtn=msgsnd(key_id_rq, &send_req, sizeof(send_req)-sizeof(send_req.mtype), 0);
	if(msg_rtn==-1)
	{
		printf("send request: msg send fail!\n");
		return INVALID_SESSION;
	}
	printf("send_request_ocall) message sends!\n");	
	msg_rtn=msgrcv(key_id_rv, &send_rev, sizeof(send_rev)-sizeof(send_rev.mtype), TYPE_SEND_RV, 0);

	if(msg_rtn==-1)
	{
		printf("send_request : msg rev fail!\n");
		return INVALID_SESSION;
	}
	printf("send_request_ocall) meesage receive!\n");	
	//*session_id = send_rev.session_id;
	//*dh_msg3 = send_rev.dh_msg3;
	//*resp_message = send_rev.resp_message;
	memcpy(resp_message, &send_rev.resp_message, sizeof(secure_message_t));
	memcpy(((secure_message_t*)resp_message)->message_aes_gcm_data.payload, send_rev.payload, max_payload_size);

/*
	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave1_generate_response(dest_enclave_id, &status, src_enclave_id, req_message, req_message_size, max_payload_size, resp_message, resp_message_size);
			break;
		case 2:
			ret = Enclave2_generate_response(dest_enclave_id, &status, src_enclave_id, req_message, req_message_size, max_payload_size, resp_message, resp_message_size);
			break;
		case 3:
			ret = Enclave3_generate_response(dest_enclave_id, &status, src_enclave_id, req_message, req_message_size, max_payload_size, resp_message, resp_message_size);
			break;
	}
*/
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else	
	    return INVALID_SESSION;



}
ATTESTATION_STATUS AE_end_session_ocall()
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;
	END_REQ end_req;
	END_REV end_rev;
	int msg_rtn;
/*
	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
	*/
//here, send message to server, and receive	
	end_req.mtype = TYPE_END_RQ;
	//end_req.src_enclave_id = src_enclave_id;
	end_req.src_enclave_id = 1;
	//end_req.dest_enclave_id = dest_enclave_id;

	ANY_REQ any_req;
	memcpy(&any_req, &end_req, sizeof(end_req));
	msg_rtn=msgsnd(key_id_rq, &any_req, sizeof(any_req)-sizeof(any_req.mtype), 0);
	//msg_rtn=msgsnd(key_id_rq, &end_req, sizeof(end_req)-sizeof(end_req.mtype), 0);
	if(msg_rtn==-1)
	{
		printf("end_session : msg send fail!\n");
		return INVALID_SESSION;
	}
	printf("end_session_ocall) meesage sends!\n");	
	msg_rtn=msgrcv(key_id_rv, &end_rev, sizeof(end_rev)-sizeof(end_rev.mtype), TYPE_END_RV, 0);

	if(msg_rtn==-1)
	{
		printf("end_session : msg rev fail!\n");
		return INVALID_SESSION;
	}
	printf("end_session_ocall) meesage receive!\n");	
	
	//*session_id = report_rev.session_id;
	//msg_rtn = end_rev.rtn;
	

/*
	switch(temp_enclave_no)
	{
		case 1:
			ret = Enclave1_end_session(dest_enclave_id, &status, src_enclave_id);
			break;
		case 2:
			ret = Enclave2_end_session(dest_enclave_id, &status, src_enclave_id);
			break;
		case 3:
			ret = Enclave3_end_session(dest_enclave_id, &status, src_enclave_id);
			break;
	}
	*/
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS)status;
	else	
	    return INVALID_SESSION;


}
