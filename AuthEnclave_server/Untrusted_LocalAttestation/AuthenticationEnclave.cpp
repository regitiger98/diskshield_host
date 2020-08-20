#include "AuthenticationEnclave.h"
#include <stdio.h>

//server side.
AuthenticationEnclave::AuthenticationEnclave(sgx_enclave_id_t enclave_id)
{
	int ret;
	this->enclave_id = enclave_id;
	long mtype;
	printf("the Authentication Server Started!\n");

	key_id_rq = 0x000D;
	key_id_rv = 0x000E;
	key_id_rq=msgget((key_t)key_id_rq, IPC_CREAT|0666);
	key_id_rv=msgget((key_t)key_id_rv, IPC_CREAT|0666);
	
	while(1)
	{
		//ret = msgrcv(key_id_rq, &msg, MAX_MSG, TYPE_ANY, 0);
		any_req.mtype = 0;
		memset(any_req.msg, 0x00, MAX_MSG);
		ret = msgrcv(key_id_rq, &any_req, MAX_MSG, TYPE_ANY, 0);
		if(ret==-1)
		{
			printf("z");

			//error
		}

		//memcpy(&mtype,&sg, sizeof(long));
	
		switch(any_req.mtype)
		{
			case TYPE_SESS_RQ : 	ret=AE_proc_sess(); 		break;
			case TYPE_REPORT_RQ : 	ret=AE_proc_report(); 		break;
			case TYPE_SEND_RQ : 	ret=AE_proc_send(); 		break;
			case TYPE_END_RQ : 	ret=AE_proc_end();			break;
		}

		if(ret==-1)
		{
			//error
		}
	}
}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_sess()
{
	uint32_t ret;
	sgx_status_t ret_sgx = SGX_SUCCESS;
	uint32_t status = 0;
	
	printf("AE_proc_sess()\n");
	//get message from client
	memcpy(&sess_req, &any_req, sizeof(sess_req));

	printf("session_request ! \n");
	//process the message
	ret_sgx = Enclave2_session_request(enclave_id, &status, sess_req.src_enclave_id, &sess_rev.dh_msg1, &sess_rev.session_id);
	
	if (ret_sgx != SGX_SUCCESS)
	    return INVALID_SESSION;

	printf("send message to client!\n");
	//response mesage to client
	sess_rev.mtype = TYPE_SESS_RV; 
	ret = msgsnd(key_id_rv, &sess_rev, sizeof(sess_rev)-sizeof(sess_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}
	return (ATTESTATION_STATUS) status;
}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_report()
{
	uint32_t ret;
	uint32_t status = 0;
	sgx_status_t ret_sgx = SGX_SUCCESS;
//	sess_req = 
	//get message from client
	printf("AE_proc_report()\n");
	memcpy(&report_req, &any_req, sizeof(report_req));

	//process the message
	ret_sgx = Enclave2_exchange_report(enclave_id, &status, report_req.src_enclave_id, &report_req.dh_msg2, &report_rev.dh_msg3, report_req.session_id);

	report_rev.mtype = TYPE_REPORT_RV;
	
	if (ret_sgx != SGX_SUCCESS)
	    return INVALID_SESSION;

	//response mesage to client
	report_rev.mtype = TYPE_REPORT_RV;
	ret = msgsnd(key_id_rv, &report_rev, sizeof(report_rev)-sizeof(report_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}
	return (ATTESTATION_STATUS) status;
}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_send()
{
	uint32_t ret;
	sgx_status_t ret_sgx = SGX_SUCCESS;
	uint32_t status = 0;
	secure_message_t *req_message, *resp_message;
	//	sess_req = 
	//get message from client
	printf("AE_proc_send()\n");
	memcpy(&send_req, &any_req, sizeof(send_req));

	//process the message
	//ret = Enclave1_exchange_report(enclave_id, &status, report_req.src_enclave_id, &report_req.dh_msg2, &report_rev.dh_msg3, report_req.session_id);

	req_message = (secure_message_t*) malloc(send_req.req_message_size);
	memcpy(req_message, &send_req.req_message, sizeof(secure_message_t));
	memcpy(req_message->message_aes_gcm_data.payload, send_req.payload, send_req.req_message_size-sizeof(secure_message_t));
	
	resp_message = (secure_message_t*) malloc (send_req.resp_message_size);
	printf("test.. payload? %d %d %d\n", req_message->message_aes_gcm_data.payload[0], req_message->message_aes_gcm_data.payload[1], req_message->message_aes_gcm_data.payload[2]);
	ret_sgx = Enclave2_generate_response(enclave_id, &status, send_req.src_enclave_id, req_message, send_req.req_message_size, send_req.max_payload_size, resp_message, send_req.resp_message_size);
	
	if (ret_sgx != SGX_SUCCESS)
	    return INVALID_SESSION;

	//response mesage to client
	send_rev.mtype = TYPE_SEND_RV;
	memcpy(&send_rev.resp_message, resp_message, sizeof(secure_message_t));
	memcpy(send_rev.payload, resp_message->message_aes_gcm_data.payload, resp_message->message_aes_gcm_data.payload_size);

	ret = msgsnd(key_id_rv, &send_rev, sizeof(send_rev)-sizeof(send_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}
	
	return (ATTESTATION_STATUS) status;

}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_end()
{
	uint32_t ret;
	sgx_status_t ret_sgx = SGX_SUCCESS;
	uint32_t status = 0;
//	sess_req = 
	//get message from client
	printf("AE_proc_end()\n");
	memcpy(&end_req, &any_req, sizeof(end_req));

	//process the message
	ret_sgx = Enclave2_end_session(enclave_id, &status, end_req.src_enclave_id);
	
	if (ret_sgx != SGX_SUCCESS)
	    return INVALID_SESSION;

	//response mesage to client
	end_rev.mtype = TYPE_END_RV;
	ret = msgsnd(key_id_rv, &end_rev, sizeof(end_rev)-sizeof(end_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}

	return (ATTESTATION_STATUS) status;

}


