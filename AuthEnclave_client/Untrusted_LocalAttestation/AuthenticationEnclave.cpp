#include "AuthenticationEnclave.h"

//server side.
/*
AuthenticationEnclave::AuthenticationEnclave(sgx_enclave_id_t enclave_id)
{
	ATTESTATION_STATUS ret;
	this->enclave_id = enclave_id;

	key_id_rq = 0x1234;
	key_id_rv = 0x4321;
	key_id_rq=msgget((key_t)key_id_rq, IPC_CREAT|0666);
	key_id_rv=msgget((key_t)key_id_rv, IPC_CREAT|0666);
	
	while(1)
	{
		ret = msgrcv(key_id_rq, &msg, MAX_MSG, TYPE_ANY, 0);
		if(ret==-1)
		{
			//error
		}
		long mtype;
		memcpy(&mtype,msg, sizeof(long));

		switch(mtype)
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
	uint32_t status = 0;
//	sess_req = 
	//get message from client
	memcpy(&sess_req, msg, sizeof(sess_req));

	//process the message
	ret = Enclave1_session_request(enclave_id, &status, sess_req.src_enclave_id, &sess_rev.dh_msg1, &sess_rev.session_id);
	
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS) status;
	else	
	    return INVALID_SESSION;

	//response mesage to client
	sess_rev.mtype = TYPE_SESS_RV; 
	ret = msgsnd(key_id_rv, &sess_rev, sizeof(sess_rev)-sizeof(sess_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}
}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_report()
{
	uint32_t ret;
	uint32_t status = 0;
//	sess_req = 
	//get message from client
	memcpy(&report_req, msg, sizeof(report_req));

	//process the message
	ret = Enclave1_exchange_report(enclave_id, &status, report_req.src_enclave_id, &report_req.dh_msg2, &report_rev.dh_msg3, report_req.session_id);

	report_rev.mtype = TYPE_REPORT_RV;
	
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS) status;
	else	
	    return INVALID_SESSION;

	//response mesage to client
	report_rev.mtype = TYPE_REPORT_RV;
	ret = msgsnd(key_id_rv, &report_rev, sizeof(report_rev)-sizeof(report_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}
}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_send()
{
	uint32_t ret;
	uint32_t status = 0;
	secure_message_t *req_message, *resp_message;
	//	sess_req = 
	//get message from client
	memcpy(&send_req, msg, sizeof(send_req));

	//process the message
	//ret = Enclave1_exchange_report(enclave_id, &status, report_req.src_enclave_id, &report_req.dh_msg2, &report_rev.dh_msg3, report_req.session_id);

	req_message = (secure_message_t*) malloc(send_req.req_message_size);
	memcpy(req_message, &send_req.req_message, sizeof(secure_message_t));
	memcpy(req_message->message_aes_gcm_data.payload, send_req.payload, sizeof(send_req.req_message_size)-sizeof(secure_message_t));
	
	resp_message = (secure_message_t*) malloc (send_req.resp_message_size);

	ret = Enclave1_generate_response(enclave_id, &status, send_req.src_enclave_id, req_message, send_req.req_message_size, send_req.max_payload_size, resp_message, send_req.resp_message_size);
	
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS) status;
	else	
	    return INVALID_SESSION;

	//response mesage to client
	send_rev.mtype = TYPE_SEND_RV;
	memcpy(&send_rev.resp_message, resp_message, sizeof(secure_message_t));
	memcpy(send_rev.payload, resp_message->message_aes_gcm_data.payload, sizeof(resp_message->message_aes_gcm_data.payload_size));

	ret = msgsnd(key_id_rv, &send_rev, sizeof(send_rev)-sizeof(send_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}

}

ATTESTATION_STATUS AuthenticationEnclave::AE_proc_end()
{
	uint32_t ret;
	uint32_t status = 0;
//	sess_req = 
	//get message from client
	memcpy(&end_req, msg, sizeof(end_req));

	//process the message
	ret = Enclave1_end_session(enclave_id, &status, end_req.src_enclave_id);
	
	if (ret == SGX_SUCCESS)
		return (ATTESTATION_STATUS) status;
	else	
	    return INVALID_SESSION;

	//response mesage to client
	end_rev.mtype = TYPE_END_RV;
	ret = msgsnd(key_id_rv, &end_rev, sizeof(end_rev)-sizeof(end_rev.mtype), 0);

	if(ret==-1)
	{
		return INVALID_SESSION;
	}

}

*/
