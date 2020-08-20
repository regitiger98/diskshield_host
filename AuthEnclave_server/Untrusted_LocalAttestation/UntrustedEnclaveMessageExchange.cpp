/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "sgx_eid.h"
#include "error_codes.h"
#include "datatypes.h"
#include "sgx_urts.h"
#include "UntrustedEnclaveMessageExchange.h"
#include "sgx_dh.h"
#include <map>


#include "AuthenticationEnclave.h"

std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

extern key_t key_id_rq, key_id_rv;
//Makes an sgx_ecall to the destination enclave to get session id and message1
ATTESTATION_STATUS session_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;
	SESS_REQ sess_req;
	SESS_REV sess_rev;
	int msg_rtn;

	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}

	//here, send message to server, and receive	
	sess_req.mtype = TYPE_SESS_RQ;
	sess_req.src_enclave_id = src_enclave_id;

	msg_rtn=msgsnd(key_id_rq, &sess_req, sizeof(sess_req)-sizeof(sess_req.mtype), 0);
	if(msg_rtn==-1)
	{
		printf("session_req : msg send fail!\n");
		return INVALID_SESSION;
	}
	printf("session_request_ocall) meesage sends!\n");	
	msg_rtn=msgrcv(key_id_rv, &sess_rev, sizeof(sess_rev)-sizeof(sess_rev.mtype), TYPE_SESS_RV, 0);

	if(msg_rtn==-1)
	{
		printf("session_req : msg rev fail!\n");
		return INVALID_SESSION;
	}
	printf("session_request_ocall) meesage receive!\n");	
	
	*session_id = sess_rev.session_id;
	*dh_msg1 = sess_rev.dh_msg1;
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
ATTESTATION_STATUS exchange_report_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	int32_t temp_enclave_no;

	REPORT_REQ report_req;
	REPORT_REV report_rev;
	int msg_rtn;
	
	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
	//here, send message to server, and receive	
	report_req.mtype = TYPE_REPORT_RQ;
	report_req.src_enclave_id = src_enclave_id;
	report_req.dh_msg2 = *dh_msg2;
	report_req.session_id = session_id;

	msg_rtn=msgsnd(key_id_rq, &report_req, sizeof(report_req)-sizeof(report_req.mtype), 0);
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
	*dh_msg3 = report_rev.dh_msg3;

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

//Make an sgx_ecall to the destination enclave function that generates the actual response
ATTESTATION_STATUS send_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id,secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
	uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;

	SEND_REQ send_req;
	SEND_REV send_rev;
	int msg_rtn;
	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
	//here, send message to server, and receive	
	send_req.mtype = TYPE_SEND_RQ;
	send_req.req_message = *req_message;
	memcpy(send_req.payload, req_message->message_aes_gcm_data.payload, req_message_size-sizeof(secure_message_t));
	send_req.max_payload_size = max_payload_size;
	send_req.req_message_size = req_message_size;
	send_req.resp_message_size = resp_message_size;
	send_req.src_enclave_id = src_enclave_id;
	msg_rtn=msgsnd(key_id_rq, &send_req, sizeof(send_req)-sizeof(send_req.mtype), 0);
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
	*resp_message = send_rev.resp_message;
	memcpy(resp_message->message_aes_gcm_data.payload, send_rev.payload, max_payload_size);

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

//Make an sgx_ecall to the destination enclave to close the session
ATTESTATION_STATUS end_session_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;
	uint32_t temp_enclave_no;
	END_REQ end_req;
	END_REV end_rev;
	int msg_rtn;

	std::map<sgx_enclave_id_t, uint32_t>::iterator it = g_enclave_id_map.find(dest_enclave_id);
    if(it != g_enclave_id_map.end())
	{
		temp_enclave_no = it->second;
	}
    else
	{
		return INVALID_SESSION;
	}
//here, send message to server, and receive	
	end_req.mtype = TYPE_END_RQ;
	end_req.src_enclave_id = src_enclave_id;
	//end_req.dest_enclave_id = dest_enclave_id;

	msg_rtn=msgsnd(key_id_rq, &end_req, sizeof(end_req)-sizeof(end_req.mtype), 0);
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
