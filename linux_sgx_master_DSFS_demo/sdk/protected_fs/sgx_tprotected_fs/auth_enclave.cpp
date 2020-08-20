#include <map>

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"


#include "auth_enclave.h" 
#include "sgx_tprotected_fs_t.h"

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

//extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);

#define KEY_SIZE 16

static ATTESTATION_STATUS create_session(dh_session_t *session_info);
static uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);
static uint32_t marshal_input_parameters_encrypt_key(uint32_t target_fn_id, uint32_t msg_type, uint8_t* key, char** marshalled_buff, size_t* marshalled_buff_len);
static uint32_t unmarshal_retval_and_output_parameters_encrypt_key(char* out_buff, uint8_t* encrypted_key);
static uint32_t SGXAPI send_request_receive_response(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, dh_session_t *p_session_info, char *inp_buff, size_t inp_buff_len, size_t max_out_buff_size, char **out_buff, size_t* out_buff_len);
static uint32_t SGXAPI close_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);

//Makes use of the sample code function to establish a secure channel with the destination enclave (Test Vector)
uint32_t test_create_session(sgx_enclave_id_t src_enclave_id,
                         sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;

	src_enclave_id = src_enclave_id;
	dest_enclave_id=2;
   
	//session already created.
	if(g_src_session_info_map.find(src_enclave_id)!=g_src_session_info_map.end())
		return SUCCESS;
	
	//Core reference code function for creating a session
    ke_status = create_session(&dest_session_info);

    //Insert the session information into the map under the corresponding destination enclave id
    if(ke_status == SUCCESS)
    {
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
}

//Makes use of the sample code function to do an enclave to enclave call (Test Vector)
uint32_t test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id,
                                          sgx_enclave_id_t dest_enclave_id,
										  unsigned char *DS_key, unsigned char *encrypted_key)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    //uint32_t var1,var2;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff=NULL;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    //char* retval;
//	uint8_t encrypted_key[16];
/*
uint8_t key[16]={1,1,1,1,\
				  1,1,1,1,\
			  1,1,1,1,\
				  1,1,1,1};
*/
    //var1 = 0x4;
    //var2 = 0x5;
    //target_fn_id = 0;
    target_fn_id = 1; //encrypt_key funciton is stored at index 1 in function table.
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 50;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_encrypt_key(target_fn_id, msg_type, DS_key, &marshalled_inp_buff, &marshalled_inp_buff_len);
    //ke_status = marshal_input_parameters_e2_foo1(target_fn_id, msg_type, var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
          dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                            marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);


    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from foo1 of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_encrypt_key(out_buff, encrypted_key);
    
	
	//
	//ke_status = unmarshal_retval_and_output_parameters_e2_foo1(out_buff, &retval);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    //SAFE_FREE(retval);
    return SUCCESS;
}

//Create a session with the destination enclave
static ATTESTATION_STATUS create_session(dh_session_t *session_info)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;        // Session Key
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    if(!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    //Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
            return status;
    }
    
    //Ocall to request for a session with the destination enclave and obtain session id and Message 1 if successful
    //session id is the target's id.
	status = AE_session_request_ocall(&retstatus, (unsigned char*)&dh_msg1, &session_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);

	}
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    //Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
         return status;
    }

    //Send Message 2 to Destination Enclave and get Message 3 in return
    status = AE_exchange_report_ocall(&retstatus, (unsigned char*)&dh_msg2, (unsigned char*)&dh_msg3, session_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }

    //Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    // Verify the identity of the destination enclave
    if(verify_peer_enclave_trust(&responder_identity) != SUCCESS)
    {
        return INVALID_SESSION;
    }

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return status;
}

//Function that is used to verify the trust of the other enclave
//Each enclave can have its own way verifying the peer enclave identity
//extern "C" 
static uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return SUCCESS;
    }
}

static uint32_t marshal_input_parameters_encrypt_key(uint32_t target_fn_id, uint32_t msg_type, uint8_t* key, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
        
    param_len = KEY_SIZE;
    //param_len = sizeof(var1)+sizeof(var2);
    temp_buff = (char*)malloc(param_len);
    if(!temp_buff)
        return MALLOC_ERROR;

    //memcpy(temp_buff,&var1,sizeof(var1));
    //memcpy(temp_buff+sizeof(var1),&var2,sizeof(var2));
    memcpy(temp_buff, key, KEY_SIZE);
	ms_len = sizeof(ms_in_msg_exchange_t) + param_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)param_len;
    memcpy(&ms->inparam_buff, temp_buff, param_len);
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}

static uint32_t unmarshal_retval_and_output_parameters_encrypt_key(char* out_buff, uint8_t* encrypted_key)
{
    //size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff)
        return INVALID_PARAMETER_ERROR;
    ms = (ms_out_msg_exchange_t *)out_buff;
    //retval_len = ms->retval_len;
//    *retval = (char*)malloc(retval_len);
//    if(!*retval)
  //      return MALLOC_ERROR;

  //  memcpy(*retval, ms->ret_outparam_buff, retval_len);
    memcpy(encrypted_key, ms->ret_outparam_buff, KEY_SIZE);
	return SUCCESS;
}

//Request for the response size, send the request message to the destination enclave and receive the response message back
static ATTESTATION_STATUS send_request_receive_response(sgx_enclave_id_t src_enclave_id,
                                  sgx_enclave_id_t dest_enclave_id,
                                  dh_session_t *session_info,
                                  char *inp_buff,
                                  size_t inp_buff_len,
                                  size_t max_out_buff_size,
                                  char **out_buff,
                                  size_t* out_buff_len)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    uint32_t retstatus;
    secure_message_t* req_message;
    secure_message_t* resp_message;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t max_resp_message_length;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!session_info || !inp_buff)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Check if the nonce for the session has not exceeded 2^32-2 if so end session and start a new session
    if(session_info->active.counter == ((uint32_t) - 2))
    {
        close_session(src_enclave_id, dest_enclave_id);
        create_session(session_info);
        //create_session(src_enclave_id, dest_enclave_id, session_info);
    }

    //Allocate memory for the AES-GCM request message
    req_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ inp_buff_len);
    if(!req_message)
    {
        return MALLOC_ERROR;
    }

    memset(req_message,0,sizeof(secure_message_t)+ inp_buff_len);
    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;
    //Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    //Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    //Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)inp_buff, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),	//init vector
                sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length, 
                &(req_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return status;
    }
    
    //Allocate memory for the response payload to be copied
    *out_buff = (char*)malloc(max_out_buff_size);
    if(!*out_buff)
    {
        SAFE_FREE(req_message);
        return MALLOC_ERROR;
    }

    memset(*out_buff, 0, max_out_buff_size);

    //Allocate memory for the response message
    resp_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ max_out_buff_size);
    if(!resp_message)
    {
        SAFE_FREE(req_message);
        return MALLOC_ERROR;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ max_out_buff_size);

    //Ocall to send the request to the Destination Enclave and get the response message back
    status = AE_send_request_ocall(&retstatus, (unsigned char*)req_message,
                                (sizeof(secure_message_t)+ inp_buff_len), max_out_buff_size,
                                (unsigned char*)resp_message, (sizeof(secure_message_t)+ max_out_buff_size));
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
        {
            SAFE_FREE(req_message);
            SAFE_FREE(resp_message);
            return ((ATTESTATION_STATUS)retstatus);
        }
    }
    else
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return ATTESTATION_SE_ERROR;
    }

    max_resp_message_length = sizeof(secure_message_t)+ max_out_buff_size;

    if(sizeof(resp_message) > max_resp_message_length)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return INVALID_PARAMETER_ERROR;
    }

    //Code to process the response message from the Destination Enclave

    decrypted_data_length = resp_message->message_aes_gcm_data.payload_size;
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return MALLOC_ERROR;
    }
    memset(&l_tag, 0, 16);

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the response message payload
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, resp_message->message_aes_gcm_data.payload, 
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                sizeof(resp_message->message_aes_gcm_data.reserved), &(resp_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length, 
                &resp_message->message_aes_gcm_data.payload_tag);
    
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(resp_message);
        return status;
    }

    // Verify if the nonce obtained in the response is equal to the session nonce + 1 (Prevents replay attacks)
    if(*(resp_message->message_aes_gcm_data.reserved) != (session_info->active.counter + 1 ))
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        SAFE_FREE(decrypted_data);
        return INVALID_PARAMETER_ERROR;
    }

        //Update the value of the session nonce in the source enclave
    session_info->active.counter = session_info->active.counter + 1;

    memcpy(out_buff_len, &decrypted_data_length, sizeof(decrypted_data_length));
    memcpy(*out_buff, decrypted_data, decrypted_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(req_message);
    SAFE_FREE(resp_message);
    return SUCCESS;


}

//Close a current session
static ATTESTATION_STATUS close_session(sgx_enclave_id_t src_enclave_id,
                        sgx_enclave_id_t dest_enclave_id)
{
    sgx_status_t status;

    uint32_t retstatus;

	src_enclave_id = src_enclave_id;
	dest_enclave_id = dest_enclave_id;
    //Ocall to ask the destination enclave to end the session
    status = AE_end_session_ocall(&retstatus);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    return SUCCESS;
}





