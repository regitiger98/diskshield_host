
#ifndef	AUTHENTICATIONENCLAVE_H_ 
#define	AUTHENTICATIONENCLAVE_H_ 

#include "sgx_ecp_types.h"
#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_attributes.h"

#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"


#define NONCE_SIZE         16
//#define MAC_SIZE           16

#define MSG_BUF_LEN        sizeof(ec_pub_t)*2
#define MSG_HASH_SZ        32

//datatypes.h
#define DH_KEY_SIZE        20
#define NONCE_SIZE         16
//#define MAC_SIZE           16
#define MAC_KEY_SIZE       16
#define PADDING_SIZE       16

#define TAG_SIZE        16
#define IV_SIZE            12

#define DERIVE_MAC_KEY      0x0
#define DERIVE_SESSION_KEY  0x1
#define DERIVE_VK1_KEY      0x3
#define DERIVE_VK2_KEY      0x4

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define MESSAGE_EXCHANGE 0x0
#define ENCLAVE_TO_ENCLAVE_CALL 0x1

#define INVALID_ARGUMENT                   -2   ///< Invalid function argument
#define LOGIC_ERROR                        -3   ///< Functional logic error
#define FILE_NOT_FOUND                     -4   ///< File not found

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#define VMC_ATTRIBUTE_MASK  0xFFFFFFFFFFFFFFCB

#pragma pack(push, 1)

//Format of the AES-GCM message being exchanged between the source and the destination enclaves
typedef struct _secure_message_t
{
    uint32_t session_id; //Session ID identifyting the session to which the message belongs
    sgx_aes_gcm_data_t message_aes_gcm_data;    
}secure_message_t;

//Format of the input function parameter structure
typedef struct _ms_in_msg_exchange_t {
    uint32_t msg_type; //Type of Call E2E or general message exchange
    uint32_t target_fn_id; //Function Id to be called in Destination. Is valid only when msg_type=ENCLAVE_TO_ENCLAVE_CALL
    uint32_t inparam_buff_len; //Length of the serialized input parameters
    char inparam_buff[]; //Serialized input parameters
} ms_in_msg_exchange_t;

//Format of the return value and output function parameter structure
typedef struct _ms_out_msg_exchange_t {
    uint32_t retval_len; //Length of the return value
    uint32_t ret_outparam_buff_len; //Length of the serialized return value and output parameters
    char ret_outparam_buff[]; //Serialized return value and output parameters
} ms_out_msg_exchange_t;

//Session Tracker to generate session ids
typedef struct _session_id_tracker_t
{
    uint32_t          session_id;
}session_id_tracker_t;

#pragma pack(pop)



//error_codes.h
typedef uint32_t ATTESTATION_STATUS;

#define SUCCESS                          0x00
#define INVALID_PARAMETER                0xE1
#define VALID_SESSION                    0xE2
#define INVALID_SESSION                  0xE3
#define ATTESTATION_ERROR                0xE4
#define ATTESTATION_SE_ERROR             0xE5
#define IPP_ERROR                        0xE6
#define NO_AVAILABLE_SESSION_ERROR       0xE7
#define MALLOC_ERROR                     0xE8
#define ERROR_TAG_MISMATCH               0xE9
#define OUT_BUFFER_LENGTH_ERROR          0xEA
#define INVALID_REQUEST_TYPE_ERROR       0xEB
#define INVALID_PARAMETER_ERROR          0xEC
#define ENCLAVE_TRUST_ERROR              0xED
#define ENCRYPT_DECRYPT_ERROR            0xEE
#define DUPLICATE_SESSION                0xEF

//dh_session_protocol.h
//
//Session information structure
typedef struct _la_dh_session_t
{
    uint32_t  session_id; //Identifies the current session
    uint32_t  status; //Indicates session is in progress, active or closed
    union
    {
        struct
        {
			sgx_dh_session_t dh_session;
        }in_progress;

        struct
        {
            sgx_key_128bit_t AEK; //Session Key
            uint32_t counter; //Used to store Message Sequence Number
        }active;
    };
} dh_session_t;


#ifdef __cplusplus
extern "C" {
#endif

uint32_t test_create_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);
uint32_t test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, unsigned char *DS_key, unsigned char* encrypted_key);
//uint32_t create_session(dh_session_t *p_session_info);
//uint32_t send_request_receive_response(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, dh_session_t *p_session_info, char *inp_buff, size_t inp_buff_len, size_t max_out_buff_size, char **out_buff, size_t* out_buff_len);
//uint32_t close_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);

#ifdef __cplusplus
}
#endif




#endif
