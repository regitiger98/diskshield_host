#ifndef SGX_TPROTECTED_FS_T_H__
#define SGX_TPROTECTED_FS_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SGX_CDECL AE_session_request_ocall(uint32_t* retval, unsigned char* dh_msg1, uint32_t* session_id);
sgx_status_t SGX_CDECL AE_exchange_report_ocall(uint32_t* retval, unsigned char* dh_msg2, unsigned char* dh_msg3, uint32_t session_id);
sgx_status_t SGX_CDECL AE_send_request_ocall(uint32_t* retval, unsigned char* req_message, size_t req_message_size, size_t max_payload_size, unsigned char* resp_message, size_t resp_message_size);
sgx_status_t SGX_CDECL AE_end_session_ocall(uint32_t* retval);
sgx_status_t SGX_CDECL u_diskshieldfs_exclusive_file_open(int32_t* retval, const char* filename, int32_t* error_code, uint8_t* mac, uint32_t* version, char* response, uint8_t* DS_key);
sgx_status_t SGX_CDECL u_diskshieldfs_fclose(int32_t* retval, int32_t fd, uint8_t* mac, uint32_t* version, char* response);
sgx_status_t SGX_CDECL u_diskshieldfs_fwrite_node(int32_t* retval, int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t* mac, uint32_t* version, char* response);
sgx_status_t SGX_CDECL u_diskshieldfs_fread_node(int32_t* retval, int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL isc_allocate_buf(uint8_t** retval, uint32_t size);
sgx_status_t SGX_CDECL isc_free_buf(int32_t* retval, uint8_t* buf);
sgx_status_t SGX_CDECL isc_write_data(int32_t* retval, uint8_t* dst, uint8_t* src, uint32_t size);
sgx_status_t SGX_CDECL isc_read_data(int32_t* retval, uint8_t* dst, uint8_t* src, uint32_t size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code);
sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f);
sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length);
sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
