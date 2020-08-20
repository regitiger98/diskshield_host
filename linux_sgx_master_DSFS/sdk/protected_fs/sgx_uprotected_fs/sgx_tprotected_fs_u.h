#ifndef SGX_TPROTECTED_FS_U_H__
#define SGX_TPROTECTED_FS_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, AE_session_request_ocall, (unsigned char* dh_msg1, uint32_t* session_id));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, AE_exchange_report_ocall, (unsigned char* dh_msg2, unsigned char* dh_msg3, uint32_t session_id));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, AE_send_request_ocall, (unsigned char* req_message, size_t req_message_size, size_t max_payload_size, unsigned char* resp_message, size_t resp_message_size));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, AE_end_session_ocall, ());
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_diskshieldfs_exclusive_file_open, (const char* filename, int32_t* error_code, uint8_t* mac, uint32_t* version, char* response, uint8_t* DS_key));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_diskshieldfs_fclose, (int32_t fd, uint8_t* mac, uint32_t* version, char* response));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_diskshieldfs_fwrite_node, (int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t* mac, uint32_t* version, char* response));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_diskshieldfs_fread_node, (int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
uint8_t* SGX_UBRIDGE(SGX_NOCONVENTION, isc_allocate_buf, (uint32_t size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, isc_free_buf, (uint8_t* buf));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, isc_write_data, (uint8_t* dst, uint8_t* src, uint32_t size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, isc_read_data, (uint8_t* dst, uint8_t* src, uint32_t size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_exclusive_file_open, (const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_check_if_file_exists, (const char* filename));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fread_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fclose, (void* f));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fflush, (void* f));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_remove, (const char* filename));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_recovery_file_open, (const char* filename));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_recovery_node, (void* f, uint8_t* data, uint32_t data_length));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_do_file_recovery, (const char* filename, const char* recovery_filename, uint32_t node_size));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
