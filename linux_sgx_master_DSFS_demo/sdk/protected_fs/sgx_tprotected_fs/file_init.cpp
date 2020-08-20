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

#include "sgx_tprotected_fs.h"
#include "sgx_tprotected_fs_t.h"
#include "protected_fs_file.h"
#include "sgx_trts.h"
#include <sgx_utils.h>
#include "auth_enclave.h"
// remove the file path if it's there, leave only the filename, null terminated
bool protected_fs_file::cleanup_filename(const char* src, char* dest)
{
	const char* p = src;
	const char* name = src;

	while ((*p) != '\0')
	{
		if ((*p) == '\\' || (*p) == '/')
			name = p+1;
		p++;
	}

	if (strnlen(name, FILENAME_MAX_LEN) >= FILENAME_MAX_LEN-1)
	{
		last_error = ENAMETOOLONG;
		return false;
	}

	strncpy(dest, name, FILENAME_MAX_LEN-1);
	dest[FILENAME_MAX_LEN-1] = '\0';

	if (strnlen(dest, 1) == 0)
	{
		last_error = EINVAL;
		return false;
	}

	return true;
}

//import_key는 auto key
//kdk_key는 user key
protected_fs_file::protected_fs_file(const char* filename, const char* mode, const sgx_aes_gcm_128bit_key_t* import_key, const sgx_aes_gcm_128bit_key_t* kdk_key)
{
	sgx_status_t status = SGX_SUCCESS;
	//uint8_t result = 0;
	int32_t result32 = 0;

	//자료구조들 초기화
	init_fields();

	if (filename == NULL || mode == NULL || 
		strnlen(filename, 1) == 0 || strnlen(mode, 1) == 0)
	{
		last_error = EINVAL;
		return;
	}

	if (strnlen(filename, FULLNAME_MAX_LEN) >= FULLNAME_MAX_LEN - 1)
	{
		last_error = ENAMETOOLONG;
		return;
	}

	if (import_key != NULL && kdk_key != NULL)
	{// import key is used only with auto generated keys
		last_error = EINVAL;
		return;
	}
	//report를 왜만들지?
	//report : 인클레이브가 cpu에게 요청해서 만드는 credential (: 인클레이브가 local 플랫폼에 있다는 증거물임)
	//param : target_info, report_data, report
	//
	status = sgx_create_report(NULL, NULL, &report);
	if (status != SGX_SUCCESS)
	{
		last_error = status;
		return;
	}
	//mutex lock인듯
	result32 = sgx_thread_mutex_init(&mutex, NULL);
	if (result32 != 0)
	{
		last_error = result32;
		return;
	}
	//마스터키는 무엇?
	//open할때마다 초기화? 생성할때만 해야할거같은데
	if (init_session_master_key() == false) 
		// last_error already set
		return;

	//user key 모드라는 거임. sgx_fopen()
	if (kdk_key != NULL)
	{
		// for new file, this value will later be saved in the meta data plain part (init_new_file)
		// for existing file, we will later compare this value with the value from the file (init_existing_file)
		use_user_kdk_key = 1; 
		memcpy(user_kdk_key, kdk_key, sizeof(sgx_aes_gcm_128bit_key_t));
	}

	//use_user_kdk_key가 유저키임

	//clean file 은뭐지? 걍 file path 제거~!
	// get the clean file name (original name might be clean or with relative path or with absolute path...)
	char clean_filename[FILENAME_MAX_LEN];
	if (cleanup_filename(filename, clean_filename) == false)
		// last_error already set
		return;
	
	if (import_key != NULL)
	{// verify the key is not empty - note from SAFE review
		sgx_aes_gcm_128bit_key_t empty_aes_key = {0};
		if (consttime_memequal(import_key, &empty_aes_key, sizeof(sgx_aes_gcm_128bit_key_t)) == 1)
		{
			last_error = EINVAL;
			return;
		}
	}
	//여기서 open_mode에 대입
	if (parse_mode(mode) == false)
	{
		last_error = EINVAL;
		return;
	}

	//파일 생성이냐 파일 오픈이냐 분리
	//diskshield에서는 이부분 제거.
	//Q1)file이 존재하는지 안존재하는지 diskshield는 어떻게 구현할까
	//A)disk가 알려주자!
	//이부분 지우고, open바로 떄리고, 만약 -1로 리턴오면 create하는걸로 구현할 계획.
	//status = u_sgxprotectedfs_check_if_file_exists(&result, filename); // if result == 1 --> file exists
	if (status != SGX_SUCCESS)
	{
		last_error = status;
		return;
	}
	//open_mode.write가 1이면 존재하는 파일 지워야 (파일 생성 모드인듯. 누가 설정하지?)
	//이건 기존 file system api와 같게 행동하는거임
	//write모드라면 (존재한다면)지우고 다시써야지.
	//remove구현할때까지 통 주석 diskshield
	/*
	if (open_mode.write == 1 && result == 1)
	{// try to delete existing file
		int32_t saved_errno = 0;

		result32 = remove(filename);	//Q2)DiskShield가 remove를 구현해야겠네
		if (result32 != 0)
		{
			// either can't delete or the file was already deleted by someone else
			saved_errno = errno;
			errno = 0;
		}

		// re-check	잘지워졌나 확인해야지
		status = u_sgxprotectedfs_check_if_file_exists(&result, filename);
		if (status != SGX_SUCCESS || result == 1)
		{
			last_error = (status != SGX_SUCCESS) ? status :
						 (saved_errno != 0) ? saved_errno : EACCES;
			return;
		}
	}
	*/
	/*
	//open_mode.read는 파일 오픈 모드인듯
	if (open_mode.read == 1 && result == 0)
	{// file must exists
		last_error = ENOENT;
		return;
	}

	if (import_key != NULL && result == 0)
	{// file must exists - otherwise the user key is not used
		last_error = ENOENT;
		return;
	}
*/
	// now open the file
	// 어러 인클레이브가 한 파일을 읽을 수 있다.
	// r아마 쓰기는 동시에 못할듯.
	// 글로벌해보이는 open_mode는 사실, 이 객체(file 객체의 변수임!)
	read_only = (open_mode.read == 1 && open_mode.update == 0); // read only files can be opened simultaneously by many enclaves

	do {
		//파일 오픈
		//Q3) diskshield가 본격적으로 open을 해야지
		//mac 계산
		//DS_make_mac(DS_OPEN_WR, DS_key, DS_mac, buf, buf_size);
		//임시
		//DS_version=1;
		//sgx_read_rand((unsigned char*)&DS_version, 4);
		DS_version=1;	//무의미하다 open시 실제 버전정보는 전달하지 않음. 나중에 수정될 사항
		/*
		for(int i=0; i<32; i++)
			DS_mac[i]=0xaa;
		*/
		//status = u_protectedfs_exclusive_file_open(&file, filename, read_only, &real_file_size, &result32, DS_mac, &DS_version);
		//일단 이렇게 설정(임시)		
		/*
		int i;

		for(i=0; i<16; i++)
			DS_key[i] = 0xaa;
		*/

		generate_diskshield_key();

		//일단 key 고정해야함
		for(int i=0; i<16; i++)
			DS_key[i]=1;



		unsigned char buf[16+1+16];
		int buf_size=16+1+4;
		//unsigned int cmd=DS_OPEN_WR;
		memcpy(buf, clean_filename, 16); 
		buf[16] = DS_OPEN_WR;
		memcpy(&buf[17], &DS_version, 4);
		//memcpy(&buf[4], &cmd, 4);
		
		HMAC(DS_key, DS_mac, buf, buf_size);

		status = u_diskshieldfs_exclusive_file_open(&DS_fd, clean_filename, &result32, DS_mac, &DS_version, response, NULL);
		
		if(DS_fd !=FILE_NOT_EXISTS && hmac_authentication(DS_OPEN_WR)==0)
		{
			last_error=EPERM;
			return;
			//DS_fd = FILE_AUTH_FAIL;	//인증 실패 error
		}
		//받았으니 한번 더 HMAC인증해야.
		//
		//여기서 create와 비교해야하는데 비교방법
		//1. disk로부터받아온다.
		//2. XXXXversion이 0으로 초기화되어있다 XXXXX
		//status = SGX_SUCCESS; //일단 이렇게

		//DS_fd = -1;
		if(DS_fd==FILE_NOT_EXISTS)	//file not exists
		{
			sgx_enclave_id_t src_id, dest_id;
			src_id = 1;
			dest_id = 2;
			uint8_t encrypted_key[KEY_SIZE];

			//if session already created, then just return.
			test_create_session(src_id, dest_id);

			test_enclave_to_enclave_call(src_id, dest_id, DS_key, encrypted_key);

			buf_size = 16+1+16;
			buf[16] = DS_CREATE_WR;
			memcpy(&buf[17], DS_key, 16);
			HMAC(DS_key, DS_mac, buf, buf_size);
			//file create
			status = u_diskshieldfs_exclusive_file_open(&DS_fd, clean_filename, &result32, DS_mac, &DS_version, response, DS_key);
			
		
			if(hmac_authentication(DS_CREATE_WR)==0)
			{
				last_error=EPERM;
				return;
				//DS_fd = FILE_AUTH_FAIL;	//인증 실패 error
			}
			
			/*		
			//file create!
			//일단 리턴하자
			//그런데 key값도 리턴해줘야함.
			//file_status = SGX_FILE_STATUS_OK;
			//fd = u_diskshieldfs_exclusive_file_create.....
			//break;
			//1. Authentiaciton Eclave (AE) attestation -> we should know whether the attestation already finished.

			//2. get the MAC and encrypted per-file key from AE

			//3. file creation request
			status = u_diskshieldfs_exclusive_file_create(&DS_fd, clean_filename, &result32, DS_mac, &DS_version, response);
*/
		}
		//status = u_sgxprotectedfs_exclusive_file_open(&file, filename, read_only, &real_file_size, &result32);
		if (status != SGX_SUCCESS || DS_fd<0)//file == NULL)
		{
			last_error = (status != SGX_SUCCESS) ? status :
					     (result32 != 0) ? result32 : EACCES;
			break;
		}

		if (real_file_size < 0)
		{
			last_error = EINVAL;
			break;
		}

		if (real_file_size % NODE_SIZE != 0)
		{
			last_error = SGX_ERROR_FILE_NOT_SGX_FILE;
			break;
		}
		//recovery file은 일단 bypass한다.
		//recovery_filename
		strncpy(recovery_filename, filename, FULLNAME_MAX_LEN - 1); // copy full file name
		recovery_filename[FULLNAME_MAX_LEN - 1] = '\0'; // just to be safe
		size_t full_name_len = strnlen(recovery_filename, RECOVERY_FILE_MAX_LEN);
		strncpy(&recovery_filename[full_name_len], "_recovery", 10);

		//파일이 creation됐는지 open됏는지 이렇게구별이 되겠군.
		if (real_file_size > 0)
		{// existing file
			/*
			if (open_mode.write == 1) // redundant check, just in case
			{
				last_error = EACCES;
				break;
			}
			*/
				//existing일 경우 초기화
			if (init_existing_file(filename, clean_filename, import_key) == false)
				break;
				
			if (open_mode.append == 1 && open_mode.update == 0)
				offset = encrypted_part_plain.size;	//이 offset이 내가 생각하는 offset이 맞는지 체크 맞을듯
		}
		else
		{// new file
			//new file일경우 초기화
			if (init_new_file(clean_filename) == false)
				break;
		}

		file_status = SGX_FILE_STATUS_OK;

	} while(0);

	//잘못된 상황임
	/*
	if (file_status != SGX_FILE_STATUS_OK)
	{
		if (file != NULL)
		{
			u_sgxprotectedfs_fclose(&result32, file); // we don't care about the result
			file = NULL;
		}
	}
	*/
}


void protected_fs_file::init_fields()
{
	meta_data_node_number = 0;
	memset(&file_meta_data, 0, sizeof(meta_data_node_t));
	memset(&encrypted_part_plain, 0, sizeof(meta_data_encrypted_t));

	memset(&empty_iv, 0, sizeof(sgx_iv_t));

	memset(&root_mht, 0, sizeof(file_mht_node_t));
	root_mht.type = FILE_MHT_NODE_TYPE;
	root_mht.physical_node_number = 1;
	root_mht.mht_node_number = 0;
	root_mht.new_node = true;
	root_mht.need_writing = false;
	
	offset = 0;
	file = NULL;
	end_of_file = false;
	need_writing = false;
	read_only = 0;
	file_status = SGX_FILE_STATUS_NOT_INITIALIZED;
	last_error = SGX_SUCCESS;
	real_file_size = 0;	
	open_mode.raw = 0;
	use_user_kdk_key = 0;
	master_key_count = 0;

	recovery_filename[0] = '\0';
	
	memset(&mutex, 0, sizeof(sgx_thread_mutex_t));

	// set hash size to fit MAX_PAGES_IN_CACHE
	cache.rehash(MAX_PAGES_IN_CACHE);

}
//authentication enclave init
/*
uint32_t protected_fs_file::test_create_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;

    //Core reference code function for creating a session
    ke_status = create_session(src_enclave_id, dest_enclave_id, &dest_session_info);

    //Insert the session information into the map under the corresponding destination enclave id
    if(ke_status == SUCCESS)
    {
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
}

uint32_t protected_fs_file::test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, char* name, uint8_t *key)
//uint32_t test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id,
  //                                        sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t var1,var2;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char* retval;



    var1 = 0x4;
    var2 = 0x5;
    target_fn_id = 0;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 50;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_foo1(target_fn_id, msg_type, var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
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
    ke_status = unmarshal_retval_and_output_parameters_e2_foo1(out_buff, &retval);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;
}
*/
#define MAX_MODE_STRING_LEN 5
bool protected_fs_file::parse_mode(const char* mode)
{
	if (mode == NULL) // re-check
		return false;

	size_t mode_len = strnlen(mode, MAX_MODE_STRING_LEN+1);
	if (mode_len > MAX_MODE_STRING_LEN)
		return false;

	for (size_t i = 0 ; i < mode_len ; i++)
	{
		switch (mode[i])
		{
		case 'r':
			if (open_mode.write == 1 || open_mode.read == 1 || open_mode.append == 1)
				return false;
			open_mode.read = 1;
			break;
		case 'w':
			if (open_mode.write == 1 || open_mode.read == 1 || open_mode.append == 1)
				return false;
			open_mode.write = 1;
			break;
		case 'a':
			if (open_mode.write == 1 || open_mode.read == 1 || open_mode.append == 1)
				return false;
			open_mode.append = 1;
			break;
		case 'b':
			if (open_mode.binary == 1)
				return false;
			open_mode.binary = 1;
			break;
		case '+':
			if (open_mode.update == 1)
				return false;
			open_mode.update = 1;
			break;
		default:
			return false;
		}
	}

	if (open_mode.write == 0 && open_mode.read == 0 && open_mode.append == 0)
		return false;

	return true;
}


bool protected_fs_file::file_recovery(const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	int32_t result32 = 0;
	int64_t new_file_size = 0;

	status = u_sgxprotectedfs_fclose(&result32, file);
	if (status != SGX_SUCCESS || result32 != 0)
	{
		last_error = (status != SGX_SUCCESS) ? status : 
					 (result32 != -1) ? result32 : EINVAL;
		return false;
	}

	file = NULL;

	status = u_sgxprotectedfs_do_file_recovery(&result32, filename, recovery_filename, NODE_SIZE);
	if (status != SGX_SUCCESS || result32 != 0)
	{
		last_error = (status != SGX_SUCCESS) ? status :
					 (result32 != -1) ? result32 : EINVAL;
		return false;
	}

	status = u_sgxprotectedfs_exclusive_file_open(&file, filename, read_only, &new_file_size, &result32);
	if (status != SGX_SUCCESS || file == NULL)
	{
		last_error = (status != SGX_SUCCESS) ? status : 
					 (result32 != 0) ? result32 : EACCES;
		return false;
	}

	// recovery only change existing data, it does not shrink or grow the file
	if (new_file_size != real_file_size)
	{
		last_error = SGX_ERROR_UNEXPECTED;
		return false;
	}

	status = u_sgxprotectedfs_fread_node(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE);
	if (status != SGX_SUCCESS || result32 != 0)
	{
		last_error = (status != SGX_SUCCESS) ? status : 
					 (result32 != -1) ? result32 : EIO;
		return false;
	}

	return true;
}


bool protected_fs_file::init_existing_file(const char* filename, const char* clean_filename, const sgx_aes_gcm_128bit_key_t* import_key)
{
	sgx_status_t status;
	int32_t result32;

	// read meta-data node
	// diskshield 수정부위
	//status = u_sgxprotectedfs_fread_node(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE);
	//HMAC mac 생성
	//DS_make_mac(DS_OPEN_WR, DS_key, DS_mac, buf, buf_size);
	char a = filename[0];
	a=a;

	//uint32_t version;
	//status = u_diskshieldfs_fread_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &version);
	status = u_diskshieldfs_fread_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE);
	//hmac_authentication_for_read((uint8_t*)&file_meta_data, NODE_SIZE, 0, version);
	if (status != SGX_SUCCESS || result32 != 0)
	{
		last_error = (status != SGX_SUCCESS) ? status : 
					 (result32 != -1) ? result32 : EIO;
		return false;
	}

	if (file_meta_data.plain_part.file_id != SGX_FILE_ID)
	{// such a file exists, but it is not an SGX file
		last_error = SGX_ERROR_FILE_NOT_SGX_FILE;
		return false;
	}

	if (file_meta_data.plain_part.major_version != SGX_FILE_MAJOR_VERSION)
	{
		last_error = ENOTSUP;
		return false;
	}
	//file_name[0]=file_name[0];
	//diskshield recovery file 아직
	//recovery주석제거
	if (file_meta_data.plain_part.update_flag == 1)
	{// file was in the middle of an update, must do a recovery
		//file 손상 체크 및 recovery를 이때함.
		if (file_recovery(filename) == false)
		{// override internal error
			last_error = SGX_ERROR_FILE_RECOVERY_NEEDED;
			return false;
		}

		if (file_meta_data.plain_part.update_flag == 1) // recovery failed, flag is still set!
		{// recovery didn't clear the flag
			last_error = SGX_ERROR_FILE_RECOVERY_NEEDED;
			return false;
		}

		// re-check after recovery
		if (file_meta_data.plain_part.major_version != SGX_FILE_MAJOR_VERSION)
		{
			last_error = ENOTSUP;
			return false;
		}
	}



	if (file_meta_data.plain_part.use_user_kdk_key != use_user_kdk_key)
	{
		last_error = EINVAL;
		return false;
	}
	
	//cur_key를 여기서 할당한다
	if (restore_current_meta_data_key(import_key) == false)
		return false;

	// decrypt the encrypted part of the meta-data
	status = sgx_rijndael128GCM_decrypt(&cur_key, 
										(const uint8_t*)file_meta_data.encrypted_part, sizeof(meta_data_encrypted_blob_t), (uint8_t*)&encrypted_part_plain,
										empty_iv, SGX_AESGCM_IV_SIZE,
										NULL, 0,
										&file_meta_data.plain_part.meta_data_gmac);
	if (status != SGX_SUCCESS)
	{
		last_error = status;
		return false;
	}

	if (strncmp(clean_filename, encrypted_part_plain.clean_filename, FILENAME_MAX_LEN) != 0)
	{
		last_error = SGX_ERROR_FILE_NAME_MISMATCH;
		return false;
	}

/*
	sgx_mc_uuid_t empty_mc_uuid = {0};

	// check if the file contains an active monotonic counter
	if (consttime_memequal(&empty_mc_uuid, &encrypted_part_plain.mc_uuid, sizeof(sgx_mc_uuid_t)) == 0)
	{
		uint32_t mc_value = 0;

		status = sgx_read_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
		if (status != SGX_SUCCESS)
		{
			last_error = status;
			return false;
		}

		if (encrypted_part_plain.mc_value < mc_value)
		{
			last_error = SGX_ERROR_FILE_MONOTONIC_COUNTER_IS_BIGGER;
			return false;
		}

		if (encrypted_part_plain.mc_value == mc_value + 1) // can happen if AESM failed - file value stayed one higher
		{
			sgx_status_t status = sgx_increment_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
			if (status != SGX_SUCCESS)
			{
				file_status = SGX_FILE_STATUS_MC_NOT_INCREMENTED;
				last_error = status;
				return false;
			}
		}

		if (encrypted_part_plain.mc_value != mc_value)
		{
			file_status = SGX_FILE_STATUS_CORRUPTED;
			last_error = SGX_ERROR_UNEXPECTED;
			return false;
		}
	}
	else
	{
		assert(encrypted_part_plain.mc_value == 0);
		encrypted_part_plain.mc_value = 0; // do this anyway for release...
	}
*/
	if (encrypted_part_plain.size > MD_USER_DATA_SIZE)
	{
		// read the root node of the mht
		//diskshield
		//HMAC mac 생성
		//DS_make_mac(DS_OPEN_WR, DS_key, DS_mac, buf, buf_size);
		//status = u_sgxprotectedfs_fread_node(&result32, file, 1, root_mht.encrypted.cipher, NODE_SIZE);
		//uint32_t version;
		//status = u_diskshieldfs_fread_node(&result32, DS_fd, 1, root_mht.encrypted.cipher, NODE_SIZE, DS_mac, &version);
		status = u_diskshieldfs_fread_node(&result32, DS_fd, 1, root_mht.encrypted.cipher, NODE_SIZE);
		//hmac_authentication_for_read(root_mht.encrypted.cipher, NODE_SIZE, 1, version);
	
		if (status != SGX_SUCCESS || result32 != 0)
		{
			last_error = (status != SGX_SUCCESS) ? status : 
						 (result32 != -1) ? result32 : EIO;
			return false;
		}

		// this also verifies the root mht gmac against the gmac in the meta-data encrypted part
		status = sgx_rijndael128GCM_decrypt(&encrypted_part_plain.mht_key, 
											root_mht.encrypted.cipher, NODE_SIZE, (uint8_t*)&root_mht.plain, 
											empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &encrypted_part_plain.mht_gmac);
		if (status != SGX_SUCCESS)
		{
			last_error = status;
			return false;
		}

		root_mht.new_node = false;
	}

	return true;
}


bool protected_fs_file::init_new_file(const char* clean_filename)
{
	file_meta_data.plain_part.file_id = SGX_FILE_ID;
	file_meta_data.plain_part.major_version = SGX_FILE_MAJOR_VERSION;
	file_meta_data.plain_part.minor_version = SGX_FILE_MINOR_VERSION;

	file_meta_data.plain_part.use_user_kdk_key = use_user_kdk_key;

	strncpy(encrypted_part_plain.clean_filename, clean_filename, FILENAME_MAX_LEN);
	
	need_writing = true;

	//diskshield
	//after call open...
	//무의미하다. create시 version생성은 SSD가한다. 추후 삭제예정
	DS_version = 1;
	for(int i=0; i<32; i++)
		DS_mac[i]=0xaa;
	//response 초기화 -> 최대 44바이트
	//response = (char* )malloc (sizeof(char)*(32+4+4+4));
	return true;
}


protected_fs_file::~protected_fs_file()
{
	void* data;
	
	while ((data = cache.get_last()) != NULL)
	{
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types, need to scrub the plaintext
		{
			file_data_node_t* file_data_node = (file_data_node_t*)data;
			memset_s(&file_data_node->plain, sizeof(data_node_t), 0, sizeof(data_node_t));
			delete file_data_node;
		}
		else
		{
			file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
			memset_s(&file_mht_node->plain, sizeof(mht_node_t), 0, sizeof(mht_node_t));
			delete file_mht_node;
		}
		cache.remove_last();
	}

	// scrub the last encryption key and the session key
	memset_s(&cur_key, sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t));
	memset_s(&session_master_key, sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t));
	
	// scrub first 3KB of user data and the gmac_key
	memset_s(&encrypted_part_plain, sizeof(meta_data_encrypted_t), 0, sizeof(meta_data_encrypted_t));

	sgx_thread_mutex_destroy(&mutex);
}


bool protected_fs_file::pre_close(sgx_key_128bit_t* key, bool import)
{
	int32_t result32 = 0;
	bool retval = true;
	sgx_status_t status = SGX_SUCCESS;

	sgx_thread_mutex_lock(&mutex);

	if (import == true)
	{
		if (use_user_kdk_key == 1) // import file is only needed for auto-key
			retval = false;
		else
			need_writing = true; // will re-encrypt the neta-data node with local key
	}

	if (file_status != SGX_FILE_STATUS_OK)
	{
		sgx_thread_mutex_unlock(&mutex);
		clear_error(); // last attempt to fix it
		sgx_thread_mutex_lock(&mutex);
	}
	else // file_status == SGX_FILE_STATUS_OK
	{
		internal_flush(/*false,*/ true);
	}

	if (file_status != SGX_FILE_STATUS_OK)
		retval = false;
	//close diskshield도 구현
	if (DS_fd>0)
	//if (file != NULL)
	{
		//Diskshield
		//HMAC
		
		unsigned char buf[4+1+4];
		int buf_size=4+1+4;
		//DS_version++;
		//unsigned int cmd=DS_CLOSE_WR;
		memcpy(buf, &DS_version, 4);
		//memcpy(&buf[4], &cmd, 4);
		buf[4] = DS_CLOSE_WR;
		memcpy(&buf[5], &DS_fd, 4); 

		HMAC(DS_key, DS_mac, buf, buf_size);
		status = u_diskshieldfs_fclose(&result32, DS_fd, DS_mac, &DS_version, response);
		
		
		if(hmac_authentication(DS_CLOSE_WR)==0)
		{
			//Error
			retval = false;

			;
		}
		//
		//
		//status = u_sgxprotectedfs_fclose(&result32, file);
		if (status != SGX_SUCCESS || result32 != 0)
		{
			last_error = (status != SGX_SUCCESS) ? status : 
						 (result32 != -1) ? result32 : SGX_ERROR_FILE_CLOSE_FAILED;
			retval = false;
		}

		file = NULL;
	}
	//recovery file은 open~close사이에만 존재하는구나
	/*
	if (file_status == SGX_FILE_STATUS_OK && 
		last_error == SGX_SUCCESS) // else...maybe something bad happened and the recovery file will be needed
		erase_recovery_file();
	*/	
	if (key != NULL)
	{
		if (use_user_kdk_key == 1) // export key is only used for auto-key
		{
			retval = false;
		}
		else
		{
			if (restore_current_meta_data_key(NULL) == true)
				memcpy(key, cur_key, sizeof(sgx_key_128bit_t));
			else
				retval = false;
		}
	}

	file_status = SGX_FILE_STATUS_CLOSED;

	sgx_thread_mutex_unlock(&mutex);

	return retval;
}

