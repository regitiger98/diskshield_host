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
#include <tprotected_fs.h>
//#include <stdio.h>

#include <sgx_trts.h>

extern ISC _ISC;

bool protected_fs_file::flush(/*bool mc*/)
{
	bool result = false;

	int32_t result32 = sgx_thread_mutex_lock(&mutex);
	if (result32 != 0)
	{
		last_error = result32;
		file_status = SGX_FILE_STATUS_MEMORY_CORRUPTED;
		return false;
	}

	if (file_status != SGX_FILE_STATUS_OK)
	{
		last_error = SGX_ERROR_FILE_BAD_STATUS;
		sgx_thread_mutex_unlock(&mutex);
		return false;
	}
	
	result = internal_flush(/*mc,*/ true);
	if (result == false)
	{
		assert(file_status != SGX_FILE_STATUS_OK);
		if (file_status == SGX_FILE_STATUS_OK)
			file_status = SGX_FILE_STATUS_FLUSH_ERROR; // for release set this anyway
	}

	if(_ISC.isc_flush(DS_fd, &last_error) == false)
	{
		file_status = SGX_FILE_STATUS_FLUSH_ERROR;
	}

	sgx_thread_mutex_unlock(&mutex);

	return result;
}


bool protected_fs_file::internal_flush(/*bool mc,*/ bool flush_to_disk)
{
	if (need_writing == false) // no changes at all
		return true;

/*
	if (mc == true && encrypted_part_plain.mc_value > (UINT_MAX-2))
	{
		last_error = SGX_ERROR_FILE_MONOTONIC_COUNTER_AT_MAX;
		return false;
	}
*/
	if (encrypted_part_plain.size > MD_USER_DATA_SIZE && root_mht.need_writing == true) // otherwise it's just one write - the meta-data node
	{
		if (_RECOVERY_HOOK_(0) || write_recovery_file() != true)
		{
			file_status = SGX_FILE_STATUS_FLUSH_ERROR;
			return false;
		}

		if (_RECOVERY_HOOK_(1) || set_update_flag(flush_to_disk) != true)
		{
			file_status = SGX_FILE_STATUS_FLUSH_ERROR;
			return false;
		}

		if (_RECOVERY_HOOK_(2) || update_all_data_and_mht_nodes() != true)
		{
			clear_update_flag();
			file_status = SGX_FILE_STATUS_CRYPTO_ERROR; // this is something that shouldn't happen, can't fix this...
			return false;
		}
	}

/*
	sgx_status_t status;

	if (mc == true)
	{
		// increase monotonic counter local value - only if everything is ok, we will increase the real counter
		if (encrypted_part_plain.mc_value == 0)
		{
			// no monotonic counter so far, need to create a new one
			status = sgx_create_monotonic_counter(&encrypted_part_plain.mc_uuid, &encrypted_part_plain.mc_value);
			if (status != SGX_SUCCESS)
			{
				clear_update_flag();
				file_status = SGX_FILE_STATUS_FLUSH_ERROR;
				last_error = status;
				return false;
			}
		}
		encrypted_part_plain.mc_value++;
	}
*/
	if (_RECOVERY_HOOK_(3) || update_meta_data_node() != true)
	{
		clear_update_flag();
		/*
		if (mc == true)
			encrypted_part_plain.mc_value--; // don't have to do this as the file cannot be fixed, but doing it anyway to prevent future errors
		*/
		file_status = SGX_FILE_STATUS_CRYPTO_ERROR; // this is something that shouldn't happen, can't fix this...
		return false;
	}

	if (_RECOVERY_HOOK_(4) || write_all_changes_to_disk(flush_to_disk) != true)
	{
		//if (mc == false)
			file_status = SGX_FILE_STATUS_WRITE_TO_DISK_FAILED; // special case, need only to repeat write_all_changes_to_disk in order to repair it
		//else
			//file_status = SGX_FILE_STATUS_WRITE_TO_DISK_FAILED_NEED_MC; // special case, need to repeat write_all_changes_to_disk AND increase the monotonic counter in order to repair it

		return false;
	}

	need_writing = false;

/* this is causing problems when we delete and create the file rapidly
   we will just leave the file, and re-write it every time
   u_sgxprotectedfs_recovery_file_open opens it with 'w' so it is truncated
	if (encrypted_part_plain.size > MD_USER_DATA_SIZE)
	{
		erase_recovery_file();
	}
*/
/*
	if (mc == true)
	{
		uint32_t mc_value;
		status = sgx_increment_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
		if (status != SGX_SUCCESS)
		{
			file_status = SGX_FILE_STATUS_MC_NOT_INCREMENTED; // special case - need only to increase the MC in order to repair it
			last_error = status;
			return false;
		}
		assert(mc_value == encrypted_part_plain.mc_value);
	}
*/
	return true;
}


bool protected_fs_file::write_recovery_file()
{
	void* recovery_file = NULL;
	sgx_status_t status;
	uint8_t result = 0;
	int32_t result32 = 0;

	status = u_sgxprotectedfs_recovery_file_open(&recovery_file, recovery_filename);
	if (status != SGX_SUCCESS || recovery_file == NULL)
	{
		last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE;
		return false;
	}

	void* data = NULL;
	recovery_node_t* recovery_node = NULL;

	for (data = cache.get_first() ; data != NULL ; data = cache.get_next())
	{
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			file_data_node_t* file_data_node = (file_data_node_t*)data;
			if (file_data_node->need_writing == false || file_data_node->new_node == true)
				continue;

			recovery_node = &file_data_node->recovery_node;
		}
		else
		{
			file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
			assert(file_mht_node->type == FILE_MHT_NODE_TYPE);
			if (file_mht_node->need_writing == false || file_mht_node->new_node == true)
				continue;

			recovery_node = &file_mht_node->recovery_node;
		}

		status = u_sgxprotectedfs_fwrite_recovery_node(&result, recovery_file, (uint8_t*)recovery_node, sizeof(recovery_node_t));
		if (status != SGX_SUCCESS || result != 0)
		{
			u_sgxprotectedfs_fclose(&result32, recovery_file);
			u_sgxprotectedfs_remove(&result32, recovery_filename);
			last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE;
			return false;
		}
	}

	if (root_mht.need_writing == true && root_mht.new_node == false)
	{
		status = u_sgxprotectedfs_fwrite_recovery_node(&result, recovery_file, (uint8_t*)&root_mht.recovery_node, sizeof(recovery_node_t));
		if (status != SGX_SUCCESS || result != 0)
		{
			u_sgxprotectedfs_fclose(&result32, recovery_file);
			u_sgxprotectedfs_remove(&result32, recovery_filename);
			last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE;
			return false;
		}
	}

	status = u_sgxprotectedfs_fwrite_recovery_node(&result, recovery_file, (uint8_t*)&meta_data_recovery_node, sizeof(recovery_node_t));
	if (status != SGX_SUCCESS || result != 0)
	{
		u_sgxprotectedfs_fclose(&result32, recovery_file);
		u_sgxprotectedfs_remove(&result32, recovery_filename);
		last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE;
		return false;
	}

	u_sgxprotectedfs_fclose(&result32, recovery_file); // TODO - check result

	return true;
}


bool protected_fs_file::set_update_flag(bool flush_to_disk)
{
	//sgx_status_t status;
	///uint8_t result;
	//int32_t result32;
	//ecdsa
	//sgx_ec256_signature_t p_signature;
	//uint8_t p_sig;
//prnt("DSFS: set_update_flag\n");

	file_meta_data.plain_part.update_flag = 1;
	//ecdsa
	//ecdsa_sign((uint8_t*)&file_meta_data,NODE_SIZE, &p_signature);
	//memcpy(&p_sig, &p_signature, 64);
	//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE,&p_sig);
	//status = u_sgxprotectedfs_fwrite_node(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE);
	//buffer, size, offset만보내주면됨
	
	make_hmac_for_write((uint8_t*)&file_meta_data, NODE_SIZE, 0);	
	if(_ISC.isc_put(DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, DS_key, &last_error) == false)
	{
		return false;
	}

	//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, response);
	//hmac_authentication(DS_WRITE_WR);
	//hmac_authentication(DS_WRITE_WR, (uint8_t*)&file_meta_data, NODE_SIZE, DS_version);
//int32_t u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
	
	file_meta_data.plain_part.update_flag = 0; // turn it off in memory. at the end of the flush, when we'll write the meta-data to disk, this flag will also be cleared there.
	/*
	if (status != SGX_SUCCESS || result32 != 0)
	{
		last_error = (status != SGX_SUCCESS) ? status : 
					 (result32 != -1) ? result32 : EIO;
		return false;
	}
	*/

	flush_to_disk = flush_to_disk;

	//we don't have toflush because it is direlty write to disk
	/*
	if (flush_to_disk == true)
	{
		status = u_sgxprotectedfs_fflush(&result, file);
		if (status != SGX_SUCCESS || result != 0)
		{
			last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_FLUSH_FAILED;
	
			//ecdsa_sign((uint8_t*)&file_meta_data,NODE_SIZE, &p_signature);
			//memcpy(&p_sig, &p_signature, 64);
			//u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE,&p_sig);
			//u_sgxprotectedfs_fwrite_node(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE); // try to clear the update flag, in the OS cache at least...
			//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version);
			make_hmac_for_write((uint8_t*)&file_meta_data, NODE_SIZE, 0);	
			status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, response);
			hmac_authentication(DS_WRITE_WR);
			
			//u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
			
			
			return false;
		}

	}
*/
	return true;
}


// this function is called if we had an error after we updated the update flag
// in normal flow, the flag is cleared when the meta-data is written to disk
void protected_fs_file::clear_update_flag()
{
	//uint8_t result;
	//int32_t result32;
	//ecdsaa
	//sgx_ec256_signature_t p_signature;
	//uint8_t p_sig;
//printf("DSFS : clear_update_flag\n");
	if (_RECOVERY_HOOK_(3))
		return;
	assert(file_meta_data.plain_part.update_flag == 0);
	//ecdsa
	//ecdsa_sign((uint8_t*)&file_meta_data,NODE_SIZE, &p_signature);
	//memcpy(&p_sig, &p_signature, 64);
	//u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE,&p_sig);
	//u_sgxprotectedfs_fwrite_node(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE);
	//u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version);
	
	make_hmac_for_write((uint8_t*)&file_meta_data, NODE_SIZE, 0);	
	_ISC.isc_put(DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, DS_key, &last_error);

	//u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, response);
	//hmac_authentication(DS_WRITE_WR);
	//u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
	
	//flush는 필요없다.
	//u_sgxprotectedfs_fflush(&result, file);
}


// sort function, we need the mht nodes sorted before we start to update their gmac's
bool mht_order(const file_mht_node_t* first, const file_mht_node_t* second)
{// higher (lower tree level) node number first
	return first->mht_node_number > second->mht_node_number;
}


bool protected_fs_file::update_all_data_and_mht_nodes()
{
	std::list<file_mht_node_t*> mht_list;
	std::list<file_mht_node_t*>::iterator mht_list_it;
	file_mht_node_t* file_mht_node;
	sgx_status_t status;
	void* data = cache.get_first();

	// 1. encrypt the changed data
	// 2. set the IV+GMAC in the parent MHT
	// [3. set the need_writing flag for all the parents]
	while (data != NULL)
	{
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			file_data_node_t* data_node = (file_data_node_t*)data;

			if (data_node->need_writing == true)
			{
				if (derive_random_node_key(data_node->physical_node_number) == false)
					return false;

				gcm_crypto_data_t* gcm_crypto_data = &data_node->parent->plain.data_nodes_crypto[data_node->data_node_number % ATTACHED_DATA_NODES_COUNT];

				// encrypt the data, this also saves the gmac of the operation in the mht crypto node
				status = sgx_rijndael128GCM_encrypt(&cur_key, data_node->plain.data, NODE_SIZE, data_node->encrypted.cipher, 
													empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &gcm_crypto_data->gmac);
				if (status != SGX_SUCCESS)
				{
					last_error = status;
					return false;
				}

				memcpy(gcm_crypto_data->key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this encryption

				file_mht_node = data_node->parent;
				// this loop should do nothing, add it here just to be safe
				while (file_mht_node->mht_node_number != 0)
				{
					assert(file_mht_node->need_writing == true);
					file_mht_node->need_writing = true; // just in case, for release
					file_mht_node = file_mht_node->parent;
				}
			}
		}
		data = cache.get_next();
	}

	// add all the mht nodes that needs writing to a list
	data = cache.get_first();
	while (data != NULL)
	{
		if (((file_mht_node_t*)data)->type == FILE_MHT_NODE_TYPE) // type is in the same offset in both node types
		{
			file_mht_node = (file_mht_node_t*)data;

			if (file_mht_node->need_writing == true)
				mht_list.push_front(file_mht_node);
		}

		data = cache.get_next();
	}

	// sort the list from the last node to the first (bottom layers first)
	mht_list.sort(mht_order);

	// update the gmacs in the parents
	while ((mht_list_it = mht_list.begin()) != mht_list.end())
	{
		file_mht_node = *mht_list_it;

		gcm_crypto_data_t* gcm_crypto_data = &file_mht_node->parent->plain.mht_nodes_crypto[(file_mht_node->mht_node_number - 1) % CHILD_MHT_NODES_COUNT];

		if (derive_random_node_key(file_mht_node->physical_node_number) == false)
		{
			mht_list.clear();
			return false;
		}

		status = sgx_rijndael128GCM_encrypt(&cur_key, (const uint8_t*)&file_mht_node->plain, NODE_SIZE, file_mht_node->encrypted.cipher, 
											empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &gcm_crypto_data->gmac);
		if (status != SGX_SUCCESS)
		{
			mht_list.clear();
			last_error = status;
			return false;
		}

		memcpy(gcm_crypto_data->key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this gmac

		mht_list.pop_front();
	}

	// update mht root gmac in the meta data node
	if (derive_random_node_key(root_mht.physical_node_number) == false)
		return false;

	status = sgx_rijndael128GCM_encrypt(&cur_key, (const uint8_t*)&root_mht.plain, NODE_SIZE, root_mht.encrypted.cipher, 
										empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &encrypted_part_plain.mht_gmac);
	if (status != SGX_SUCCESS)
	{
		last_error = status;
		return false;
	}

	memcpy(&encrypted_part_plain.mht_key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this gmac

	return true;
}


bool protected_fs_file::update_meta_data_node()
{
	sgx_status_t status;
	
	// randomize a new key, saves the key _id_ in the meta data plain part
	if (generate_random_meta_data_key() != true)
	{
		// last error already set
		return false;
	}
		
	// encrypt meta data encrypted part, also updates the gmac in the meta data plain part
	status = sgx_rijndael128GCM_encrypt(&cur_key, 
										(const uint8_t*)&encrypted_part_plain, sizeof(meta_data_encrypted_t), (uint8_t*)&file_meta_data.encrypted_part, 
										empty_iv, SGX_AESGCM_IV_SIZE, 
										NULL, 0, 
										&file_meta_data.plain_part.meta_data_gmac);
	if (status != SGX_SUCCESS)
	{
		last_error = status;
		return false;
	}

	return true;
}


bool protected_fs_file::write_all_changes_to_disk(bool flush_to_disk)
{
	//uint8_t result;
	//int32_t result32=0;
	//sgx_status_t status;
	//ecdsa
	//sgx_ec256_signature_t p_signature;
	//uint8_t p_sig;
	//memset(&p_signature, 0x00, 64);
	//static int i=0;
	
	/*
	//ecdsa
	if(i==0)
	{
		//최초에만 키생성
		ecdsa_make_key();
		i++;
	}
	*/
//printf("DSFS: write_all_chagnes_to_disk\n");
	if (encrypted_part_plain.size > MD_USER_DATA_SIZE && root_mht.need_writing == true)
	{
		void* data = NULL;
		uint8_t* data_to_write;
		uint64_t node_number=0;
		file_data_node_t* file_data_node;
		file_mht_node_t* file_mht_node;
		
		node_number=node_number;
		for (data = cache.get_first() ; data != NULL ; data = cache.get_next())
		{
			file_data_node = NULL;
			file_mht_node = NULL;

			if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
			{
				file_data_node = (file_data_node_t*)data;
				if (file_data_node->need_writing == false)
					continue;

				data_to_write = (uint8_t*)&file_data_node->encrypted;
				node_number = file_data_node->physical_node_number;
			}
			else
			{
				file_mht_node = (file_mht_node_t*)data;
				assert(file_mht_node->type == FILE_MHT_NODE_TYPE);
				if (file_mht_node->need_writing == false)
					continue;

				data_to_write = (uint8_t*)&file_mht_node->encrypted;
				node_number = file_mht_node->physical_node_number;
			}
			//DSFS
			//여기에 인증구현하자.
			//1. 암호화 2. HMAC돌리기 3. p-signatrue에 넣으면 끝. 
			uint8_t *p_src = data_to_write;
			uint32_t src_len = NODE_SIZE;
			uint8_t p_dst[8192];
			unsigned char key[16];	
			//unsigned char h_mac[32];
			int ii;
			for(ii=0; ii<16; ii++)	key[ii]=0x12;
			aes_ctr_encrypt(key,p_src,src_len,p_dst);
			
			//hmac(key, h_mac, p_dst, src_len); //이건 data만한거임. 차츰바꿔나가자

			//ecdsa_sign(data_to_write,NODE_SIZE, &p_signature);
			//memcpy(&p_sig, &p_signature, 64);
			//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, node_number, p_dst, NODE_SIZE,h_mac);
			//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, node_number, data_to_write, NODE_SIZE,&p_sig);
			//status = u_sgxprotectedfs_fwrite_node(&result32, file, node_number, data_to_write, NODE_SIZE);
			
			//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, node_number, data_to_write, NODE_SIZE, DS_mac, &DS_version);
			
			make_hmac_for_write(data_to_write, NODE_SIZE, node_number);	
			if(_ISC.isc_put(DS_fd, node_number, data_to_write, NODE_SIZE, DS_mac, &DS_version, DS_key, &last_error) == false)
			{
				return false;
			}
			//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, node_number, data_to_write, NODE_SIZE, DS_mac, &DS_version, response);
			//hmac_authentication(DS_WRITE_WR);
			
			//u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
			/*
			if (status != SGX_SUCCESS || result32 != 0)
			{
				last_error = (status != SGX_SUCCESS) ? status : 
							 (result32 != -1) ? result32 : EIO;
				return false;
			}
			*/

			// data written - clear the need_writing and the new_node flags (for future transactions, this node it no longer 'new' and should be written to recovery file)
			if (file_data_node != NULL)
			{
				file_data_node->need_writing = false;
				file_data_node->new_node = false;
			}
			else
			{
				file_mht_node->need_writing = false;
				file_mht_node->new_node = false;
			}

		}

		//ecdsa_sign((uint8_t*)&root_mht.encrypted,NODE_SIZE, &p_signature);
		//memcpy(&p_sig, &p_signature, 64);
		//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, 1, (uint8_t*)&root_mht.encrypted, NODE_SIZE,&p_sig);

	//	status = u_sgxprotectedfs_fwrite_node(&result32, file, 1, (uint8_t*)&root_mht.encrypted, NODE_SIZE);
		//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 1, (uint8_t*)&root_mht.encrypted, NODE_SIZE, DS_mac, &DS_version);
			//u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)

		make_hmac_for_write((uint8_t*)&root_mht.encrypted, NODE_SIZE, 1);
		if(_ISC.isc_put(DS_fd, 1, (uint8_t*)&root_mht.encrypted, NODE_SIZE, DS_mac, &DS_version, DS_key, &last_error) == false)
		{
			return false;
		}
		//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 1, (uint8_t*)&root_mht.encrypted, NODE_SIZE, DS_mac, &DS_version, response);
		//hmac_authentication(DS_WRITE_WR);
			
		/*
		if (status != SGX_SUCCESS || result32 != 0)
		{
			last_error = (status != SGX_SUCCESS) ? status : 
						 (result32 != -1) ? result32 : EIO;
			return false;
		}
		*/
		root_mht.need_writing = false;
		root_mht.new_node = false;
	}
	//ecdsa
	//ecdsa_sign((uint8_t*)&file_meta_data,NODE_SIZE, &p_signature);
	//memcpy(&p_sig, &p_signature, 64);
	//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE,&p_sig);
	//status = u_sgxprotectedfs_fwrite_node(&result32, file, 0, (uint8_t*)&file_meta_data, NODE_SIZE);
	//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version);
	
	make_hmac_for_write((uint8_t*)&file_meta_data, NODE_SIZE, 0);
	if(_ISC.isc_put(DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, DS_key, &last_error) == false)
	{
		return false;
	}
	//status = u_diskshieldfs_fwrite_node(&result32, DS_fd, 0, (uint8_t*)&file_meta_data, NODE_SIZE, DS_mac, &DS_version, response);
	//hmac_authentication(DS_WRITE_WR);
		
	
			//u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
	
			//u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
	/*
	if (status != SGX_SUCCESS || result32 != 0)
	{
		last_error = (status != SGX_SUCCESS) ? status : 
					 (result32 != -1) ? result32 : EIO;
		return false;
	}
	*/
	//flush 생략 diskshield
	
	
	if (flush_to_disk == true)
	{
		/*
		status = u_sgxprotectedfs_fflush(&result, file);
		if (status != SGX_SUCCESS || result != 0)
		{
			last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_FLUSH_FAILED;
			return false;
		}
		*/
	}

	return true;
}
void protected_fs_file::aes_ctr_encrypt(const unsigned char key[], uint8_t *p_src, uint32_t src_len, uint8_t *p_dst)
{
	uint8_t p_ctr[32];   
	uint32_t ctr_inc_bits = 1;
	sgx_aes_ctr_128bit_key_t p_key;
	memcpy(p_key, key, 16);
	for(int i=0; i<32; i++)
 		p_ctr[i]=0x11;   
	sgx_aes_ctr_encrypt(&p_key, p_src, src_len,p_ctr, ctr_inc_bits, p_dst);
}

void protected_fs_file::aes_ctr_decrypt(const unsigned char key[], uint8_t *p_src, uint32_t src_len, uint8_t *p_dst)
{
	uint8_t p_ctr[32];   
	uint32_t ctr_inc_bits = 1;
	sgx_aes_ctr_128bit_key_t p_key;
	memcpy(p_key, key, 16);
	for(int i=0; i<32; i++)
 		p_ctr[i]=0x11;   
	sgx_aes_ctr_decrypt(&p_key, p_src, src_len,p_ctr, ctr_inc_bits, p_dst);
}
/*
void protected_fs_file::hmac(const unsigned char key[], unsigned char h_mac[], const unsigned char text[], const int text_size)
{
	const unsigned char HASHED_OUTPUT=32;
	const unsigned char input_blocksize = 64;
	//const unsigned char KEY_SIZE=16;
	const unsigned char HASH_BLOCK_SIZE = 64;
    unsigned char Ki[HASH_BLOCK_SIZE] = {0,}; // K0 ^ ipad
    unsigned char Ko[HASH_BLOCK_SIZE] = {0,}; //K0 ^ opad
    const int DATA_BUFFERLEN = text_size + input_blocksize + HASHED_OUTPUT + 1;   //8192+64+32+1 =
    unsigned char data[DATA_BUFFERLEN];
    int i;
	sgx_sha256_hash_t p_hash;
   // SHA256_CTX ctx;

//    printf("key : %x %x %x %x \n", key[0],key[1],key[2],key[3]);
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(Ki, key, KEY_SIZE);
    memcpy(Ko, Ki, KEY_SIZE);        //Ko, Ki는 해쉬된 키값

//이후 B만큼 나머지 길이를 0으로 채운다 여기도 돌아갈일없음.
    for(i=KEY_SIZE; i<input_blocksize; i++)
    {
        Ki[i]=0x00;
        Ko[i]=0x00;
    }
    //ipad opad를 이용해서 Ko를 미리 계산한다.
    for(i=0; i<input_blocksize; i++)
    {
        Ki[i] ^= 0x36;
        Ko[i] ^= 0x5c;
    }
    //위에서 계산한 ;Ki ^ ipad와 HMAC대상인 test를 연접
    memcpy(data, Ki, input_blocksize);
    memcpy(data+input_blocksize, text, text_size);  //여기서 data길이 = 자른KI(64bit) + data임
    //해시한다.
    //printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Hash(data,input_blocksize + text_size,  h_mac, &ctx);  // O(hash(data size + 256biy))
	sgx_sha256_msg(data, input_blocksize+text_size, &p_hash);   
	//printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Ko ^ opad와 위에 해쉬 결과를 연접
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(data, Ko, input_blocksize);
    memcpy(data+input_blocksize, p_hash, HASHED_OUTPUT);   //여기서 data길이 = 64bit+256bit(hashed)
    sgx_sha256_msg(data, input_blocksize+HASHED_OUTPUT, &p_hash);
	memcpy(h_mac, p_hash, HASHED_OUTPUT);
	//H//ash(data, input_blocksize + HASHED_OUTPUT, h_mac, &ctx); //O(hash(256+64bit))
    //예측 복잡도 = O( hash(128) + hash(data+256bit) + hash(320)) //결국 O(Hash(data)) 랑 비슷.
    //=O(hash(data))
}

*/
/*
void protected_fs_file::ecdsa_make_key()
{
	sgx_ecc256_open_context(&p_ecc_handle);
	sgx_ecc256_create_key_pair(&p_private, &p_public, p_ecc_handle);
}
//DSFS
void protected_fs_file::ecdsa_sign(const uint8_t* buf, const int len, sgx_ec256_signature_t *p_signature) 
{
//	sgx_sha256_hash_t p_hash;
//	sgx_sha_state_handle_t *p_sha_handle;
//	sgx_ecc_state_handle_t p_ecc_handle;
// 	sgx_ec256_private_t p_private;
// 	sgx_ec256_public_t p_public;
	//int r;
//	sgx_ec256_signature_t p_signature;

//	sgx_sha256_msg(buf, len,&p_hash);
 	
//	sgx_ecc256_open_context(&p_ecc_handle); 

//	sgx_ecc256_create_key_pair(&p_private, &p_public, p_ecc_handle);
 	sgx_ecdsa_sign(buf, len, &p_private, p_signature, p_ecc_handle);
//sgx_ecdsa_verify(p_src, cnt_datas, &p_public, &p_signature, &p_result, p_ecc_handle);
}

void protected_fs_file::ecdsa_close()
{
	sgx_ecc256_close_context(p_ecc_handle);
}
*/
void protected_fs_file::erase_recovery_file()
{
	sgx_status_t status;
	int32_t result32;

	if (recovery_filename[0] == '\0') // not initialized yet
		return;

	status = u_sgxprotectedfs_remove(&result32, recovery_filename);
	(void)status; // don't care if it succeeded or failed...just remove the warning
}




void protected_fs_file::HMAC(const unsigned char key[], unsigned char h_mac[], const unsigned char text[], const int text_size)
{
	const unsigned char HASHED_OUTPUT=32;
	const unsigned char input_blocksize = 64;
	//const unsigned char KEY_SIZE=16;
	const unsigned char HASH_BLOCK_SIZE = 64;
    unsigned char Ki[HASH_BLOCK_SIZE] = {0,}; // K0 ^ ipad
    unsigned char Ko[HASH_BLOCK_SIZE] = {0,}; //K0 ^ opad
    const int DATA_BUFFERLEN = text_size + input_blocksize + HASHED_OUTPUT + 1;   //8192+64+32+1 =
    unsigned char data[DATA_BUFFERLEN];
    int i;
	sgx_sha256_hash_t p_hash;
   // SHA256_CTX ctx;

//    printf("key : %x %x %x %x \n", key[0],key[1],key[2],key[3]);
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(Ki, key, KEY_SIZE);
    memcpy(Ko, Ki, KEY_SIZE);        //Ko, Ki는 해쉬된 키값

//이후 B만큼 나머지 길이를 0으로 채운다 여기도 돌아갈일없음.
    for(i=KEY_SIZE; i<input_blocksize; i++)
    {
        Ki[i]=0x00;
        Ko[i]=0x00;
    }
    //ipad opad를 이용해서 Ko를 미리 계산한다.
    for(i=0; i<input_blocksize; i++)
    {
        Ki[i] ^= 0x36;
        Ko[i] ^= 0x5c;
    }
    //위에서 계산한 ;Ki ^ ipad와 HMAC대상인 test를 연접
    memcpy(data, Ki, input_blocksize);
    memcpy(data+input_blocksize, text, text_size);  //여기서 data길이 = 자른KI(64bit) + data임
    //해시한다.
    //printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Hash(data,input_blocksize + text_size,  h_mac, &ctx);  // O(hash(data size + 256biy))
	sgx_sha256_msg(data, input_blocksize+text_size, &p_hash);   
	//printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Ko ^ opad와 위에 해쉬 결과를 연접
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(data, Ko, input_blocksize);
    memcpy(data+input_blocksize, p_hash, HASHED_OUTPUT);   //여기서 data길이 = 64bit+256bit(hashed)
    sgx_sha256_msg(data, input_blocksize+HASHED_OUTPUT, &p_hash);
	memcpy(h_mac, p_hash, HASHED_OUTPUT);
	//H//ash(data, input_blocksize + HASHED_OUTPUT, h_mac, &ctx); //O(hash(256+64bit))
    //예측 복잡도 = O( hash(128) + hash(data+256bit) + hash(320)) //결국 O(Hash(data)) 랑 비슷.
    //=O(hash(data))
}
//write할때 data|version|cmd|fd|offset|size
void protected_fs_file::make_hmac_for_write(const unsigned char* buffer, const unsigned int buffer_size, const uint64_t offset_)
{
	int size = buffer_size+4+1+4+4+4;
	//char *text = (char*)malloc(sizeof(char)*(size));
	char text[size];
	//DS_version++;

	/*
	char tp=buffer[0];
	tp=tp;
	//buffer[0]=buffer[0];
	// 임시코드
	DS_version=1;
	for(int i=0; i<4096; i++)
		text[i]=1;
	text[0]=3;
	text[1]=2;

	unsigned char key[16];
	for(int i=0;i<16;i++)
		key[i]=1;

	//HMAC(key, DS_mac, (unsigned char*)text, my_size);
	*/
	
	memcpy(text, buffer, buffer_size);
	memcpy(&text[buffer_size], &DS_version, 4); 
	text[buffer_size+4] = DS_WRITE_WR;
	memcpy(&text[buffer_size+4+1], &DS_fd, 4);
	memcpy(&text[buffer_size+4+1+4], &offset_, 4);
	memcpy(&text[buffer_size+4+1+4+4], &buffer_size, 4);

//	HMAC(key, DS_mac, (unsigned char*)text, size);
	HMAC(DS_key, DS_mac, (unsigned char*)text, size);

	
//	free(text);
}

uint8_t protected_fs_file::hmac_authentication_for_read(const unsigned char *buffer, const unsigned int buffer_size, const uint64_t offset_, const unsigned int version)
{
	//read는 write할때와 마찬가지로 체크해야함. 
	unsigned char h_mac[32];
	int size = buffer_size+4+1+4+4+4;
	char *text = (char*)malloc(sizeof(char)*(size));
	
	memcpy(text, buffer, buffer_size);
	memcpy(&text[buffer_size], &version, 4); 
	text[buffer_size+4] = DS_WRITE_WR;
	memcpy(&text[buffer_size+4+1], &DS_fd, 4);
	memcpy(&text[buffer_size+4+1+4], &offset_, 4);
	memcpy(&text[buffer_size+4+1+4+4], &size, 4);

	HMAC(DS_key, h_mac, (unsigned char*)text, size);
	//if(memcmp(h_mac, response, MAC_SIZE)==0)
	if(memcmp(h_mac, DS_mac, 32)==0)
	{
		free(text);
		return 1;
	}
	else
	{	//error
		free(text);
		return 1;
	}


}

//protectedfs_file::uint8_t hmac_authentication(unsigned char *auth_SSD, uin32_t size)
uint8_t protected_fs_file::hmac_authentication(const unsigned char flag)//, const unsigned char* buffer, unsigned int buffer_size, unsigned int version)
{
	//size = 10+32(data, mac)
	//mac 인증하려면?
	//unsigned char key[16];
	unsigned char h_mac[32];
	unsigned char *text;
	int result=0;
	//nt text_size=size;
	
	//DS_version++;
	if(flag == DS_OPEN_WR)
	{
		text = (unsigned char*)malloc(sizeof(unsigned char)*12);
		memcpy(text, &response[MAC_SIZE], 12);
		//인증하지 않는다.
		//HMAC(DS_key, h_mac, text, 12);
		//if(memcmp(h_mac, response, MAC_SIZE)==0 || 1)	
		if(1)
		{
			//memcpy(DS_mac, response, MAC_SIZE);
			memcpy(&DS_fd, &response[MAC_SIZE], 4);
			memcpy(&DS_version, &response[MAC_SIZE+4], 4);
			memcpy(&real_file_size, &response[MAC_SIZE+4+4], 4);
			if(real_file_size>0)
			{
				real_file_size = real_file_size/NODE_SIZE*NODE_SIZE;	
			}
			free(text);
			return 1;
		}
	}
	/*
	else if(flag == DS_CREATE_WR)
	{
		text = (char*)malloc(sizeof(char)*40);
		memcpy(text, response, 40);	
		HMAC(key, h_mac, text, text_size);
		f(memcmp(h_mac, response, 32)==0)	
		{

			return 1;
		}
	}
	*/
	else if(flag == DS_CLOSE_WR)
	{
		text = (unsigned char*)malloc(sizeof(unsigned char)*8);
		memcpy(text, &response[MAC_SIZE], 8);	
		HMAC(DS_key, h_mac, text, 8);
		if(memcmp(h_mac, response, MAC_SIZE)==0|| 1)	
		{
			memcpy(DS_mac, response, MAC_SIZE);
			memcpy(&result, &response[MAC_SIZE], 4);
			//memcpy(&DS_version, &response[MAC_SIZE+4], 4);
			if(result==1)
			{
				free(text);
				return 1;
			}
		}
	}
	else if(flag == DS_WRITE_WR)
	{
		text = (unsigned char*)malloc(sizeof(unsigned char)*8);
		memcpy(text, &response[MAC_SIZE], 8);	
		HMAC(DS_key, h_mac, text, 8);
		if(memcmp(h_mac, response, MAC_SIZE)==0|| 1)		
		{
			memcpy(DS_mac, response, MAC_SIZE);
			memcpy(&result, &response[MAC_SIZE], 4);
			//memcpy(&DS_version, &response[MAC_SIZE+4], 4);
			DS_version++;
			if(memcmp(&DS_version, &response[MAC_SIZE+4], 4)==0)
			{
				//무조건 같아야한다. 틀리면 에러임
				;
			}
			free(text);
			return 1;
		}
	}

	//return 0;	
	return 1;
	
/*	
//	memcpy(text, auth_SSD, text_size);
//	protected_fs_file f;
	//f.hmac(key, h_mac, text, text_size
//	HMAC(key, h_mac, text, text_size);
//	if(memcmp(h_mac, auth_SSD+10, 32)==0)	return 1;
//	else return 0;
*/
}



//sgx_fwrite(const void* ptr, size_t size, size_t count, SGX_FILE* stream)  
/*
uint8_t write_to_disk(uint8_t* ptr, unsigned int size, unsigned int offset)
{
  //여기에 인증구현하자.
            //1. 암호화 2. HMAC돌리기 3. p-signatrue에 넣으면 끝. 	
//	int32_t result32;
	uint8_t *p_src = ptr;
	uint32_t src_len = size;
    uint8_t p_dst[8192+512];
    unsigned char key[16];
    unsigned char h_mac[32];
	int ii;
    uint8_t p_ctr[32];
	uint32_t ctr_inc_bits=1;
	uint8_t fid = ptr[0];
	for(ii=0; ii<16; ii++)  key[ii]=0x12;
	for(ii=0; ii<32; ii++)	p_ctr[ii]=0x11;
	p_src = p_src;
	ctr_inc_bits = ctr_inc_bits;
*/
/*
	p_dst[0]=0;
	p_dst[0]=p_dst[0];
	key[0]=key[0], p_src[0]=p_src[0], src_len=src_len, p_ctr[0]=p_ctr[0], h_mac[0]=h_mac[0], ctr_inc_bits=ctr_inc_bits;
*/
/*
	offset=offset;
	sgx_aes_ctr_encrypt(&key,p_src,src_len,p_ctr, ctr_inc_bits, p_dst);
 
  	HMAC(key, h_mac, p_dst, src_len); //이건 data만한거임. 차츰바꿔나가자
//	h_mac[0]=1; result32=1; p_dst[0]=0;

//	key[0]=key[0], p_src[0]=p_src[0], src_len=src_len, p_ctr[0]=p_ctr[0], ctr_inc_bits = ctr_inc_bits, p_dst[0]=p_dst[0];
//	h_mac[0]=h_mac[0];

	p_dst[0]=fid;
//ecdsa_sign(data_to_write,NODE_SIZE, &p_signature);
            //memcpy(&p_sig, &p_signature, 64);
    //u_sgxprotectedfs_fwrite_node_ecdsa(&result32, NULL, (uint64_t)offset, p_dst, (uint32_t)size,(uint8_t*)h_mac);
//	offset=offset, size=size;
//	result32=result32;
	//data받아왔다가정하면
	unsigned char auth_SSD[42];
	for(ii=0; ii<42; ii++)	auth_SSD[ii]=0x34;
	hmac_authentication(auth_SSD);
//	auth_SSD[0]=auth_SSD[0];
	return 1;
	//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, node_number, data_to_write, NODE_SIZE,&p_sig);
            //status = u_sgxprotectedfs_fwrite_node(&result32, file, node_number, data_to_write, NODE_SIZE);
}

uint8_t read_from_disk(uint8_t* ptr, unsigned int size, unsigned int offset)
{
  //여기에 인증구현하자.
            //1. 암호화 2. HMAC돌리기 3. p-signatrue에 넣으면 끝. 	
	//int32_t result32;
	uint8_t *p_src = ptr;
	uint32_t src_len = size;
    uint8_t p_dst[8192+512];
	sgx_aes_ctr_128bit_key_t key;
	//   unsigned char key[16];
    unsigned char h_mac[32];
	int ii;
    uint8_t p_ctr[32];
	uint32_t ctr_inc_bits=1;


	offset=offset;
	//u_sgxprotectedfs_fread_node_ecdsa(&result32, NULL, (uint64_t)offset, p_src, (uint32_t) size, NULL);

		
	for(ii=0; ii<16; ii++)  key[ii]=0x12;
	for(ii=0; ii<32; ii++)	p_ctr[ii]=0x11;
*/
/*
	p_dst[0]=0;
	p_dst[0]=p_dst[0];
	key[0]=key[0], p_src[0]=p_src[0], src_len=src_len, p_ctr[0]=p_ctr[0], h_mac[0]=h_mac[0], ctr_inc_bits=ctr_inc_bits;
*/
/*
//퍼포먼스에 영향미치는 부분까지만 구현함.	 
    HMAC(key, h_mac, p_src, src_len); //이건 data만한거임. 차츰바꿔나가자
	if(memcmp(h_mac, p_src, 16)==0)
	{
		;
	}
	sgx_aes_ctr_decrypt( &key,p_src,src_len,p_ctr, ctr_inc_bits, p_dst);
	memcpy(ptr, p_dst, size);	

//ecdsa_sign(data_to_write,NODE_SIZE, &p_signature);
            //memcpy(&p_sig, &p_signature, 64);
//    u_sgxprotectedfs_fwrite_node_ecdsa(&result32, NULL, (uint64_t)offset, p_dst, (uint32_t)size,(uint8_t*)h_mac);
	//data받아왔다가정하면
//	unsigned char auth_SSD[42];
//	for(ii=0; ii<42; ii++)	auth_SSD[ii]=0x34;
//	hmac_authentication(auth_SSD);

	return 1;
	//status = u_sgxprotectedfs_fwrite_node_ecdsa(&result32, file, node_number, data_to_write, NODE_SIZE,&p_sig);
            //status = u_sgxprotectedfs_fwrite_node(&result32, file, node_number, data_to_write, NODE_SIZE);
}
*/
