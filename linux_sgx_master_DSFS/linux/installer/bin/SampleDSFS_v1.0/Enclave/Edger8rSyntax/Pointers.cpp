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


/* Test Pointer Auttributes */

#include <sys/types.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_lfence.h"
#include "../Enclave.h"
#include "Enclave_t.h"
#include "sgx_tprotected_fs.h"
#include "sgx_tcrypto.h"
/* checksum_internal:
 *   get simple checksum of input buffer and length
 */
int32_t checksum_internal(char *buf, size_t count)
{
    register int32_t sum = 0;
    int16_t *ptr = (int16_t *)buf;

    /* Main summing loop */
    while(count > 1) {
        sum = sum + *ptr++;
        count = count - 2;
    }

    /* Add left-over byte, if any */
    if (count > 0)
        sum = sum + *((char *)ptr);

	return ~sum;
}

/* ecall_pointer_user_check, ecall_pointer_in, ecall_pointer_out, ecall_pointer_in_out:
 *   The root ECALLs to test [in], [out], [user_check] attributes.
 */
size_t ecall_pointer_user_check(void *val, size_t sz)
{
    /* check if the buffer is allocated outside */
    if (sgx_is_outside_enclave(val, sz) != 1)
        abort();

    /*fence after sgx_is_outside_enclave check*/
    sgx_lfence();

    char tmp[100] = {0};
    size_t len = sz>100?100:sz;
    
    /* copy the memory into the enclave to make sure 'val' 
     * is not being changed in checksum_internal() */
    memcpy(tmp, val, len);
    
    int32_t sum = checksum_internal((char *)tmp, len);
    printf("Checksum(0x%p, %zu) = 0x%x\n", 
            val, len, (unsigned int)sum);
    
    /* modify outside memory directly */
    memcpy(val, "SGX_SUCCESS", len>12?12:len);

	return len;
}

/* ecall_pointer_in:
 *   the buffer of val is copied to the enclave.
 */

void ecall_pointer_in(int *val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    *val = 1234;
}

/* ecall_pointer_out:
 *   the buffer of val is copied to the untrusted side.
 */
void ecall_pointer_out(int *val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    assert(*val == 0);
    *val = 1234;
}

/* ecall_pointer_in_out:
 * the buffer of val is double-copied.
 */
void ecall_pointer_in_out(int *val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    *val = 1234;
}

/* ocall_pointer_attr:
 *   The root ECALL that test OCALL [in], [out], [user_check].
 */
void ocall_pointer_attr(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int val = 0;
    ret = ocall_pointer_user_check(&val);
    if (ret != SGX_SUCCESS)
        abort();

    val = 0;
    ret = ocall_pointer_in(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 0);

    val = 0;
    ret = ocall_pointer_out(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);

    val = 0;
    ret = ocall_pointer_in_out(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);

    return;
}

/* ecall_pointer_string:
 *   [string] defines a string.
 */
void ecall_pointer_string(char *str)
{
    strncpy(str, "0987654321", strlen(str));
}

/* ecall_pointer_string_const:
 *   const [string] defines a string that cannot be modified.
 */
void ecall_pointer_string_const(const char *str)
{
    char* temp = new char[strlen(str)];
    strncpy(temp, str, strlen(str));
    delete []temp;
}

/* ecall_pointer_size:
 *   'len' needs to be specified to tell Edger8r the length of 'str'.
 */
void ecall_pointer_size(void *ptr, size_t len)
{
    strncpy((char*)ptr, "0987654321", len);
}

/* ecall_pointer_count:
 *   'cnt' needs to be specified to tell Edger8r the number of elements in 'arr'.
 */
void ecall_pointer_count(int *arr, int cnt)
{
    for (int i = (cnt - 1); i >= 0; i--)
        arr[i] = (cnt - 1 - i);
}

/* ecall_pointer_isptr_readonly:
 *   'buf' is user defined type, shall be tagged with [isptr].
 *   if it's not writable, [readonly] shall be specified. 
 */
void ecall_pointer_isptr_readonly(buffer_t buf, size_t len)
{
    strncpy((char*)buf, "0987654321", len);
}

void HMAC(const unsigned char key[], unsigned char h_mac[], const unsigned char text[], const int text_size)
{
	const unsigned char HASHED_OUTPUT=32;
	const unsigned char input_blocksize = 64;
	const unsigned char KEY_SIZE=16;
	const unsigned char HASH_BLOCK_SIZE = 64;
    unsigned char Ki[HASH_BLOCK_SIZE] = {0,}; // K0 ^ ipad
    unsigned char Ko[HASH_BLOCK_SIZE] = {0,}; //K0 ^ opad
    const int DATA_BUFFERLEN = text_size + input_blocksize + HASHED_OUTPUT + 1;   //8192+64+32+1 =
    uint8_t data[DATA_BUFFERLEN];
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
	//sgx_sha256_msg(data, (uint32_t)input_blocksize+text_size, &p_hash);   
	//printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Ko ^ opad와 위에 해쉬 결과를 연접
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(data, Ko, input_blocksize);
    memcpy(data+input_blocksize, p_hash, HASHED_OUTPUT);   //여기서 data길이 = 64bit+256bit(hashed)
   // /sgx_sha256_msg(data, (uint32_t)input_blocksize+HASHED_OUTPUT, &p_hash);
	memcpy(h_mac, p_hash, HASHED_OUTPUT);
	//H//ash(data, input_blocksize + HASHED_OUTPUT, h_mac, &ctx); //O(hash(256+64bit))
    //예측 복잡도 = O( hash(128) + hash(data+256bit) + hash(320)) //결국 O(Hash(data)) 랑 비슷.
    //=O(hash(data))
}

uint8_t hmac_authentication(unsigned char *auth_SSD)
{
	//size = 10+32(data, mac)
	//mac  인증하려면?
	unsigned char key[16];
	unsigned char h_mac[32];
	unsigned char text[10];
	int text_size=10;
	memcpy(text, auth_SSD, 10);
//	protected_fs_file f;
	//f.hmac(key, h_mac, text, text_size);
	HMAC(key, h_mac, text, text_size);
	if(memcmp(h_mac, auth_SSD+10, 32)==0)	return 1;
	else return 0;
}


void ecall_IPFS_function(char* file_name, char* datas, size_t cnt_filename, size_t cnt_datas)
{
	size_t offset = cnt_filename;
	sgx_fwrite(datas, cnt_datas,offset, fp);
	//sgx_fwite가 인증데이터를 받아왔다는 가정을 하자.
	//unsigned char auth_SSD[42];	//10vytes는 데이터, 32bytew는인증데이터
	//hmac_authentication(auth_SSD);

/*
	SGX_FILE* fp = sgx_fopen_auto_key(file_name, "w");

	printf("file name :%s,  datas:%s\n",file_name,datas);
	printf("%d\n", strlen(file_name));

	char hi[10];
	strncpy(hi, file_name, strlen(file_name));
	
	//strcpy(hi, "hello");
	
	//printf("%s\n", hi);
	printf("%d %d\n", strlen(datas), cnt_datas);
	printf("data write :%s\n", datas);
	sgx_fwrite(datas, 1, cnt_datas, fp);

	sgx_fclose(fp);
	fp = sgx_fopen_auto_key(file_name, "r");
	char read_data[100];
	sgx_fread(read_data, 1, cnt_datas, fp);

//	printf("Who am I?\n");
	printf("Data read :%s\n", read_data);
	//printf(read_data);

	sgx_fclose(fp);

	//ref : include/sgx_tcrypto.h
	//
	//const char* p_src = datas;
	const uint8_t *p_src = (uint8_t *)datas;
	uint32_t src_len = cnt_datas;
	//enclave ecdsa check
	sgx_sha256_hash_t p_hash;
	printf("sha check\n");
	printf("data : %s\n", p_src);
	sgx_sha_state_handle_t *p_sha_handle;
	sgx_sha256_msg(p_src, src_len,&p_hash); 
//	printf("%d %d %d %d\n", SGX_SUCCESS, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_OUT_OF_MEMORY, SGX_ERROR_UNEXPECTED);
//	printf("return ? :%d\n", return_);
	printf("hash : \n");	
	for(int i=0; i<32; i++)
		printf("0x%x, ", p_hash[i]);
	printf("\n");
	
	printf("aes_ctr : \n");
	
	sgx_aes_ctr_128bit_key_t p_key;
	for(int i=0; i<16; i++)	p_key[i]=0x11;
	uint8_t *p_sr = (uint8_t*)p_hash;
	uint8_t p_ctr[32];
	uint32_t ctr_inc_bits = 1; 
	uint32_t ctr_inc_bits2= 1; 
	uint8_t p_dst[32];
	uint32_t sr_len = 32;
	
	for(int i=0; i<32; i++)
		p_ctr[i]=0x11;
	for(int i=0; i<32; i++)
		printf("0x%x, ", p_sr[i]);
	printf("\n");
	printf("encrypted :  %d %d %x\n", p_ctr, ctr_inc_bits,*((uint32_t*)p_key));
	int ret_aes;
	ret_aes=sgx_aes_ctr_encrypt(&p_key, p_sr, sr_len,p_ctr, ctr_inc_bits, p_dst);
	printf("suc? %d %d\n", ret_aes, SGX_SUCCESS);
	
	for(int i=0; i<32; i++)
		printf("0x%x, ", p_dst[i]);
	printf("\n");
	uint8_t org[32];
	printf("decrypted : %d %d %d\n", p_ctr, ctr_inc_bits,ctr_inc_bits2);
	ret_aes=sgx_aes_ctr_decrypt(&p_key, p_dst, sr_len, p_ctr, ctr_inc_bits, org);
	printf("suc? %d %d\n", ret_aes, SGX_SUCCESS);
	for(int i=0; i<32; i++)
		printf("0x%x, ", org[i]);
	printf("\n");

	

	
	printf("ecdsa check :");
	sgx_ecc_state_handle_t p_ecc_handle;

	int r = sgx_ecc256_open_context(&p_ecc_handle);
	
	printf("success?%d %d %d %d %d\n", r,SGX_SUCCESS, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_OUT_OF_MEMORY, SGX_ERROR_UNEXPECTED);
	sgx_ec256_private_t p_private;
	sgx_ec256_public_t p_public;
	sgx_ecc256_create_key_pair(&p_private, &p_public, p_ecc_handle);
	printf("success?%d %d\n", r,SGX_SUCCESS);
	printf("private key : \n");

	
	for(int i=0; i<32; i++)
		printf("0x%x, ", p_private.r[i]);
	printf("\n");

	printf("public key :\nx: ");
	for(int i=0; i<32; i++)
		printf("0x%x, ", p_public.gx[i]);
	printf("\ny: ");
	for(int i=0; i<32; i++)
		printf("0x%x, ", p_public.gy[i]);
	printf("\n");


	sgx_ec256_signature_t p_signature;
	//sgx_ecdsa_sigang
	sgx_ecdsa_sign(p_src, cnt_datas, &p_private, &p_signature, p_ecc_handle);
	printf("signature : \nX: ");
	for(int i=0; i<8; i++)
		printf("0x%x, ", p_signature.x[i]);
	printf("\n Y: ");
	for(int i=0; i<8; i++)
		printf("0x%x, ", p_signature.y[i]);
	printf("\n");
	uint8_t p_result;
	sgx_ecdsa_verify(p_src, cnt_datas, &p_public, &p_signature, &p_result, p_ecc_handle);
	printf("verify ? : %d | valid :%d invalid:%d\n", p_result, SGX_EC_VALID, SGX_EC_INVALID_SIGNATURE);



	sgx_ecc256_close_context(p_ecc_handle);
*/
}
