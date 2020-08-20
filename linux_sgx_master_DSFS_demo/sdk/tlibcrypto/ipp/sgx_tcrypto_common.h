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


#ifndef _SGX_TCRYPTO_COMMON_H_
#define _SGX_TCRYPTO_COMMON_H_

#include "ippcp.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "util.h"
#include "stdlib.h"
#include "string.h"

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x != ippStsNoErr){break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

#define RSA_SEED_SIZE_SHA256 32

IppStatus sgx_ipp_newBN(const Ipp32u *p_data, int size_in_bytes, IppsBigNumState **p_new_BN);
void sgx_ipp_secure_free_BN(IppsBigNumState *pBN, int size_in_bytes);
IppStatus IPP_STDCALL sgx_ipp_DRNGen(Ipp32u* pRandBNU, int nBits, void* pCtx);

IppStatus sgx_ipp_newPrimeGen(int nMaxBits, IppsPrimeState ** pPrimeG);


static inline IppStatus check_copy_size(size_t target_size, size_t source_size)
{
    if(target_size < source_size)
        return ippStsSizeErr;
    return ippStsNoErr;
}

#endif
