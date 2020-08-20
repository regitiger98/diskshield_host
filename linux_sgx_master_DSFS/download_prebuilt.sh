#!/usr/bin/env bash
#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


top_dir=`dirname $0`
out_dir=$top_dir
optlib_name=optimized_libs-2.1.3.tar
ae_file_name=prebuilt-ae-2.1.3.tar
server_url_path=https://download.01.org/intel-sgx/linux-2.1.3/
server_optlib_url=$server_url_path/$optlib_name
server_ae_url=$server_url_path/$ae_file_name
optlib_sha256=b8091d8ad9ea91949610468944b2604c858833f70099c7d369234acd3d62c774
ae_sha256=022fadd5a72234282176c09695c08b755defcffb82ea47b7dd9337c2f43b8378
rm -rf $out_dir/$optlib_name
wget $server_optlib_url -P $out_dir 
if [ $? -ne 0 ]; then
    echo "Fail to download file $server_optlib_url"
    exit -1
fi
sha256sum $out_dir/$optlib_name > check_sum.txt
grep $optlib_sha256 check_sum.txt
if [ $? -ne 0 ]; then 
    echo "File $server_optlib_url checksum failure"
    exit -1
fi
rm -rf $out_dir/$ae_file_name
wget $server_ae_url -P $out_dir
if [ $? -ne 0 ]; then
    echo "Fail to download file $server_ae_url"
    exit -1
fi
sha256sum $out_dir/$ae_file_name > check_sum.txt
grep $ae_sha256 check_sum.txt
if [ $? -ne 0 ]; then
    echo "File $server_ae_url checksum failure"
    exit -1
fi

pushd $out_dir;tar -xf $optlib_name;tar -xf $ae_file_name;rm -f $optlib_name;rm -f $ae_file_name;popd
