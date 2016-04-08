/*
 * Copyright (c) 2014 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <openssl/bio.h>
#include <openssl/evp.h>
 #include <openssl/buffer.h>

#include "fido_logs.h"
#include "fido_internal_types.h"
#include "fido_b64_util.h"

int
_fido_b64url_encode(const unsigned char *input,  int inlen, unsigned char *output, int *outlen)
{
	_INFO("_fido_b64url_encode start");

	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;
	b64 = BIO_new(BIO_f_base64());
	if(b64 == NULL) {
		_ERR("BIO_new with BIO_f_base64 failed ");
		return -1;
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, inlen);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	memcpy(output, bptr->data, bptr->length);
	output[bptr->length] = 0;
	*outlen = bptr->length;

	int i;
	for(i =0; i < *outlen ; i++) {
		if(output[i] == '+')
			output[i] = '-';

		else if(output[i] == '/')
			output[i] = '_';

		else if(output[i] == '=') {
			*outlen = i ;
			output[i] = '\0';
		break;
		}
	}

	BIO_free_all(b64);

	_INFO("%s", output);
	_INFO("_fido_b64url_encode end");

	return 0;
}

int
_fido_b64url_decode(const unsigned char *in,  int inlen, unsigned char *out, int *outlen)
{
	_INFO("_fido_b64url_decode start");

	int npadChars = (inlen %4) == 0 ? 0 : (4 - (inlen%4));
	unsigned char *base64 = (unsigned char *) malloc(inlen + npadChars);
	if(base64 == NULL) {
	_ERR("malloc failed");
	return -1;
	}

	memcpy(base64, in, inlen);

	int i;
	for (i = 0; i < inlen ; i++) {
		if (base64[i] == '-')
			base64[i] = '+';

		else if (base64[i] == '_')
			base64[i] = '/';
	}

	if (npadChars != 0)
		memset(base64 + inlen, '=', npadChars);

	BIO * b64 = NULL;
	BIO * bmem = NULL;
	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		_ERR("BIO_new with BIO_f_base64 failed");

		SAFE_DELETE(base64);
		return -1;
	}
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(base64, inlen);
	if (bmem == NULL) {
		_ERR("BIO_new_mem_buf failed");

		SAFE_DELETE(base64);
		return -1;
	}

	bmem = BIO_push(b64, bmem);
	*outlen = BIO_read(bmem, out, inlen);
	if (*outlen <= 0) {
		_ERR("BIO_read failed");

		SAFE_DELETE(base64);
		return -1;
	}

	if (bmem)
		BIO_free_all(bmem);

	_INFO("_fido_b64url_decode end");

	return 0;
}
