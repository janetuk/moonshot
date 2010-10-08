/*
 * Copyright (c) 2010, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _GSSAPI_EAP_H_
#define _GSSAPI_EAP_H_ 1

#include <gssapi/gssapi.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern gss_OID GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM;
extern gss_OID GSS_EAP_AES256_CTS_HMAC_SHA1_96_MECHANISM;

/* name type */
extern gss_OID GSS_EAP_NT_PRINCIPAL_NAME;

/* the libradsec configuration file */
extern gss_OID GSS_EAP_CRED_SET_RADIUS_CONFIG_FILE;
/* the stanza in the libradsec configuration file */
extern gss_OID GSS_EAP_CRED_SET_RADIUS_CONFIG_STANZA;

/* flags in NBO followed by an optional boolean octet that
 * specifies whether to clear the specified flags */
extern gss_OID GSS_EAP_CRED_SET_CRED_FLAG;

#define GSS_EAP_DISABLE_LOCAL_ATTRS_FLAG    0x00000001

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _GSSAPI_EAP_H_ */
