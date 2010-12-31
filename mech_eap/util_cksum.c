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
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Message protection services: checksum helpers.
 */

#include "gssapiP_eap.h"

static int
gssEapChecksum(krb5_context context,
               krb5_cksumtype type,
               size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
               krb5_crypto crypto,
#else
               krb5_keyblock *crypto,
#endif
               krb5_keyusage sign_usage,
               gss_iov_buffer_desc *iov,
               int iov_count,
               int verify,
               int *valid)
{
    krb5_error_code code;
    gss_iov_buffer_desc *header;
    gss_iov_buffer_desc *trailer;
    krb5_crypto_iov *kiov;
    size_t kiov_count;
    int i = 0, j;
    size_t k5_checksumlen;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_cksumtype cksumtype;
#endif

    if (verify)
        *valid = FALSE;

    code = krbCryptoLength(context, crypto, KRB5_CRYPTO_TYPE_CHECKSUM, &k5_checksumlen);
    if (code != 0)
        return code;

    header = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    assert(header != NULL);

    trailer = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);
    assert(rrc != 0 || trailer != NULL);

    if (trailer == NULL) {
        if (rrc != k5_checksumlen)
            return KRB5_BAD_MSIZE;
        if (header->buffer.length != 16 + k5_checksumlen)
            return KRB5_BAD_MSIZE;
    } else if (trailer->buffer.length != k5_checksumlen)
        return KRB5_BAD_MSIZE;

    kiov_count = 2 + iov_count;
    kiov = (krb5_crypto_iov *)GSSEAP_MALLOC(kiov_count * sizeof(krb5_crypto_iov));
    if (kiov == NULL)
        return ENOMEM;

    /* Checksum over ( Data | Header ) */

    /* Data */
    for (j = 0; j < iov_count; j++) {
        kiov[i].flags = gssEapMapCryptoFlag(iov[j].type);
        kiov[i].data.length = iov[j].buffer.length;
        kiov[i].data.data = (char *)iov[j].buffer.value;
        i++;
    }

    /* Header */
    kiov[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    kiov[i].data.length = 16;
    kiov[i].data.data = (char *)header->buffer.value;
    i++;

    /* Checksum */
    kiov[i].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    if (trailer == NULL) {
        kiov[i].data.length = header->buffer.length - 16;
        kiov[i].data.data = (char *)header->buffer.value + 16;
    } else {
        kiov[i].data.length = trailer->buffer.length;
        kiov[i].data.data = (char *)trailer->buffer.value;
    }
    i++;

#ifdef HAVE_HEIMDAL_VERSION
    if (verify) {
        code = krb5_verify_checksum_iov(context, crypto, sign_usage,
                                        kiov, kiov_count, &cksumtype);
        *valid = (code == 0);
    } else {
        code = krb5_create_checksum_iov(context, crypto, sign_usage,
                                        kiov, kiov_count, &cksumtype);
    }
#else
    if (verify) {
        krb5_boolean kvalid = FALSE;

        code = krb5_c_verify_checksum_iov(context, type, crypto,
                                          sign_usage, kiov, kiov_count, &kvalid);

        *valid = kvalid;
    } else {
        code = krb5_c_make_checksum_iov(context, type, crypto,
                                        sign_usage, kiov, kiov_count);
    }
#endif /* HAVE_HEIMDAL_VERSION */

    GSSEAP_FREE(kiov);

    return code;
}

int
gssEapSign(krb5_context context,
           krb5_cksumtype type,
           size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
           krb5_crypto crypto,
#else
           krb5_keyblock *crypto,
#endif
           krb5_keyusage sign_usage,
           gss_iov_buffer_desc *iov,
           int iov_count)
{
    return gssEapChecksum(context, type, rrc, crypto,
                          sign_usage, iov, iov_count, 0, NULL);
}

int
gssEapVerify(krb5_context context,
             krb5_cksumtype type,
             size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
             krb5_crypto crypto,
#else
             krb5_keyblock *crypto,
#endif
             krb5_keyusage sign_usage,
             gss_iov_buffer_desc *iov,
             int iov_count,
             int *valid)
{
    return gssEapChecksum(context, type, rrc, crypto,
                          sign_usage, iov, iov_count, 1, valid);
}

#if 0
OM_uint32
gssEapEncodeGssChannelBindings(OM_uint32 *minor,
                               gss_channel_bindings_t chanBindings,
                               gss_buffer_t encodedBindings)
{
    OM_uint32 major, tmpMinor;
    size_t length;
    unsigned char *p;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS) {
        length = 24;
        length += chanBindings->initiator_address.length;
        length += chanBindings->acceptor_address.length;
        length += chanBindings->application_data.length;

        encodedBindings->value = GSSEAP_MALLOC(length);
        if (encodedBindings->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        encodedBindings->length = length;
        p = (unsigned char *)encodedBindings->value;

        store_uint32_be(chanBindings->initiator_addrtype, p);
        store_buffer(&chanBindings->initiator_address, p + 4, 0);
        p += 4 + chanBindings->initiator_address.length;

        store_uint32_be(chanBindings->acceptor_addrtype, p);
        store_buffer(&chanBindings->acceptor_address, p + 4, 0);
        p += 4 + chanBindings->acceptor_address.length;

        store_buffer(&chanBindings->application_data, p, 1);
        p += chanBindings->application_data.length;
    } else {
        encodedBindings->length = 0;
        encodedBindings->value = NULL;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}
#endif
