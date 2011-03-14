/*
 * Copyright (c) 2011, JANET(UK)
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
 * Portions Copyright 1993 by OpenVision Technologies, Inc.
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
 * Utility routines for GSS tokens.
 */

#include "gssapiP_eap.h"

OM_uint32
gssEapDecodeInnerTokens(OM_uint32 *minor,
                        const gss_buffer_t buffer,
                        gss_buffer_set_t *pExtensions,
                        OM_uint32 **pTypes)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_set_t extensions = GSS_C_NO_BUFFER_SET;
    OM_uint32 *types = NULL;
    unsigned char *p;
    size_t remain;

    *pExtensions = GSS_C_NO_BUFFER_SET;
    *pTypes = NULL;

    major = gss_create_empty_buffer_set(minor, &extensions);
    if (GSS_ERROR(major))
        goto cleanup;

    if (buffer->length == 0) {
        major = GSS_S_COMPLETE;
        goto cleanup;
    }

    p = (unsigned char *)buffer->value;
    remain = buffer->length;

    do {
        OM_uint32 *ntypes;
        gss_buffer_desc extension;

        if (remain < 8) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_TOK_TRUNC;
            goto cleanup;
        }

        ntypes = GSSEAP_REALLOC(types,
                                (extensions->count + 1) * sizeof(OM_uint32));
        if (ntypes == NULL) {
            major = GSS_S_FAILURE;
            *minor = ENOMEM;
            goto cleanup;
        }
        types = ntypes;

        types[extensions->count] = load_uint32_be(&p[0]);
        extension.length = load_uint32_be(&p[4]);

        if (remain < ITOK_HEADER_LENGTH + extension.length) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_TOK_TRUNC;
            goto cleanup;
        }
        extension.value = &p[8];

        major = gss_add_buffer_set_member(minor, &extension, &extensions);
        if (GSS_ERROR(major))
            goto cleanup;

        p      += ITOK_HEADER_LENGTH + extension.length;
        remain -= ITOK_HEADER_LENGTH + extension.length;
    } while (remain != 0);

cleanup:
    if (GSS_ERROR(major)) {
        gss_release_buffer_set(&tmpMinor, &extensions);
        if (types != NULL)
            GSSEAP_FREE(types);
    } else {
        *pExtensions = extensions;
        *pTypes = types;
    }

    return major;
}

static OM_uint32
recordTokens(OM_uint32 *minor,
             gss_ctx_id_t ctx,
             gss_buffer_t tokens,
             size_t tokensCount)
{
    unsigned char *buf;
    size_t i, size, offset;

    size = ctx->conversation.length;

    for (i = 0; i < tokensCount; i++)
        size += tokens[i].length;

    buf = GSSEAP_REALLOC(ctx->conversation.value, size);
    if (buf == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    offset = ctx->conversation.length;

    ctx->conversation.length = size;
    ctx->conversation.value = buf;

    for (i = 0; i < tokensCount; i++) {
        memcpy(buf + offset, tokens[i].value, tokens[i].length);
        offset += tokens[i].length;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRecordContextTokenHeader(OM_uint32 *minor,
                               gss_ctx_id_t ctx,
                               enum gss_eap_token_type tokType)
{
    unsigned char wireOidHeader[2], wireTokType[2];
    gss_buffer_desc buffers[3];

    assert(ctx->mechanismUsed != GSS_C_NO_OID);

    wireOidHeader[0] = 0x06;
    wireOidHeader[1] = ctx->mechanismUsed->length;
    buffers[0].length = sizeof(wireOidHeader);
    buffers[0].value  = wireOidHeader;

    buffers[1].length = ctx->mechanismUsed->length;
    buffers[1].value  = ctx->mechanismUsed->elements;

    store_uint16_be(tokType, wireTokType);
    buffers[2].length = sizeof(wireTokType);
    buffers[2].value = wireTokType;

    return recordTokens(minor, ctx, buffers, sizeof(buffers)/sizeof(buffers[0]));
}

OM_uint32
gssEapRecordInnerContextToken(OM_uint32 *minor,
                              gss_ctx_id_t ctx,
                              gss_buffer_t innerToken,
                              OM_uint32 itokType)
{
    gss_buffer_desc buffers[2];
    unsigned char itokHeader[ITOK_HEADER_LENGTH];

    assert(innerToken != GSS_C_NO_BUFFER);

    store_uint32_be(itokType,           &itokHeader[0]);
    store_uint32_be(innerToken->length, &itokHeader[4]);
    buffers[0].length = sizeof(itokHeader);
    buffers[0].value  = itokHeader;

    buffers[1] = *innerToken;

    return recordTokens(minor, ctx, buffers, sizeof(buffers)/sizeof(buffers[0]));
}

OM_uint32
gssEapVerifyContextToken(OM_uint32 *minor,
                         gss_ctx_id_t ctx,
                         const gss_buffer_t inputToken,
                         enum gss_eap_token_type tokType,
                         gss_buffer_t innerInputToken)
{
    OM_uint32 major;
    size_t bodySize;
    unsigned char *p = (unsigned char *)inputToken->value;
    gss_OID_desc oidBuf;
    gss_OID oid;
    enum gss_eap_token_type actualTokType;
    gss_buffer_desc tokenBuf;

    if (ctx->mechanismUsed != GSS_C_NO_OID) {
        oid = ctx->mechanismUsed;
    } else {
        oidBuf.elements = NULL;
        oidBuf.length = 0;
        oid = &oidBuf;
    }

    major = verifyTokenHeader(minor, oid, &bodySize, &p,
                              inputToken->length, &actualTokType);
    if (GSS_ERROR(major))
        return major;

    if (actualTokType != tokType) {
        *minor = GSSEAP_WRONG_TOK_ID;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx->mechanismUsed == GSS_C_NO_OID) {
        if (!gssEapIsConcreteMechanismOid(oid)) {
            *minor = GSSEAP_WRONG_MECH;
            return GSS_S_BAD_MECH;
        }

        if (!gssEapInternalizeOid(oid, &ctx->mechanismUsed)) {
            major = duplicateOid(minor, oid, &ctx->mechanismUsed);
            if (GSS_ERROR(major))
                return major;
        }
    }

    innerInputToken->length = bodySize;
    innerInputToken->value = p;

    /*
     * Add OID, tokenType, body to conversation; variable length
     * header omitted. A better API to verifyTokenHeader would
     * avoid this ugly pointer arithmetic. XXX FIXME
     */
    tokenBuf.value = p - (2 + oid->length + 2);
    tokenBuf.length = 2 + oid->length + 2 + bodySize;

    major = recordTokens(minor, ctx, &tokenBuf, 1);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapContextTime(OM_uint32 *minor,
                  gss_ctx_id_t context_handle,
                  OM_uint32 *time_rec)
{
    if (context_handle->expiryTime == 0) {
        *time_rec = GSS_C_INDEFINITE;
    } else {
        time_t now, lifetime;

        time(&now);
        lifetime = context_handle->expiryTime - now;
        if (lifetime <= 0) {
            *time_rec = 0;
            return GSS_S_CONTEXT_EXPIRED;
        }
        *time_rec = lifetime;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapEncodeSupportedExts(OM_uint32 *minor,
                          OM_uint32 *types,
                          size_t typesCount,
                          gss_buffer_t outputToken)
{
    size_t i;
    unsigned char *p;

    outputToken->value = GSSEAP_MALLOC(4 * typesCount);
    if (outputToken->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    p = (unsigned char *)outputToken->value;

    outputToken->length = 4 * typesCount;

    for (i = 0; i < typesCount; i++) {
        store_uint32_be(types[i], p);
        p += 4;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapProcessSupportedExts(OM_uint32 *minor,
                           gss_buffer_t inputToken,
                           struct gss_eap_itok_map *map,
                           size_t mapCount,
                           OM_uint32 *flags)
{
    size_t i;
    unsigned char *p;

    if ((inputToken->length % 4) != 0) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    p = (unsigned char *)inputToken->value;

    for (i = 0; i < inputToken->length / 4; i++) {
        OM_uint32 type = load_uint32_be(p);
        size_t j;

        for (j = 0; j < mapCount; j++) {
            if (map->type == type) {
                *flags |= map->flag;
                break;
            }
        }

        p += 4;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapMakeTokenChannelBindings(OM_uint32 *minor,
                               gss_ctx_id_t ctx,
                               gss_channel_bindings_t userChanBindings,
                               gss_buffer_t inputToken,
                               gss_channel_bindings_t wireChanBindings)
{
    gss_buffer_t wireData = &wireChanBindings->application_data;
    unsigned char *p;
    size_t tokenHeaderLength = 0;

    memset(wireChanBindings, 0, sizeof(*wireChanBindings));

    if (!CTX_IS_INITIATOR(ctx)) {
        assert(inputToken != GSS_C_NO_BUFFER);

        tokenHeaderLength = ITOK_HEADER_LENGTH + inputToken->length +
            2 + ctx->mechanismUsed->length + 2;
        assert(ctx->conversation.length > tokenHeaderLength);
    }

    wireData->length = ctx->conversation.length - tokenHeaderLength;

    if (userChanBindings != GSS_C_NO_CHANNEL_BINDINGS)
        wireData->length += userChanBindings->application_data.length;

    wireData->value = GSSEAP_MALLOC(wireData->length);
    if (wireData->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    p = (unsigned char *)wireData->value;

    memcpy(p, ctx->conversation.value, ctx->conversation.length - tokenHeaderLength);
    p += ctx->conversation.length - tokenHeaderLength;

    if (userChanBindings != GSS_C_NO_CHANNEL_BINDINGS) {
        memcpy(p, userChanBindings->application_data.value,
               userChanBindings->application_data.length);
        p += userChanBindings->application_data.length;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * $Id: util_token.c 23457 2009-12-08 00:04:48Z tlyu $
 */

/* XXXX this code currently makes the assumption that a mech oid will
   never be longer than 127 bytes.  This assumption is not inherent in
   the interfaces, so the code can be fixed if the OSI namespace
   balloons unexpectedly. */

/*
 * Each token looks like this:
 * 0x60                 tag for APPLICATION 0, SEQUENCE
 *                              (constructed, definite-length)
 * <length>             possible multiple bytes, need to parse/generate
 * 0x06                 tag for OBJECT IDENTIFIER
 * <moid_length>        compile-time constant string (assume 1 byte)
 * <moid_bytes>         compile-time constant string
 * <inner_bytes>        the ANY containing the application token
 * bytes 0,1 are the token type
 * bytes 2,n are the token data
 *
 * Note that the token type field is a feature of RFC 1964 mechanisms and
 * is not used by other GSSAPI mechanisms.  As such, a token type of -1
 * is interpreted to mean that no token type should be expected or
 * generated.
 *
 * For the purposes of this abstraction, the token "header" consists of
 * the sequence tag and length octets, the mech OID DER encoding, and the
 * first two inner bytes, which indicate the token type.  The token
 * "body" consists of everything else.
 */

static size_t
der_length_size(size_t length)
{
    if (length < (1<<7))
        return 1;
    else if (length < (1<<8))
        return 2;
#if INT_MAX == 0x7fff
    else
        return 3;
#else
    else if (length < (1<<16))
        return 3;
    else if (length < (1<<24))
        return 4;
    else
        return 5;
#endif
}

static void
der_write_length(unsigned char **buf, size_t length)
{
    if (length < (1<<7)) {
        *(*buf)++ = (unsigned char)length;
    } else {
        *(*buf)++ = (unsigned char)(der_length_size(length)+127);
#if INT_MAX > 0x7fff
        if (length >= (1<<24))
            *(*buf)++ = (unsigned char)(length>>24);
        if (length >= (1<<16))
            *(*buf)++ = (unsigned char)((length>>16)&0xff);
#endif
        if (length >= (1<<8))
            *(*buf)++ = (unsigned char)((length>>8)&0xff);
        *(*buf)++ = (unsigned char)(length&0xff);
    }
}

/* returns decoded length, or < 0 on failure.  Advances buf and
   decrements bufsize */

static int
der_read_length(unsigned char **buf, ssize_t *bufsize)
{
    unsigned char sf;
    int ret;

    if (*bufsize < 1)
        return -1;

    sf = *(*buf)++;
    (*bufsize)--;
    if (sf & 0x80) {
        if ((sf &= 0x7f) > ((*bufsize)-1))
            return -1;
        if (sf > sizeof(int))
            return -1;
        ret = 0;
        for (; sf; sf--) {
            ret = (ret<<8) + (*(*buf)++);
            (*bufsize)--;
        }
    } else {
        ret = sf;
    }

    return ret;
}

/* returns the length of a token, given the mech oid and the body size */

size_t
tokenSize(size_t body_size)
{
    return 1 + der_length_size(body_size) + body_size;
}

/* fills in a buffer with the token header.  The buffer is assumed to
   be the right size.  buf is advanced past the token header */

void
makeTokenHeader(
    size_t body_size,
    unsigned char **buf)
{
    *(*buf)++ = 0x60;
    der_write_length(buf, body_size);
}

/*
 * Given a buffer containing a token, reads and verifies the token,
 * leaving buf advanced past the token header, and setting body_size
 * to the number of remaining bytes.  Returns 0 on success,
 * G_BAD_TOK_HEADER for a variety of errors, and G_WRONG_MECH if the
 * mechanism in the token does not match the mech argument.  buf and
 * *body_size are left unmodified on error.
 */

OM_uint32
verifyTokenHeader(OM_uint32 *minor,
                  gss_OID mech,
                  size_t *body_size,
                  unsigned char **buf_in,
                  size_t toksize_in,
                  enum gss_eap_token_type *ret_tok_type)
{
    unsigned char *buf = *buf_in;
    ssize_t seqsize;
    gss_OID_desc toid;
    ssize_t toksize = (ssize_t)toksize_in;

    *minor = GSSEAP_BAD_TOK_HEADER;

    if (ret_tok_type != NULL)
        *ret_tok_type = TOK_TYPE_NONE;

    if ((toksize -= 1) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    if (*buf++ != 0x60)
        return GSS_S_DEFECTIVE_TOKEN;

    seqsize = der_read_length(&buf, &toksize);
    if (seqsize < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    if (seqsize != toksize)
        return GSS_S_DEFECTIVE_TOKEN;

    if ((toksize -= 1) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    if (*buf++ != 0x06)
        return GSS_S_DEFECTIVE_TOKEN;

    if ((toksize -= 1) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    toid.length = *buf++;

    if ((toksize -= toid.length) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    toid.elements = buf;
    buf += toid.length;

    if (mech->elements == NULL) {
        *mech = toid;
        if (toid.length == 0)
            return GSS_S_BAD_MECH;
    } else if (!oidEqual(&toid, mech)) {
        *minor = GSSEAP_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    if (ret_tok_type != NULL) {
        if ((toksize -= 2) < 0)
            return GSS_S_DEFECTIVE_TOKEN;

        *ret_tok_type = load_uint16_be(buf);
        buf += 2;
    }

    *buf_in = buf;
    *body_size = toksize;

    *minor = 0;
    return GSS_S_COMPLETE;
}
