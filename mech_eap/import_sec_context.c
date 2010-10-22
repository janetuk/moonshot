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
 * Deserialise a context handle.
 */

#include "gssapiP_eap.h"

#define UPDATE_REMAIN(n)    do {                \
        p += (n);                               \
        remain -= (n);                          \
    } while (0)

#define CHECK_REMAIN(n)     do {                \
        if (remain < (n)) {                     \
            *minor = GSSEAP_TOK_TRUNC;          \
            return GSS_S_DEFECTIVE_TOKEN;       \
        }                                       \
    } while (0)

static OM_uint32
gssEapImportPartialContext(OM_uint32 *minor,
                           unsigned char **pBuf,
                           size_t *pRemain,
                           gss_ctx_id_t ctx)
{
    OM_uint32 major;
    unsigned char *p = *pBuf;
    size_t remain = *pRemain;
    gss_buffer_desc buf;
    size_t serverLen;

    /* Selected RADIUS server */
    CHECK_REMAIN(4);
    serverLen = load_uint32_be(p);
    UPDATE_REMAIN(4);

    if (serverLen != 0) {
        CHECK_REMAIN(serverLen);

        ctx->acceptorCtx.radServer = GSSEAP_MALLOC(serverLen + 1);
        if (ctx->acceptorCtx.radServer == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(ctx->acceptorCtx.radServer, p, serverLen);
        ctx->acceptorCtx.radServer[serverLen] = '\0';

        UPDATE_REMAIN(serverLen);
    }

    /* RADIUS state blob */
    CHECK_REMAIN(4);
    buf.length = load_uint32_be(p);
    UPDATE_REMAIN(4);

    if (buf.length != 0) {
        CHECK_REMAIN(buf.length);

        buf.value = p;

        major = duplicateBuffer(minor, &buf, &ctx->acceptorCtx.state);
        if (GSS_ERROR(major))
            return major;

        UPDATE_REMAIN(buf.length);
    }

    *pBuf = p;
    *pRemain = remain;

    return GSS_S_COMPLETE;
}

static OM_uint32
importMechanismOid(OM_uint32 *minor,
                   unsigned char **pBuf,
                   size_t *pRemain,
                   gss_OID *pOid)
{
    OM_uint32 major;
    unsigned char *p = *pBuf;
    size_t remain = *pRemain;
    gss_OID_desc oidBuf;

    oidBuf.length = load_uint32_be(p);
    if (remain < 4 + oidBuf.length || oidBuf.length == 0) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    oidBuf.elements = &p[4];

    if (!gssEapIsConcreteMechanismOid(&oidBuf)) {
        *minor = GSSEAP_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    if (!gssEapInternalizeOid(&oidBuf, pOid)) {
        major = duplicateOid(minor, &oidBuf, pOid);
        if (GSS_ERROR(major))
            return major;
    }

    *pBuf    += 4 + oidBuf.length;
    *pRemain -= 4 + oidBuf.length;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
importKerberosKey(OM_uint32 *minor,
                  unsigned char **pBuf,
                  size_t *pRemain,
                  krb5_cksumtype *checksumType,
                  krb5_enctype *pEncryptionType,
                  krb5_keyblock *key)
{
    unsigned char *p = *pBuf;
    size_t remain = *pRemain;
    OM_uint32 encryptionType;
    OM_uint32 length;
    gss_buffer_desc tmp;

    if (remain < 12) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    *checksumType  = load_uint32_be(&p[0]);
    encryptionType = load_uint32_be(&p[4]);
    length         = load_uint32_be(&p[8]);

    if ((length != 0) != (encryptionType != ENCTYPE_NULL)) {
        *minor = GSSEAP_BAD_CONTEXT_TOKEN;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (remain - 12 < length) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (load_buffer(&p[12], length, &tmp) == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    KRB_KEY_TYPE(key)   = encryptionType;
    KRB_KEY_LENGTH(key) = tmp.length;
    KRB_KEY_DATA(key)   = (unsigned char *)tmp.value;

    *pBuf    += 12 + length;
    *pRemain -= 12 + length;
    *pEncryptionType = encryptionType;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
importName(OM_uint32 *minor,
           unsigned char **pBuf,
           size_t *pRemain,
           gss_name_t *pName)
{
    OM_uint32 major;
    unsigned char *p = *pBuf;
    size_t remain = *pRemain;
    gss_buffer_desc tmp;

    if (remain < 4) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    tmp.length = load_uint32_be(p);
    if (tmp.length != 0) {
        if (remain - 4 < tmp.length) {
            *minor = GSSEAP_TOK_TRUNC;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        tmp.value = p + 4;

        major = gssEapImportNameInternal(minor, &tmp, pName,
                                         EXPORT_NAME_FLAG_COMPOSITE);
        if (GSS_ERROR(major))
            return major;
    }

    *pBuf    += 4 + tmp.length;
    *pRemain -= 4 + tmp.length;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
gssEapImportContext(OM_uint32 *minor,
                    gss_buffer_t token,
                    gss_ctx_id_t ctx)
{
    OM_uint32 major;
    unsigned char *p = (unsigned char *)token->value;
    size_t remain = token->length;

    if (remain < 16) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    if (load_uint32_be(&p[0]) != EAP_EXPORT_CONTEXT_V1) {
        *minor = GSSEAP_BAD_CONTEXT_TOKEN;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    ctx->state      = load_uint32_be(&p[4]);
    ctx->flags      = load_uint32_be(&p[8]);
    ctx->gssFlags   = load_uint32_be(&p[12]);
    p      += 16;
    remain -= 16;

    /* Validate state */
    if (ctx->state < GSSEAP_STATE_IDENTITY ||
        ctx->state > GSSEAP_STATE_ESTABLISHED)
        return GSS_S_DEFECTIVE_TOKEN;

    /* Only acceptor can export partial context tokens */
    if (CTX_IS_INITIATOR(ctx) && !CTX_IS_ESTABLISHED(ctx))
        return GSS_S_DEFECTIVE_TOKEN;

    major = importMechanismOid(minor, &p, &remain, &ctx->mechanismUsed);
    if (GSS_ERROR(major))
        return major;

    major = importKerberosKey(minor, &p, &remain,
                              &ctx->checksumType,
                              &ctx->encryptionType,
                              &ctx->rfc3961Key);
    if (GSS_ERROR(major))
        return major;

    major = importName(minor, &p, &remain, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    major = importName(minor, &p, &remain, &ctx->acceptorName);
    if (GSS_ERROR(major))
        return major;

    /* Check that, if context is established, names are valid */
    if (CTX_IS_ESTABLISHED(ctx) &&
        (CTX_IS_INITIATOR(ctx) ? ctx->acceptorName == GSS_C_NO_NAME
                               : ctx->initiatorName == GSS_C_NO_NAME)) {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (remain < 24 + sequenceSize(ctx->seqState)) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    ctx->expiryTime = (time_t)load_uint64_be(&p[0]); /* XXX */
    ctx->sendSeq    = load_uint64_be(&p[8]);
    ctx->recvSeq    = load_uint64_be(&p[16]);
    p      += 24;
    remain -= 24;

    major = sequenceInternalize(minor, &ctx->seqState, &p, &remain);
    if (GSS_ERROR(major))
        return major;

    /*
     * The partial context should only be expected for unestablished
     * acceptor contexts.
     */
    if (!CTX_IS_INITIATOR(ctx) && !CTX_IS_ESTABLISHED(ctx)) {
        assert((ctx->flags & CTX_FLAG_KRB_REAUTH) == 0);

        major = gssEapImportPartialContext(minor, &p, &remain, ctx);
        if (GSS_ERROR(major))
            return major;
    }

#ifdef GSSEAP_DEBUG
    assert(remain == 0);
#endif

    major = GSS_S_COMPLETE;
    *minor = 0;

    return major;
}

OM_uint32
gss_import_sec_context(OM_uint32 *minor,
                       gss_buffer_t interprocess_token,
                       gss_ctx_id_t *context_handle)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;

    *context_handle = GSS_C_NO_CONTEXT;

    if (interprocess_token == GSS_C_NO_BUFFER ||
        interprocess_token->length == 0) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    major = gssEapAllocContext(minor, &ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssEapImportContext(minor, interprocess_token, ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    *context_handle = ctx;

cleanup:
    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, &ctx);

    return major;
}
