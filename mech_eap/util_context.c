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
 * Utility routines for context handles.
 */

#include "gssapiP_eap.h"

OM_uint32
gssEapAllocContext(OM_uint32 *minor,
                   gss_ctx_id_t *pCtx)
{
    OM_uint32 tmpMinor;
    gss_ctx_id_t ctx;

    assert(*pCtx == GSS_C_NO_CONTEXT);

    ctx = (gss_ctx_id_t)GSSEAP_CALLOC(1, sizeof(*ctx));
    if (ctx == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSEAP_MUTEX_INIT(&ctx->mutex) != 0) {
        *minor = errno;
        gssEapReleaseContext(&tmpMinor, &ctx);
        return GSS_S_FAILURE;
    }

    ctx->state = GSSEAP_STATE_INITIAL;

    /*
     * Integrity, confidentiality, sequencing and replay detection are
     * always available.  Regardless of what flags are requested in
     * GSS_Init_sec_context, implementations MUST set the flag corresponding
     * to these services in the output of GSS_Init_sec_context and
     * GSS_Accept_sec_context.
    */
    ctx->gssFlags = GSS_C_TRANS_FLAG    |   /* exporting contexts */
                    GSS_C_INTEG_FLAG    |   /* integrity */
                    GSS_C_CONF_FLAG     |   /* confidentiality */
                    GSS_C_SEQUENCE_FLAG |   /* sequencing */
                    GSS_C_REPLAY_FLAG;      /* replay detection */

    *pCtx = ctx;

    return GSS_S_COMPLETE;
}

static void
releaseInitiatorContext(struct gss_eap_initiator_ctx *ctx)
{
    eap_peer_sm_deinit(ctx->eap);
}

static void
releaseAcceptorContext(struct gss_eap_acceptor_ctx *ctx)
{
    OM_uint32 tmpMinor;

    if (ctx->radConn != NULL)
        rs_conn_destroy(ctx->radConn);
    if (ctx->radContext != NULL)
        rs_context_destroy(ctx->radContext);
    if (ctx->radServer != NULL)
        GSSEAP_FREE(ctx->radServer);
    gss_release_buffer(&tmpMinor, &ctx->state);
    if (ctx->vps != NULL)
        gssEapRadiusFreeAvps(&tmpMinor, &ctx->vps);
}

OM_uint32
gssEapReleaseContext(OM_uint32 *minor,
                     gss_ctx_id_t *pCtx)
{
    OM_uint32 tmpMinor;
    gss_ctx_id_t ctx = *pCtx;
    krb5_context krbContext = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        return GSS_S_COMPLETE;
    }

    gssEapKerberosInit(&tmpMinor, &krbContext);

#ifdef GSSEAP_ENABLE_REAUTH
    if (ctx->flags & CTX_FLAG_KRB_REAUTH) {
        gssDeleteSecContext(&tmpMinor, &ctx->kerberosCtx, GSS_C_NO_BUFFER);
    } else
#endif
    if (CTX_IS_INITIATOR(ctx)) {
        releaseInitiatorContext(&ctx->initiatorCtx);
    } else {
        releaseAcceptorContext(&ctx->acceptorCtx);
    }

    krb5_free_keyblock_contents(krbContext, &ctx->rfc3961Key);
    gssEapReleaseName(&tmpMinor, &ctx->initiatorName);
    gssEapReleaseName(&tmpMinor, &ctx->acceptorName);
    gssEapReleaseOid(&tmpMinor, &ctx->mechanismUsed);
    sequenceFree(&tmpMinor, &ctx->seqState);
    gssEapReleaseCred(&tmpMinor, &ctx->defaultCred);
    gss_release_buffer(&tmpMinor, &ctx->conversation);

    GSSEAP_MUTEX_DESTROY(&ctx->mutex);

    memset(ctx, 0, sizeof(*ctx));
    GSSEAP_FREE(ctx);
    *pCtx = GSS_C_NO_CONTEXT;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapGetConversationMIC(OM_uint32 *minor,
                         gss_ctx_id_t ctx,
                         gss_buffer_t convMIC)
{
    OM_uint32 major;
    gss_iov_buffer_desc iov[2];

    iov[0].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[0].buffer = ctx->conversation;

    iov[1].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[1].buffer.length = 0;
    iov[1].buffer.value = NULL;

    major = gssEapWrapOrGetMIC(minor, ctx, FALSE, NULL, iov, 2, TOK_TYPE_MIC);
    if (GSS_ERROR(major))
        return major;

    *convMIC = iov[1].buffer;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapVerifyConversationMIC(OM_uint32 *minor,
                            gss_ctx_id_t ctx,
                            const gss_buffer_t convMIC)
{
    OM_uint32 major;
    gss_iov_buffer_desc iov[3];
    int confState;
    size_t tokenHeaderLength;

    if (convMIC == GSS_C_NO_BUFFER || convMIC->length < 16) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_BAD_SIG;
    }

    iov[0].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[0].buffer = ctx->conversation;

    /*
     * The conversation state already includes the MIC and its
     * TLV header, as well as a header for emiting a subsequent
     * token. These should not be included as input to verifyMIC.
     */
    tokenHeaderLength = ITOK_HEADER_LENGTH + convMIC->length
        + 2 + ctx->mechanismUsed->length + 2;
    assert(ctx->conversation.length > tokenHeaderLength);
    iov[0].buffer.length -= tokenHeaderLength;

    iov[1].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[1].buffer.length = 16;
    iov[1].buffer.value = convMIC->value;

    iov[2].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[2].buffer.length = convMIC->length - 16;
    iov[2].buffer.value = (unsigned char *)convMIC->value + 16;

    major = gssEapUnwrapOrVerifyMIC(minor, ctx, &confState, NULL,
                                    iov, 3, TOK_TYPE_MIC);


    return major;
}
