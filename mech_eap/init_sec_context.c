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
 * Establish a security context on the initiator (client). These functions
 * wrap around libeap.
 */

#include "gssapiP_eap.h"

static OM_uint32
policyVariableToFlag(enum eapol_bool_var variable)
{
    OM_uint32 flag = 0;

    switch (variable) {
    case EAPOL_eapSuccess:
        flag = CTX_FLAG_EAP_SUCCESS;
        break;
    case EAPOL_eapRestart:
        flag = CTX_FLAG_EAP_RESTART;
        break;
    case EAPOL_eapFail:
        flag = CTX_FLAG_EAP_FAIL;
        break;
    case EAPOL_eapResp:
        flag = CTX_FLAG_EAP_RESP;
        break;
    case EAPOL_eapNoResp:
        flag = CTX_FLAG_EAP_NO_RESP;
        break;
    case EAPOL_eapReq:
        flag = CTX_FLAG_EAP_REQ;
        break;
    case EAPOL_portEnabled:
        flag = CTX_FLAG_EAP_PORT_ENABLED;
        break;
    case EAPOL_altAccept:
        flag = CTX_FLAG_EAP_ALT_ACCEPT;
        break;
    case EAPOL_altReject:
        flag = CTX_FLAG_EAP_ALT_REJECT;
        break;
    }

    return flag;
}

static struct eap_peer_config *
peerGetConfig(void *ctx)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;

    return &gssCtx->initiatorCtx.eapPeerConfig;
}

static Boolean
peerGetBool(void *data, enum eapol_bool_var variable)
{
    gss_ctx_id_t ctx = data;
    OM_uint32 flag;

    if (ctx == GSS_C_NO_CONTEXT)
        return FALSE;

    flag = policyVariableToFlag(variable);

    return ((ctx->flags & flag) != 0);
}

static void
peerSetBool(void *data, enum eapol_bool_var variable,
            Boolean value)
{
    gss_ctx_id_t ctx = data;
    OM_uint32 flag;

    if (ctx == GSS_C_NO_CONTEXT)
        return;

    flag = policyVariableToFlag(variable);

    if (value)
        ctx->flags |= flag;
    else
        ctx->flags &= ~(flag);
}

static unsigned int
peerGetInt(void *data, enum eapol_int_var variable)
{
    gss_ctx_id_t ctx = data;

    if (ctx == GSS_C_NO_CONTEXT)
        return FALSE;

    assert(CTX_IS_INITIATOR(ctx));

    switch (variable) {
    case EAPOL_idleWhile:
        return ctx->initiatorCtx.idleWhile;
        break;
    }

    return 0;
}

static void
peerSetInt(void *data, enum eapol_int_var variable,
           unsigned int value)
{
    gss_ctx_id_t ctx = data;

    if (ctx == GSS_C_NO_CONTEXT)
        return;

    assert(CTX_IS_INITIATOR(ctx));

    switch (variable) {
    case EAPOL_idleWhile:
        ctx->initiatorCtx.idleWhile = value;
        break;
    }
}

static struct wpabuf *
peerGetEapReqData(void *ctx)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;

    return &gssCtx->initiatorCtx.reqData;
}

static void
peerSetConfigBlob(void *ctx, struct wpa_config_blob *blob)
{
}

static const struct wpa_config_blob *
peerGetConfigBlob(void *ctx, const char *name)
{
    return NULL;
}

static void
peerNotifyPending(void *ctx)
{
}

static struct eapol_callbacks gssEapPolicyCallbacks = {
    peerGetConfig,
    peerGetBool,
    peerSetBool,
    peerGetInt,
    peerSetInt,
    peerGetEapReqData,
    peerSetConfigBlob,
    peerGetConfigBlob,
    peerNotifyPending,
};

#ifdef GSSEAP_DEBUG
extern int wpa_debug_level;
#endif

static OM_uint32
peerConfigInit(OM_uint32 *minor,
               gss_cred_id_t cred,
               gss_ctx_id_t ctx)
{
    krb5_context krbContext;
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;
    krb5_error_code code;
    char *identity, *anonymousIdentity;

    eapPeerConfig->identity = NULL;
    eapPeerConfig->identity_len = 0;
    eapPeerConfig->password = NULL;
    eapPeerConfig->password_len = 0;

    assert(cred != GSS_C_NO_CREDENTIAL);

    GSSEAP_KRB_INIT(&krbContext);

    eapPeerConfig->fragment_size = 1024;
#ifdef GSSEAP_DEBUG
    wpa_debug_level = 0;
#endif

    assert(cred->name != GSS_C_NO_NAME);

    if ((cred->name->flags & (NAME_FLAG_NAI | NAME_FLAG_SERVICE)) == 0) {
        *minor = GSSEAP_BAD_INITIATOR_NAME;
        return GSS_S_BAD_NAME;
    }

    code = krb5_unparse_name(krbContext, cred->name->krbPrincipal, &identity);
    if (code != 0) {
        *minor = code;
        return GSS_S_FAILURE;
    }

    anonymousIdentity = strchr(identity, '@');
    if (anonymousIdentity == NULL)
        anonymousIdentity = "";

    eapPeerConfig->identity = (unsigned char *)identity;
    eapPeerConfig->identity_len = strlen(identity);
    eapPeerConfig->anonymous_identity = (unsigned char *)anonymousIdentity;
    eapPeerConfig->anonymous_identity_len = strlen(anonymousIdentity);
    eapPeerConfig->password = (unsigned char *)cred->password.value;
    eapPeerConfig->password_len = cred->password.length;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
peerConfigFree(OM_uint32 *minor,
               gss_ctx_id_t ctx)
{
    krb5_context krbContext;
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;

    GSSEAP_KRB_INIT(&krbContext);

    krb5_free_unparsed_name(krbContext, (char *)eapPeerConfig->identity);

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Mark an initiator context as ready for cryptographic operations
 */
static OM_uint32
initReady(OM_uint32 *minor, gss_ctx_id_t ctx, OM_uint32 reqFlags)
{
    OM_uint32 major;
    const unsigned char *key;
    size_t keyLength;

#if 1
    /* XXX actually check for mutual auth */
    if (reqFlags & GSS_C_MUTUAL_FLAG)
        ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
#endif

    /* Cache encryption type derived from selected mechanism OID */
    major = gssEapOidToEnctype(minor, ctx->mechanismUsed, &ctx->encryptionType);
    if (GSS_ERROR(major))
        return major;

    if (!eap_key_available(ctx->initiatorCtx.eap)) {
        *minor = GSSEAP_KEY_UNAVAILABLE;
        return GSS_S_UNAVAILABLE;
    }

    key = eap_get_eapKeyData(ctx->initiatorCtx.eap, &keyLength);

    if (keyLength < EAP_EMSK_LEN) {
        *minor = GSSEAP_KEY_TOO_SHORT;
        return GSS_S_UNAVAILABLE;
    }

    major = gssEapDeriveRfc3961Key(minor,
                                   &key[EAP_EMSK_LEN / 2],
                                   EAP_EMSK_LEN / 2,
                                   ctx->encryptionType,
                                   &ctx->rfc3961Key);
       if (GSS_ERROR(major))
           return major;

    major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                      &ctx->checksumType);
    if (GSS_ERROR(major))
        return major;

    major = sequenceInit(minor,
                         &ctx->seqState,
                         ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
initBegin(OM_uint32 *minor,
          gss_cred_id_t cred,
          gss_ctx_id_t ctx,
          gss_name_t target,
          gss_OID mech,
          OM_uint32 reqFlags,
          OM_uint32 timeReq,
          gss_channel_bindings_t chanBindings)
{
    OM_uint32 major;

    assert(cred != GSS_C_NO_CREDENTIAL);

    if (cred->expiryTime)
        ctx->expiryTime = cred->expiryTime;
    else if (timeReq == 0 || timeReq == GSS_C_INDEFINITE)
        ctx->expiryTime = 0;
    else
        ctx->expiryTime = time(NULL) + timeReq;

    /*
     * The credential mutex protects its name, however we need to
     * explicitly lock the acceptor name (unlikely as it may be
     * that it has attributes set on it).
     */
    major = gssEapDuplicateName(minor, cred->name, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    if (target != GSS_C_NO_NAME) {
        GSSEAP_MUTEX_LOCK(&target->mutex);

        major = gssEapDuplicateName(minor, target, &ctx->acceptorName);
        if (GSS_ERROR(major)) {
            GSSEAP_MUTEX_UNLOCK(&target->mutex);
            return major;
        }

        GSSEAP_MUTEX_UNLOCK(&target->mutex);
    }

    if (mech == GSS_C_NULL_OID) {
        major = gssEapDefaultMech(minor, &ctx->mechanismUsed);
    } else if (gssEapIsConcreteMechanismOid(mech)) {
        if (!gssEapInternalizeOid(mech, &ctx->mechanismUsed))
            major = duplicateOid(minor, mech, &ctx->mechanismUsed);
    } else {
        major = GSS_S_BAD_MECH;
        *minor = GSSEAP_WRONG_MECH;
    }
    if (GSS_ERROR(major))
        return major;

    /* If credentials were provided, check they're usable with this mech */
    if (!gssEapCredAvailable(cred, ctx->mechanismUsed)) {
        *minor = GSSEAP_CRED_MECH_MISMATCH;
        return GSS_S_BAD_MECH;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
eapGssSmInitError(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_ctx_id_t ctx,
                  gss_name_t target,
                  gss_OID mech,
                  OM_uint32 reqFlags,
                  OM_uint32 timeReq,
                  gss_channel_bindings_t chanBindings,
                  gss_buffer_t inputToken,
                  gss_buffer_t outputToken,
                  OM_uint32 *smFlags)
{
    OM_uint32 major;
    unsigned char *p;

    if (inputToken->length < 8) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    p = (unsigned char *)inputToken->value;

    major = load_uint32_be(&p[0]);
    *minor = ERROR_TABLE_BASE_eapg + load_uint32_be(&p[4]);

    if (!GSS_ERROR(major) || !IS_WIRE_ERROR(*minor)) {
        major = GSS_S_FAILURE;
        *minor = GSSEAP_BAD_ERROR_TOKEN;
    }

    assert(GSS_ERROR(major));

    return major;
}

#ifdef GSSEAP_ENABLE_REAUTH
static OM_uint32
eapGssSmInitGssReauth(OM_uint32 *minor,
                      gss_cred_id_t cred,
                      gss_ctx_id_t ctx,
                      gss_name_t target,
                      gss_OID mech,
                      OM_uint32 reqFlags,
                      OM_uint32 timeReq,
                      gss_channel_bindings_t chanBindings,
                      gss_buffer_t inputToken,
                      gss_buffer_t outputToken,
                      OM_uint32 *smFlags)
{
    OM_uint32 major, tmpMinor;
    gss_name_t mechTarget = GSS_C_NO_NAME;
    gss_OID actualMech = GSS_C_NO_OID;
    OM_uint32 gssFlags, timeRec;

    assert(cred != GSS_C_NO_CREDENTIAL);

    if (GSSEAP_SM_STATE(ctx) == GSSEAP_STATE_INITIAL) {
        if (!gssEapCanReauthP(cred, target, timeReq))
            return GSS_S_CONTINUE_NEEDED;

        ctx->flags |= CTX_FLAG_KRB_REAUTH;
    } else if ((ctx->flags & CTX_FLAG_KRB_REAUTH) == 0) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSEAP_WRONG_ITOK;
        goto cleanup;
    }

    major = gssEapMechToGlueName(minor, target, &mechTarget);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssInitSecContext(minor,
                              cred->krbCred,
                              &ctx->kerberosCtx,
                              mechTarget,
                              (gss_OID)gss_mech_krb5,
                              reqFlags | GSS_C_MUTUAL_FLAG,
                              timeReq,
                              chanBindings,
                              inputToken,
                              &actualMech,
                              outputToken,
                              &gssFlags,
                              &timeRec);
    if (GSS_ERROR(major))
        goto cleanup;

    ctx->gssFlags = gssFlags;

    if (major == GSS_S_COMPLETE) {
        assert(GSSEAP_SM_STATE(ctx) == GSSEAP_STATE_REAUTHENTICATE);

        major = gssEapReauthComplete(minor, ctx, cred, actualMech, timeRec);
        if (GSS_ERROR(major))
            goto cleanup;

        GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_INITIATOR_EXTS);
    } else {
        GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_REAUTHENTICATE);
    }

    major = GSS_S_CONTINUE_NEEDED;

cleanup:
    gssReleaseName(&tmpMinor, &mechTarget);

    return major;
}
#endif /* GSSEAP_ENABLE_REAUTH */

#ifdef GSSEAP_DEBUG
static OM_uint32
eapGssSmInitVendorInfo(OM_uint32 *minor,
                       gss_cred_id_t cred,
                       gss_ctx_id_t ctx,
                       gss_name_t target,
                       gss_OID mech,
                       OM_uint32 reqFlags,
                       OM_uint32 timeReq,
                       gss_channel_bindings_t chanBindings,
                       gss_buffer_t inputToken,
                       gss_buffer_t outputToken,
                       OM_uint32 *smFlags)
{
    OM_uint32 major;

    major = makeStringBuffer(minor, "JANET(UK)", outputToken);
    if (GSS_ERROR(major))
        return major;

    return GSS_S_CONTINUE_NEEDED;
}
#endif

static OM_uint32
eapGssSmInitAcceptorName(OM_uint32 *minor,
                         gss_cred_id_t cred,
                         gss_ctx_id_t ctx,
                         gss_name_t target,
                         gss_OID mech,
                         OM_uint32 reqFlags,
                         OM_uint32 timeReq,
                         gss_channel_bindings_t chanBindings,
                         gss_buffer_t inputToken,
                         gss_buffer_t outputToken,
                         OM_uint32 *smFlags)
{
    OM_uint32 major;

    if (GSSEAP_SM_STATE(ctx) == GSSEAP_STATE_INITIAL &&
        ctx->acceptorName != GSS_C_NO_NAME) {

        /* Send desired target name to acceptor */
        major = gssEapDisplayName(minor, ctx->acceptorName,
                                  outputToken, NULL);
        if (GSS_ERROR(major))
            return major;
    } else if (inputToken != GSS_C_NO_BUFFER &&
               ctx->acceptorName == GSS_C_NO_NAME) {
        /* Accept target name hint from acceptor */
        major = gssEapImportName(minor, inputToken,
                                 GSS_C_NT_USER_NAME, &ctx->acceptorName);
        if (GSS_ERROR(major))
            return major;
    }

    /*
     * Currently, other parts of the code assume that the acceptor name
     * is available, hence this check.
     */
    if (ctx->acceptorName == GSS_C_NO_NAME) {
        *minor = GSSEAP_NO_ACCEPTOR_NAME;
        return GSS_S_FAILURE;
    }

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
gssEapSupportedAcceptorExts[] = {
    ITOK_TYPE_REAUTH_CREDS,
};

static struct gss_eap_itok_map
gssEapInitiatorExtsFlagMap[] = {
};

static OM_uint32
eapGssSmInitExts(OM_uint32 *minor,
                 gss_cred_id_t cred,
                 gss_ctx_id_t ctx,
                 gss_name_t target,
                 gss_OID mech,
                 OM_uint32 reqFlags,
                 OM_uint32 timeReq,
                 gss_channel_bindings_t chanBindings,
                 gss_buffer_t inputToken,
                 gss_buffer_t outputToken,
                 OM_uint32 *smFlags)
{
    OM_uint32 major;

    if (GSSEAP_SM_STATE(ctx) == GSSEAP_STATE_INITIAL) {
        major = gssEapEncodeExtensions(minor,
                                       gssEapSupportedAcceptorExts,
                                       sizeof(gssEapSupportedAcceptorExts) /
                                            sizeof(gssEapSupportedAcceptorExts[0]),
                                       outputToken);
    } else if (inputToken != GSS_C_NO_BUFFER) {
        major = gssEapProcessExtensions(minor, inputToken,
                                        gssEapInitiatorExtsFlagMap,
                                        sizeof(gssEapInitiatorExtsFlagMap) /
                                            sizeof(gssEapInitiatorExtsFlagMap[0]),
                                        &ctx->flags);
    }

    if (GSS_ERROR(major))
        return major;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmInitIdentity(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t ctx,
                     gss_name_t target,
                     gss_OID mech,
                     OM_uint32 reqFlags,
                     OM_uint32 timeReq,
                     gss_channel_bindings_t chanBindings,
                     gss_buffer_t inputToken,
                     gss_buffer_t outputToken,
                     OM_uint32 *smFlags)
{
    struct eap_config eapConfig;

#ifdef GSSEAP_ENABLE_REAUTH
    if (GSSEAP_SM_STATE(ctx) == GSSEAP_STATE_REAUTHENTICATE) {
        OM_uint32 tmpMinor;

        /* server didn't support reauthentication, sent EAP request */
        gssDeleteSecContext(&tmpMinor, &ctx->kerberosCtx, GSS_C_NO_BUFFER);
        ctx->flags &= ~(CTX_FLAG_KRB_REAUTH);
        GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_INITIAL);
    } else
#endif
        *smFlags |= SM_FLAG_FORCE_SEND_TOKEN;

    assert((ctx->flags & CTX_FLAG_KRB_REAUTH) == 0);
    assert(inputToken == GSS_C_NO_BUFFER);

    memset(&eapConfig, 0, sizeof(eapConfig));

    ctx->initiatorCtx.eap = eap_peer_sm_init(ctx,
                                             &gssEapPolicyCallbacks,
                                             ctx,
                                             &eapConfig);
    if (ctx->initiatorCtx.eap == NULL) {
        *minor = GSSEAP_PEER_SM_INIT_FAILURE;
        return GSS_S_FAILURE;
    }

    ctx->flags |= CTX_FLAG_EAP_RESTART | CTX_FLAG_EAP_PORT_ENABLED;

    /* poke EAP state machine */
    if (eap_peer_sm_step(ctx->initiatorCtx.eap) != 0) {
        *minor = GSSEAP_PEER_SM_STEP_FAILURE;
        return GSS_S_FAILURE;
    }

    GSSEAP_SM_TRANSITION_NEXT(ctx);

    *minor = 0;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmInitAuthenticate(OM_uint32 *minor,
                         gss_cred_id_t cred,
                         gss_ctx_id_t ctx,
                         gss_name_t target,
                         gss_OID mech,
                         OM_uint32 reqFlags,
                         OM_uint32 timeReq,
                         gss_channel_bindings_t chanBindings,
                         gss_buffer_t inputToken,
                         gss_buffer_t outputToken,
                         OM_uint32 *smFlags)
{
    OM_uint32 major;
    OM_uint32 tmpMinor;
    int code;
    struct wpabuf *resp = NULL;

    *minor = 0;

    assert(inputToken != GSS_C_NO_BUFFER);

    major = peerConfigInit(minor, cred, ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    assert(ctx->initiatorCtx.eap != NULL);
    assert(ctx->flags & CTX_FLAG_EAP_PORT_ENABLED);

    ctx->flags |= CTX_FLAG_EAP_REQ; /* we have a Request from the acceptor */

    wpabuf_set(&ctx->initiatorCtx.reqData,
               inputToken->value, inputToken->length);

    major = GSS_S_CONTINUE_NEEDED;

    code = eap_peer_sm_step(ctx->initiatorCtx.eap);
    if (ctx->flags & CTX_FLAG_EAP_RESP) {
        ctx->flags &= ~(CTX_FLAG_EAP_RESP);

        resp = eap_get_eapRespData(ctx->initiatorCtx.eap);
    } else if (ctx->flags & CTX_FLAG_EAP_SUCCESS) {
        major = initReady(minor, ctx, reqFlags);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->flags &= ~(CTX_FLAG_EAP_SUCCESS);
        major = GSS_S_CONTINUE_NEEDED;
        GSSEAP_SM_TRANSITION_NEXT(ctx);
    } else if (ctx->flags & CTX_FLAG_EAP_FAIL) {
        major = GSS_S_DEFECTIVE_CREDENTIAL;
        *minor = GSSEAP_PEER_AUTH_FAILURE;
    } else {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSEAP_PEER_BAD_MESSAGE;
    }

cleanup:
    if (resp != NULL) {
        OM_uint32 tmpMajor;
        gss_buffer_desc respBuf;

        assert(major == GSS_S_CONTINUE_NEEDED);

        respBuf.length = wpabuf_len(resp);
        respBuf.value = (void *)wpabuf_head(resp);

        tmpMajor = duplicateBuffer(&tmpMinor, &respBuf, outputToken);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
        }

        *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;
    }

    wpabuf_set(&ctx->initiatorCtx.reqData, NULL, 0);
    peerConfigFree(&tmpMinor, ctx);

    return major;
}

static OM_uint32
eapGssSmInitGssChannelBindings(OM_uint32 *minor,
                               gss_cred_id_t cred,
                               gss_ctx_id_t ctx,
                               gss_name_t target,
                               gss_OID mech,
                               OM_uint32 reqFlags,
                               OM_uint32 timeReq,
                               gss_channel_bindings_t chanBindings,
                               gss_buffer_t inputToken,
                               gss_buffer_t outputToken,
                               OM_uint32 *smFlags)
{
    OM_uint32 major;
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;

    if (ctx->flags & CTX_FLAG_KRB_REAUTH)
        return GSS_S_CONTINUE_NEEDED;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS)
        buffer = chanBindings->application_data;

    major = gssEapWrap(minor, ctx, TRUE, GSS_C_QOP_DEFAULT,
                       &buffer, NULL, outputToken);
    if (GSS_ERROR(major))
        return major;

    assert(outputToken->value != NULL);

    *minor = 0;
    *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;

    return GSS_S_CONTINUE_NEEDED;
}

#ifdef GSSEAP_ENABLE_REAUTH
static OM_uint32
eapGssSmInitReauthCreds(OM_uint32 *minor,
                        gss_cred_id_t cred,
                        gss_ctx_id_t ctx,
                        gss_name_t target,
                        gss_OID mech,
                        OM_uint32 reqFlags,
                        OM_uint32 timeReq,
                        gss_channel_bindings_t chanBindings,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken,
                        OM_uint32 *smFlags)
{
    OM_uint32 major;

    if (ctx->gssFlags & GSS_C_MUTUAL_FLAG) {
        major = gssEapStoreReauthCreds(minor, ctx, cred, inputToken);
        if (GSS_ERROR(major))
            return major;
    }

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}
#endif /* GSSEAP_ENABLE_REAUTH */

static OM_uint32
eapGssSmInitInitiatorMIC(OM_uint32 *minor,
                         gss_cred_id_t cred,
                         gss_ctx_id_t ctx,
                         gss_name_t target,
                         gss_OID mech,
                         OM_uint32 reqFlags,
                         OM_uint32 timeReq,
                         gss_channel_bindings_t chanBindings,
                         gss_buffer_t inputToken,
                         gss_buffer_t outputToken,
                         OM_uint32 *smFlags)
{
    OM_uint32 major;

    major = gssEapGetConversationMIC(minor, ctx, outputToken);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_SM_TRANSITION_NEXT(ctx);

    *minor = 0;
    *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmInitAcceptorMIC(OM_uint32 *minor,
                        gss_cred_id_t cred,
                        gss_ctx_id_t ctx,
                        gss_name_t target,
                        gss_OID mech,
                        OM_uint32 reqFlags,
                        OM_uint32 timeReq,
                        gss_channel_bindings_t chanBindings,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken,
                        OM_uint32 *smFlags)
{
    OM_uint32 major;

    major = gssEapVerifyConversationMIC(minor, ctx, inputToken);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_ESTABLISHED);

    *minor = 0;

    return GSS_S_COMPLETE;
}

static struct gss_eap_sm eapGssInitiatorSm[] = {
    {
        ITOK_TYPE_CONTEXT_ERR,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_ALL & ~(GSSEAP_STATE_INITIAL),
        0,
        eapGssSmInitError
    },
    {
        ITOK_TYPE_ACCEPTOR_NAME_RESP,
        ITOK_TYPE_ACCEPTOR_NAME_REQ,
        GSSEAP_STATE_INITIAL | GSSEAP_STATE_AUTHENTICATE,
        0,
        eapGssSmInitAcceptorName
    },
    {
        ITOK_TYPE_INITIATOR_EXTS,
        ITOK_TYPE_ACCEPTOR_EXTS,
        GSSEAP_STATE_INITIAL | GSSEAP_STATE_AUTHENTICATE,
        0,
        eapGssSmInitExts
    },
#ifdef GSSEAP_DEBUG
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_VENDOR_INFO,
        GSSEAP_STATE_INITIAL,
        0,
        eapGssSmInitVendorInfo
    },
#endif
#ifdef GSSEAP_ENABLE_REAUTH
    {
        ITOK_TYPE_REAUTH_RESP,
        ITOK_TYPE_REAUTH_REQ,
        GSSEAP_STATE_INITIAL | GSSEAP_STATE_REAUTHENTICATE,
        0,
        eapGssSmInitGssReauth
    },
#endif
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_NONE,
#ifdef GSSEAP_ENABLE_REAUTH
        GSSEAP_STATE_REAUTHENTICATE |
#endif
        GSSEAP_STATE_INITIAL,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitIdentity
    },
    {
        ITOK_TYPE_EAP_REQ,
        ITOK_TYPE_EAP_RESP,
        GSSEAP_STATE_AUTHENTICATE,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitAuthenticate
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_GSS_CHANNEL_BINDINGS,
        GSSEAP_STATE_INITIATOR_EXTS,
        0,
        eapGssSmInitGssChannelBindings
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_INITIATOR_MIC,
        GSSEAP_STATE_INITIATOR_EXTS,
        0,
        eapGssSmInitInitiatorMIC
    },
#ifdef GSSEAP_ENABLE_REAUTH
    {
        ITOK_TYPE_REAUTH_CREDS,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_ACCEPTOR_EXTS,
        0,
        eapGssSmInitReauthCreds
    },
#endif
    /* other extensions go here */
    {
        ITOK_TYPE_ACCEPTOR_MIC,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_ACCEPTOR_EXTS,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitAcceptorMIC
    }
};

OM_uint32
gss_init_sec_context(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t *context_handle,
                     gss_name_t target_name,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     gss_buffer_t input_token,
                     gss_OID *actual_mech_type,
                     gss_buffer_t output_token,
                     OM_uint32 *ret_flags,
                     OM_uint32 *time_rec)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = *context_handle;

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            *minor = GSSEAP_WRONG_SIZE;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        major = gssEapAllocContext(minor, &ctx);
        if (GSS_ERROR(major))
            return major;

        ctx->flags |= CTX_FLAG_INITIATOR;

        major = initBegin(minor, cred, ctx, target_name, mech_type,
                          req_flags, time_req, input_chan_bindings);
        if (GSS_ERROR(major)) {
            gssEapReleaseContext(minor, &ctx);
            return major;
        }

        *context_handle = ctx;
    }

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    if (cred == GSS_C_NO_CREDENTIAL) {
        if (ctx->defaultCred == GSS_C_NO_CREDENTIAL) {
            major = gssEapAcquireCred(minor,
                                      GSS_C_NO_NAME,
                                      GSS_C_NO_BUFFER,
                                      time_req,
                                      GSS_C_NO_OID_SET,
                                      GSS_C_INITIATE,
                                      &ctx->defaultCred,
                                      NULL,
                                      NULL);
            if (GSS_ERROR(major))
                goto cleanup;
        }

        cred = ctx->defaultCred;
    }

    GSSEAP_MUTEX_LOCK(&cred->mutex);


    if ((cred->flags & CRED_FLAG_INITIATE) == 0) {
        major = GSS_S_NO_CRED;
        *minor = GSSEAP_CRED_USAGE_MISMATCH;
        goto cleanup;
    }

    major = gssEapSmStep(minor,
                         cred,
                         ctx,
                         target_name,
                         mech_type,
                         req_flags,
                         time_req,
                         input_chan_bindings,
                         input_token,
                         output_token,
                         eapGssInitiatorSm,
                         sizeof(eapGssInitiatorSm) / sizeof(eapGssInitiatorSm[0]));
    if (GSS_ERROR(major))
        goto cleanup;

    if (actual_mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, actual_mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, actual_mech_type);
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (time_rec != NULL)
        gssEapContextTime(&tmpMinor, ctx, time_rec);

    assert(CTX_IS_ESTABLISHED(ctx) || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    if (cred != GSS_C_NO_CREDENTIAL)
        GSSEAP_MUTEX_UNLOCK(&cred->mutex);
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, context_handle);

    return major;
}
