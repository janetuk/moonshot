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
 * Context establishment state machine.
 */

#include "gssapiP_eap.h"

/* private flags */
#define SM_FLAG_TRANSITED                   0x80000000

#define SM_ASSERT_VALID(ctx, status)        do { \
        assert(GSS_ERROR((status)) || \
               ((status) == GSS_S_CONTINUE_NEEDED && ((ctx)->state > GSSEAP_STATE_INITIAL && (ctx)->state < GSSEAP_STATE_ESTABLISHED)) || \
               ((status) == GSS_S_COMPLETE && (ctx)->state == GSSEAP_STATE_ESTABLISHED)); \
    } while (0)

#ifdef GSSEAP_DEBUG
static const char *
gssEapStateToString(enum gss_eap_state state)
{
    const char *s;

    switch (state) {
    case GSSEAP_STATE_INITIAL:
        s = "INITIAL";
        break;
    case GSSEAP_STATE_AUTHENTICATE:
        s = "AUTHENTICATE";
        break;
    case GSSEAP_STATE_INITIATOR_EXTS:
        s = "INITIATOR_EXTS";
        break;
    case GSSEAP_STATE_ACCEPTOR_EXTS:
        s = "ACCEPTOR_EXTS";
        break;
#ifdef GSSEAP_ENABLE_REAUTH
    case GSSEAP_STATE_REAUTHENTICATE:
        s = "REAUTHENTICATE";
        break;
#endif
    case GSSEAP_STATE_ESTABLISHED:
        s = "ESTABLISHED";
        break;
    default:
        s = "INVALID";
        break;
    }

    return s;
}

void
gssEapSmTransition(gss_ctx_id_t ctx, enum gss_eap_state state)
{
    assert(state >= GSSEAP_STATE_INITIAL);
    assert(state <= GSSEAP_STATE_ESTABLISHED);

    fprintf(stderr, "GSS-EAP: state transition %s->%s\n",
            gssEapStateToString(GSSEAP_SM_STATE(ctx)),
            gssEapStateToString(state));

    ctx->state = state;
}
#endif /* GSSEAP_DEBUG */

static OM_uint32
recordErrorToken(OM_uint32 *minor,
                 gss_ctx_id_t ctx,
                 OM_uint32 majorStatus,
                 OM_uint32 minorStatus)
{
    unsigned char errorData[8];
    gss_buffer_desc errorBuffer;

    assert(GSS_ERROR(majorStatus));

    /*
     * Only return error codes that the initiator could have caused,
     * to avoid information leakage.
     */
    if (IS_RADIUS_ERROR(minorStatus)) {
        /* Squash RADIUS error codes */
        minorStatus = GSSEAP_RADIUS_PROT_FAILURE;
    } else if (!IS_WIRE_ERROR(minorStatus)) {
        /* Don't return non-wire error codes */
        return GSS_S_COMPLETE;
    }

    minorStatus -= ERROR_TABLE_BASE_eapg;

    store_uint32_be(majorStatus, &errorData[0]);
    store_uint32_be(minorStatus, &errorData[4]);

    errorBuffer.length = sizeof(errorData);
    errorBuffer.value = errorData;

    return gssEapRecordInnerContextToken(minor, ctx, &errorBuffer, 
                                         ITOK_TYPE_CONTEXT_ERR | ITOK_FLAG_CRITICAL);
}

static OM_uint32
makeContextToken(OM_uint32 *minor,
                 gss_ctx_id_t ctx,
                 size_t headerOffset,
                 gss_buffer_t outputToken)
{
    size_t tokSize, bodySize;
    unsigned char *p;

    assert(ctx->conversation.length > headerOffset);

    bodySize = ctx->conversation.length - headerOffset;
    tokSize = tokenSize(bodySize);

    outputToken->value = GSSEAP_MALLOC(tokSize);
    if (outputToken->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    outputToken->length = tokSize;

    p = (unsigned char *)outputToken->value;

    makeTokenHeader(bodySize, &p);
    memcpy(p, (unsigned char *)ctx->conversation.value + headerOffset, bodySize);

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapSmStep(OM_uint32 *minor,
             gss_cred_id_t cred,
             gss_ctx_id_t ctx,
             gss_name_t target,
             gss_OID mech,
             OM_uint32 reqFlags,
             OM_uint32 timeReq,
             gss_channel_bindings_t chanBindings,
             gss_buffer_t inputToken,
             gss_buffer_t outputToken,
             struct gss_eap_sm *sm, /* ordered by state */
             size_t smCount)
{
    OM_uint32 major, tmpMajor, tmpMinor;
    gss_buffer_desc unwrappedInputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc unwrappedOutputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_set_t innerInputTokens = GSS_C_NO_BUFFER_SET;
    OM_uint32 *inputTokenTypes = NULL, *outputTokenTypes = NULL;
    unsigned int smFlags = 0;
    size_t i, j;
    int initialContextToken = 0;
    enum gss_eap_token_type tokType;
    size_t headerOffset, firstTokenOffset;
    size_t innerOutputTokenCount = 0;

    assert(smCount > 0);

    *minor = 0;

    outputToken->length = 0;
    outputToken->value = NULL;

    if (inputToken != GSS_C_NO_BUFFER && inputToken->length != 0) {
        tokType = CTX_IS_INITIATOR(ctx) ?
            TOK_TYPE_ACCEPTOR_CONTEXT : TOK_TYPE_INITIATOR_CONTEXT;

        major = gssEapVerifyContextToken(minor, ctx, inputToken, tokType,
                                         &unwrappedInputToken);
        if (GSS_ERROR(major))
            goto cleanup;
    } else if (!CTX_IS_INITIATOR(ctx) || ctx->state != GSSEAP_STATE_INITIAL) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSEAP_WRONG_SIZE;
        goto cleanup;
    } else {
        initialContextToken = 1;
    }

    if (CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_BAD_STATUS;
        *minor = GSSEAP_CONTEXT_ESTABLISHED;
        goto cleanup;
    }

    assert(ctx->state < GSSEAP_STATE_ESTABLISHED);

    major = gssEapDecodeInnerTokens(minor, &unwrappedInputToken,
                                    &innerInputTokens, &inputTokenTypes);
    if (GSS_ERROR(major))
        goto cleanup;

    headerOffset = ctx->conversation.length;

    assert(innerInputTokens != GSS_C_NO_BUFFER_SET);

    /* Get ready to emit an output token */
    tokType = CTX_IS_INITIATOR(ctx) ?
        TOK_TYPE_INITIATOR_CONTEXT : TOK_TYPE_ACCEPTOR_CONTEXT;

    major = gssEapRecordContextTokenHeader(minor, ctx, tokType);
    if (GSS_ERROR(major))
        goto cleanup;

    firstTokenOffset = ctx->conversation.length;

    /* Process all the tokens that are valid for the current state. */
    for (i = 0; i < smCount; i++) {
        struct gss_eap_sm *smp = &sm[i];
        int processToken = 0;
        gss_buffer_t innerInputToken = GSS_C_NO_BUFFER;
        OM_uint32 *inputTokenType = NULL;
        gss_buffer_desc innerOutputToken = GSS_C_EMPTY_BUFFER;

        if ((smp->validStates & ctx->state) == 0)
            continue;

        /*
         * We special case the first call to gss_init_sec_context so that
         * all token providers have the opportunity to generate an initial
         * context token. Providers where inputTokenType is ITOK_TYPE_NONE
         * are always called and generally act on state transition boundaries,
         * for example to advance the state after a series of optional tokens
         * (as is the case with the extension token exchange) or to generate
         * a new token after the state was advanced by a provider which did
         * not emit a token.
         */
        if (smp->inputTokenType == ITOK_TYPE_NONE || initialContextToken) {
            processToken = 1;
        } else if ((smFlags & SM_FLAG_TRANSITED) == 0) {
            /* Don't regurgitate a token which belonds to a previous state. */
            for (j = 0; j < innerInputTokens->count; j++) {
                if ((inputTokenTypes[j] & ITOK_TYPE_MASK) == smp->inputTokenType) {
                    if (processToken) {
                        /* Check for duplicate inner tokens */
                        major = GSS_S_DEFECTIVE_TOKEN;
                        *minor = GSSEAP_DUPLICATE_ITOK;
                        break;
                    }
                    processToken = 1;
                    innerInputToken = &innerInputTokens->elements[j];
                    inputTokenType = &inputTokenTypes[j];
                }
            }
            if (GSS_ERROR(major))
                break;
        }

        if (processToken) {
            enum gss_eap_state oldState = ctx->state;

            smFlags = 0;
            if (inputTokenType != NULL && (*inputTokenType & ITOK_FLAG_CRITICAL))
                smFlags |= SM_FLAG_INPUT_TOKEN_CRITICAL;

            major = smp->processToken(minor, cred, ctx, target, mech, reqFlags,
                                      timeReq, chanBindings, innerInputToken,
                                      &innerOutputToken, &smFlags);
            if (GSS_ERROR(major))
                break;

            if (inputTokenType != NULL)
                *inputTokenType |= ITOK_FLAG_VERIFIED;
            if (ctx->state < oldState)
                i = 0; /* restart */
            else if (ctx->state != oldState)
                smFlags |= SM_FLAG_TRANSITED;

            if (innerOutputToken.value != NULL) {
                OM_uint32 outputTokenType = smp->outputTokenType;

                if (smFlags & SM_FLAG_OUTPUT_TOKEN_CRITICAL)
                    outputTokenType |= ITOK_FLAG_CRITICAL;

                assert(smp->outputTokenType != ITOK_TYPE_NONE);

                tmpMajor = gssEapRecordInnerContextToken(&tmpMinor, ctx,
                                                         &innerOutputToken,
                                                         outputTokenType);
                if (GSS_ERROR(tmpMajor)) {
                    major = tmpMajor;
                    *minor = tmpMinor;
                    break;
                }

                innerOutputTokenCount++;
            }

            /*
             * Break out if we made a state transition and have some tokens to send.
             */
            if (smFlags & SM_FLAG_SEND_TOKEN) {
                SM_ASSERT_VALID(ctx, major);
                break;
            }
        } else if ((smp->itokFlags & SM_ITOK_FLAG_REQUIRED) &&
            smp->inputTokenType != ITOK_TYPE_NONE) {
            /* Check for required inner tokens */
#ifdef GSSEAP_DEBUG
            fprintf(stderr, "GSS-EAP: missing required token %08X\n",
                    smp->inputTokenType);
#endif
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_MISSING_REQUIRED_ITOK;
            break;
        }
    }

    /* Check we understood all critical tokens sent by peer */
    if (!GSS_ERROR(major)) {
        for (j = 0; j < innerInputTokens->count; j++) {
            if ((inputTokenTypes[j] & ITOK_FLAG_CRITICAL) &&
                (inputTokenTypes[j] & ITOK_FLAG_VERIFIED) == 0) {
                major = GSS_S_UNAVAILABLE;
                *minor = GSSEAP_CRIT_ITOK_UNAVAILABLE;
                goto cleanup;
            }
        }
    }

    /* Optionaly emit an error token if we are the acceptor */
    if (GSS_ERROR(major)) {
        if (CTX_IS_INITIATOR(ctx))
            goto cleanup; /* return error directly to caller */

        /* replace any emitted tokens with error token */
        ctx->conversation.length = firstTokenOffset;

        tmpMajor = recordErrorToken(&tmpMinor, ctx, major, *minor);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }

        innerOutputTokenCount = 1;
    }

    /* Format output token from inner tokens */
    if (innerOutputTokenCount != 0 ||               /* inner tokens to send */
        !CTX_IS_INITIATOR(ctx) ||                   /* any leg acceptor */
        !CTX_IS_ESTABLISHED(ctx)) {                 /* non-last leg initiator */
        tmpMajor = makeContextToken(&tmpMinor, ctx, headerOffset, outputToken);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }

    /* If the context is established, empty tokens only to be emitted by initiator */
    assert(!CTX_IS_ESTABLISHED(ctx) || ((outputToken->length == 0) == CTX_IS_INITIATOR(ctx)));

    SM_ASSERT_VALID(ctx, major);

cleanup:
    gss_release_buffer_set(&tmpMinor, &innerInputTokens);
    if (inputTokenTypes != NULL)
        GSSEAP_FREE(inputTokenTypes);
    if (outputTokenTypes != NULL)
    gss_release_buffer(&tmpMinor, &unwrappedOutputToken);
        GSSEAP_FREE(outputTokenTypes);

    return major;
}
