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

#ifndef _GSSAPIP_EAP_H_
#define _GSSAPIP_EAP_H_ 1

#include "config.h"

#ifdef HAVE_HEIMDAL_VERSION
#define KRB5_DEPRECATED         /* so we can use krb5_free_unparsed_name() */
#endif

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>

/* GSS headers */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#ifndef HAVE_HEIMDAL_VERSION
#include <gssapi/gssapi_ext.h>
#endif
#include "gssapi_eap.h"

/* Kerberos headers */
#include <krb5.h>

/* EAP headers */
#include <common.h>
#include <eap_peer/eap.h>
#include <eap_peer/eap_config.h>
#include <eap_peer/eap_methods.h>
#include <eap_common/eap_common.h>
#include <wpabuf.h>

/* FreeRADIUS headers */
#ifdef __cplusplus
extern "C" {
#define operator fr_operator
#endif
#include <freeradius/libradius.h>
#include <freeradius/radius.h>
#include <radsec/radsec.h>
#include <radsec/request.h>
#ifdef __cplusplus
#undef operator
}
#endif

#include "gsseap_err.h"
#include "radsec_err.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* These name flags are informative and not actually used by anything yet */
#define NAME_FLAG_NAI                       0x00000001
#define NAME_FLAG_SERVICE                   0x00000002
#define NAME_FLAG_COMPOSITE                 0x00000004

struct gss_eap_saml_attr_ctx;
struct gss_eap_attr_ctx;

#ifdef HAVE_HEIMDAL_VERSION
struct gss_name_t_desc_struct
#else
struct gss_name_struct
#endif
{
    GSSEAP_MUTEX mutex; /* mutex protects attrCtx */
    OM_uint32 flags;
    krb5_principal krbPrincipal; /* this is immutable */
    struct gss_eap_attr_ctx *attrCtx;
};

#define CRED_FLAG_INITIATE                  0x00010000
#define CRED_FLAG_ACCEPT                    0x00020000
#define CRED_FLAG_DEFAULT_IDENTITY          0x00040000
#define CRED_FLAG_PASSWORD                  0x00080000
#define CRED_FLAG_DEFAULT_CCACHE            0x00100000
#define CRED_FLAG_PUBLIC_MASK               0x0000FFFF

#ifdef HAVE_HEIMDAL_VERSION
struct gss_cred_id_t_desc_struct
#else
struct gss_cred_id_struct
#endif
{
    GSSEAP_MUTEX mutex;
    OM_uint32 flags;
    gss_name_t name;
    gss_buffer_desc password;
    gss_OID_set mechanisms;
    time_t expiryTime;
    char *radiusConfigFile;
    char *radiusConfigStanza;
#ifdef GSSEAP_ENABLE_REAUTH
    krb5_ccache krbCredCache;
    gss_cred_id_t krbCred;
#endif
};

#define CTX_FLAG_INITIATOR                  0x00000001
#define CTX_FLAG_KRB_REAUTH                 0x00000002

#define CTX_IS_INITIATOR(ctx)               (((ctx)->flags & CTX_FLAG_INITIATOR) != 0)

enum gss_eap_state {
    GSSEAP_STATE_INITIAL        = 0x01,     /* initial state */
    GSSEAP_STATE_AUTHENTICATE   = 0x02,     /* exchange EAP messages */
    GSSEAP_STATE_INITIATOR_EXTS = 0x04,     /* initiator extensions */
    GSSEAP_STATE_ACCEPTOR_EXTS  = 0x08,     /* acceptor extensions */
    GSSEAP_STATE_ESTABLISHED    = 0x10,     /* context established */
    GSSEAP_STATE_ALL            = 0x1F
};

#define GSSEAP_STATE_NEXT(s)    ((s) << 1)

/* state machine entry */
struct gss_eap_sm {
    OM_uint32 inputTokenType;
    OM_uint32 outputTokenType;
    enum gss_eap_state validStates;
    int critical;
    int required;
    OM_uint32 (*processToken)(OM_uint32 *,
                              gss_cred_id_t,
                              gss_ctx_id_t,
                              gss_name_t,
                              gss_OID,
                              OM_uint32,
                              OM_uint32,
                              gss_channel_bindings_t,
                              gss_buffer_t,
                              gss_buffer_t,
                              OM_uint32 *);
};

#define SM_FLAG_TRANSITION                  0x00000001
#define SM_FLAG_FORCE_SEND_TOKEN            0x00000002
#define SM_FLAG_STOP_EVAL                   0x00000004

#define CTX_IS_ESTABLISHED(ctx)             ((ctx)->state == GSSEAP_STATE_ESTABLISHED)

/* Initiator context flags */
#define CTX_FLAG_EAP_SUCCESS                0x00010000
#define CTX_FLAG_EAP_RESTART                0x00020000
#define CTX_FLAG_EAP_FAIL                   0x00040000
#define CTX_FLAG_EAP_RESP                   0x00080000
#define CTX_FLAG_EAP_NO_RESP                0x00100000
#define CTX_FLAG_EAP_REQ                    0x00200000
#define CTX_FLAG_EAP_PORT_ENABLED           0x00400000
#define CTX_FLAG_EAP_ALT_ACCEPT             0x00800000
#define CTX_FLAG_EAP_ALT_REJECT             0x01000000
#define CTX_FLAG_EAP_MASK                   0xFFFF0000

struct gss_eap_initiator_ctx {
    unsigned int idleWhile;
#ifndef __cplusplus
    struct eap_peer_config eapPeerConfig;
    struct eap_sm *eap;
    struct wpabuf reqData;
#endif
};

struct gss_eap_acceptor_ctx {
    struct rs_context *radContext;
    struct rs_connection *radConn;
    char *radServer;
    gss_buffer_desc state;
    VALUE_PAIR *vps;
};

#ifdef HAVE_HEIMDAL_VERSION
struct gss_ctx_id_t_desc_struct
#else
struct gss_ctx_id_struct
#endif
{
    GSSEAP_MUTEX mutex;
    enum gss_eap_state state;
    OM_uint32 flags;
    OM_uint32 gssFlags;
    gss_OID mechanismUsed;
    krb5_cksumtype checksumType;
    krb5_enctype encryptionType;
    krb5_keyblock rfc3961Key;
    gss_name_t initiatorName;
    gss_name_t acceptorName;
    time_t expiryTime;
    uint64_t sendSeq, recvSeq;
    void *seqState;
    gss_cred_id_t defaultCred;
    union {
        struct gss_eap_initiator_ctx initiator;
        #define initiatorCtx         ctxU.initiator
        struct gss_eap_acceptor_ctx  acceptor;
        #define acceptorCtx          ctxU.acceptor
#ifdef GSSEAP_ENABLE_REAUTH
        gss_ctx_id_t                 kerberos;
        #define kerberosCtx          ctxU.kerberos
#endif
    } ctxU;
};

#define TOK_FLAG_SENDER_IS_ACCEPTOR         0x01
#define TOK_FLAG_WRAP_CONFIDENTIAL          0x02
#define TOK_FLAG_ACCEPTOR_SUBKEY            0x04

#define KEY_USAGE_ACCEPTOR_SEAL             22
#define KEY_USAGE_ACCEPTOR_SIGN             23
#define KEY_USAGE_INITIATOR_SEAL            24
#define KEY_USAGE_INITIATOR_SIGN            25

/* wrap_iov.c */
OM_uint32
gssEapWrapOrGetMIC(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int conf_req_flag,
                   int *conf_state,
                   gss_iov_buffer_desc *iov,
                   int iov_count,
                   enum gss_eap_token_type toktype);

OM_uint32
gssEapUnwrapOrVerifyMIC(OM_uint32 *minor_status,
                        gss_ctx_id_t ctx,
                        int *conf_state,
                        gss_qop_t *qop_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count,
                        enum gss_eap_token_type toktype);

OM_uint32
gssEapWrapIovLength(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count);
OM_uint32
gssEapWrap(OM_uint32 *minor,
           gss_ctx_id_t ctx,
           int conf_req_flag,
           gss_qop_t qop_req,
           gss_buffer_t input_message_buffer,
           int *conf_state,
           gss_buffer_t output_message_buffer);

unsigned char
rfc4121Flags(gss_ctx_id_t ctx, int receiving);

/* display_status.c */
void
gssEapSaveStatusInfo(OM_uint32 minor, const char *format, ...);

#define IS_WIRE_ERROR(err)              ((err) > GSSEAP_RESERVED && \
                                         (err) <= GSSEAP_RADIUS_PROT_FAILURE)

#ifdef __cplusplus
}
#endif

#endif /* _GSSAPIP_EAP_H_ */
