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
 * Portions Copyright 2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Name utility routines.
 */

#include "gssapiP_eap.h"

static gss_OID_desc gssEapNtPrincipalName = {
    /* 1.3.6.1.4.1.5322.22.2.1  */
    10, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x02\x01"
};

gss_OID GSS_EAP_NT_PRINCIPAL_NAME = &gssEapNtPrincipalName;

OM_uint32
gssEapAllocName(OM_uint32 *minor, gss_name_t *pName)
{
    OM_uint32 tmpMinor;
    gss_name_t name;

    *pName = GSS_C_NO_NAME;

    name = (gss_name_t)GSSEAP_CALLOC(1, sizeof(*name));
    if (name == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSEAP_MUTEX_INIT(&name->mutex) != 0) {
        *minor = errno;
        gssEapReleaseName(&tmpMinor, &name);
        return GSS_S_FAILURE;
    }

    *pName = name;

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseName(OM_uint32 *minor, gss_name_t *pName)
{
    gss_name_t name;
    krb5_context krbContext = NULL;
    OM_uint32 tmpMinor;

    *minor = 0;

    if (pName == NULL) {
        return GSS_S_COMPLETE;
    }

    name = *pName;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_COMPLETE;
    }

    GSSEAP_KRB_INIT(&krbContext);
    krb5_free_principal(krbContext, name->krbPrincipal);
    gssEapReleaseOid(&tmpMinor, &name->mechanismUsed);

    gssEapReleaseAttrContext(&tmpMinor, name);

    GSSEAP_MUTEX_DESTROY(&name->mutex);
    GSSEAP_FREE(name);
    *pName = NULL;

    return GSS_S_COMPLETE;
}

static OM_uint32
krbPrincipalToName(OM_uint32 *minor,
                   krb5_principal *principal,
                   gss_name_t *pName)
{
    OM_uint32 major;
    gss_name_t name;

    major = gssEapAllocName(minor, &name);
    if (GSS_ERROR(major))
        return major;

    name->krbPrincipal = *principal;
    *principal = NULL;

    if (KRB_PRINC_LENGTH(name->krbPrincipal) > 1) {
        name->flags |= NAME_FLAG_SERVICE;
    } else {
        name->flags |= NAME_FLAG_NAI;
    }

    *pName = name;
    *minor = 0;

    return GSS_S_COMPLETE;
}

static OM_uint32
importServiceName(OM_uint32 *minor,
                  const gss_buffer_t nameBuffer,
                  gss_name_t *pName)
{
    OM_uint32 major;
    krb5_context krbContext;
    krb5_principal krbPrinc;
    char *service, *host;

    GSSEAP_KRB_INIT(&krbContext);

    major = bufferToString(minor, nameBuffer, &service);
    if (GSS_ERROR(major))
        return major;

    host = strchr(service, '@');
    if (host != NULL) {
        *host = '\0';
        host++;
    }

    /* XXX this is probably NOT what we want to be doing */
    if (krb5_sname_to_principal(krbContext, host, service,
                                KRB5_NT_SRV_HST, &krbPrinc) != 0) {
        GSSEAP_FREE(service);
        *minor = GSSEAP_BAD_SERVICE_NAME;
        return GSS_S_FAILURE;
    }

    major = krbPrincipalToName(minor, &krbPrinc, pName);
    if (GSS_ERROR(major)) {
        krb5_free_principal(krbContext, krbPrinc);
    }

    GSSEAP_FREE(service);
    return major;
}

static OM_uint32
importUserName(OM_uint32 *minor,
               const gss_buffer_t nameBuffer,
               gss_name_t *pName)
{
    OM_uint32 major;
    krb5_context krbContext;
    krb5_principal krbPrinc;
    char *nameString, *realm = NULL;
    int flags = 0;
    krb5_error_code code;

    GSSEAP_KRB_INIT(&krbContext);

    code = krb5_get_default_realm(krbContext, &realm);
    if (code != 0 || realm == NULL)
        flags |= KRB5_PRINCIPAL_PARSE_REQUIRE_REALM;
    else
        krb5_free_default_realm(krbContext, realm);

    if (nameBuffer == GSS_C_NO_BUFFER) {
        *minor = krb5_copy_principal(krbContext,
                                     krbAnonymousPrincipal(), &krbPrinc);
        if (*minor != 0)
            return GSS_S_FAILURE;
    } else {
        major = bufferToString(minor, nameBuffer, &nameString);
        if (GSS_ERROR(major))
            return major;

        *minor = krb5_parse_name_flags(krbContext, nameString, flags, &krbPrinc);
        if (*minor != 0) {
            GSSEAP_FREE(nameString);
            return GSS_S_FAILURE;
        }
    }

    major = krbPrincipalToName(minor, &krbPrinc, pName);
    if (GSS_ERROR(major)) {
        krb5_free_principal(krbContext, krbPrinc);
    }

    GSSEAP_FREE(nameString);
    return major;
}

static OM_uint32
importAnonymousName(OM_uint32 *minor,
                    const gss_buffer_t nameBuffer GSSEAP_UNUSED,
                    gss_name_t *pName)
{
    OM_uint32 major;
    krb5_context krbContext;
    krb5_principal krbPrinc;

    GSSEAP_KRB_INIT(&krbContext);

    *minor = krb5_copy_principal(krbContext, krbAnonymousPrincipal(),
                                 &krbPrinc);
    if (*minor != 0)
        return GSS_S_FAILURE;

    major = krbPrincipalToName(minor, &krbPrinc, pName);
    if (GSS_ERROR(major)) {
        krb5_free_principal(krbContext, krbPrinc);
    }

    return major;
}

#define UPDATE_REMAIN(n)    do {            \
        p += (n);                           \
        remain -= (n);                      \
    } while (0)

#define CHECK_REMAIN(n)     do {        \
        if (remain < (n)) {             \
            major = GSS_S_BAD_NAME;     \
            *minor = GSSEAP_TOK_TRUNC;  \
            goto cleanup;               \
        }                               \
    } while (0)

OM_uint32
gssEapImportNameInternal(OM_uint32 *minor,
                         const gss_buffer_t nameBuffer,
                         gss_name_t *pName,
                         unsigned int flags)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    unsigned char *p;
    size_t len, remain;
    gss_buffer_desc buf;
    enum gss_eap_token_type tokType;
    gss_name_t name = GSS_C_NO_NAME;
    gss_OID mechanismUsed = GSS_C_NO_OID;

    GSSEAP_KRB_INIT(&krbContext);

    p = (unsigned char *)nameBuffer->value;
    remain = nameBuffer->length;

    if (flags & EXPORT_NAME_FLAG_OID) {
        gss_OID_desc mech;

        /* TOK_ID || MECH_OID_LEN || MECH_OID */
        if (remain < 6)
            return GSS_S_BAD_NAME;

        if (flags & EXPORT_NAME_FLAG_COMPOSITE)
            tokType = TOK_TYPE_EXPORT_NAME_COMPOSITE;
        else
            tokType = TOK_TYPE_EXPORT_NAME;

        /* TOK_ID */
        if (load_uint16_be(p) != tokType)
            return GSS_S_BAD_NAME;
        UPDATE_REMAIN(2);

        /* MECH_OID_LEN */
        len = load_uint16_be(p);
        if (len < 2)
            return GSS_S_BAD_NAME;
        UPDATE_REMAIN(2);

        /* MECH_OID */
        if (p[0] != 0x06)
            return GSS_S_BAD_NAME;

        mech.length = p[1];
        mech.elements = &p[2];

        CHECK_REMAIN(mech.length);

        major = gssEapCanonicalizeOid(minor,
                                      &mech,
                                      OID_FLAG_FAMILY_MECH_VALID |
                                        OID_FLAG_MAP_FAMILY_MECH_TO_NULL,
                                      &mechanismUsed);
        if (GSS_ERROR(major))
            goto cleanup;

        UPDATE_REMAIN(2 + mech.length);
    }

    /* NAME_LEN */
    CHECK_REMAIN(4);
    len = load_uint32_be(p);
    UPDATE_REMAIN(4);

    /* NAME */
    CHECK_REMAIN(len);
    buf.length = len;
    buf.value = p;
    UPDATE_REMAIN(len);

    major = importUserName(minor, &buf, &name);
    if (GSS_ERROR(major))
        goto cleanup;

    name->mechanismUsed = mechanismUsed;
    mechanismUsed = GSS_C_NO_OID;

    if (flags & EXPORT_NAME_FLAG_COMPOSITE) {
        gss_buffer_desc buf;

        buf.length = remain;
        buf.value = p;

        major = gssEapImportAttrContext(minor, &buf, name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major)) {
        gssEapReleaseOid(&tmpMinor, &mechanismUsed);
        gssEapReleaseName(&tmpMinor, &name);
    } else {
        *pName = name;
    }

    return major;
}

static OM_uint32
importExportName(OM_uint32 *minor,
                 const gss_buffer_t nameBuffer,
                 gss_name_t *name)
{
    return gssEapImportNameInternal(minor, nameBuffer, name,
                                    EXPORT_NAME_FLAG_OID);
}

#ifdef HAVE_GSS_C_NT_COMPOSITE_EXPORT
static OM_uint32
importCompositeExportName(OM_uint32 *minor,
                          const gss_buffer_t nameBuffer,
                          gss_name_t *name)
{
    return gssEapImportNameInternal(minor, nameBuffer, name,
                                    EXPORT_NAME_FLAG_OID |
                                    EXPORT_NAME_FLAG_COMPOSITE);
}
#endif

struct gss_eap_name_import_provider {
    gss_OID oid;
    OM_uint32 (*import)(OM_uint32 *, const gss_buffer_t, gss_name_t *);
};

OM_uint32
gssEapImportName(OM_uint32 *minor,
                 const gss_buffer_t nameBuffer,
                 gss_OID nameType,
                 gss_OID mechType,
                 gss_name_t *pName)
{
    struct gss_eap_name_import_provider nameTypes[] = {
        { GSS_C_NT_USER_NAME,               importUserName              },
        { GSS_EAP_NT_PRINCIPAL_NAME,        importUserName              },
        { GSS_C_NT_HOSTBASED_SERVICE,       importServiceName           },
        { GSS_C_NT_HOSTBASED_SERVICE_X,     importServiceName           },
        { GSS_C_NT_ANONYMOUS,               importAnonymousName         },
        { GSS_C_NT_EXPORT_NAME,             importExportName            },
#ifdef HAVE_GSS_C_NT_COMPOSITE_EXPORT
        { GSS_C_NT_COMPOSITE_EXPORT,        importCompositeExportName   },
#endif
    };
    size_t i;
    OM_uint32 major = GSS_S_BAD_NAMETYPE;
    OM_uint32 tmpMinor;
    gss_name_t name = GSS_C_NO_NAME;

    if (nameType == GSS_C_NO_OID)
        nameType = nameTypes[0].oid;

    for (i = 0; i < sizeof(nameTypes) / sizeof(nameTypes[0]); i++) {
        if (oidEqual(nameTypes[i].oid, nameType)) {
            major = nameTypes[i].import(minor, nameBuffer, &name);
            break;
        }
    }

    if (major == GSS_S_COMPLETE &&
        mechType != GSS_C_NO_OID) {
        assert(gssEapIsConcreteMechanismOid(mechType));
        assert(name->mechanismUsed == GSS_C_NO_OID);

        major = gssEapCanonicalizeOid(minor, mechType, 0, &name->mechanismUsed);
    }

    if (GSS_ERROR(major))
        gssEapReleaseName(&tmpMinor, &name);
    else
        *pName = name;

    return major;
}

OM_uint32
gssEapExportName(OM_uint32 *minor,
                 const gss_name_t name,
                 gss_buffer_t exportedName)
{
    return gssEapExportNameInternal(minor, name, exportedName,
                                    EXPORT_NAME_FLAG_OID);
}

OM_uint32
gssEapExportNameInternal(OM_uint32 *minor,
                         const gss_name_t name,
                         gss_buffer_t exportedName,
                         unsigned int flags)
{
    OM_uint32 major = GSS_S_FAILURE, tmpMinor;
    krb5_context krbContext;
    char *krbName = NULL;
    size_t krbNameLen, exportedNameLen;
    unsigned char *p;
    gss_buffer_desc attrs = GSS_C_EMPTY_BUFFER;
    gss_OID mech;

    exportedName->length = 0;
    exportedName->value = NULL;

    if (name->mechanismUsed != GSS_C_NO_OID)
        mech = name->mechanismUsed;
    else
        mech = GSS_EAP_MECHANISM;

    GSSEAP_KRB_INIT(&krbContext);

    *minor = krb5_unparse_name(krbContext, name->krbPrincipal, &krbName);
    if (*minor != 0) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }
    krbNameLen = strlen(krbName);

    exportedNameLen = 0;
    if (flags & EXPORT_NAME_FLAG_OID) {
        exportedNameLen += 6 + mech->length;
    }
    exportedNameLen += 4 + krbNameLen;
    if (flags & EXPORT_NAME_FLAG_COMPOSITE) {
        major = gssEapExportAttrContext(minor, name, &attrs);
        if (GSS_ERROR(major))
            goto cleanup;
        exportedNameLen += attrs.length;
    }

    exportedName->value = GSSEAP_MALLOC(exportedNameLen);
    if (exportedName->value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }
    exportedName->length = exportedNameLen;

    p = (unsigned char *)exportedName->value;

    if (flags & EXPORT_NAME_FLAG_OID) {
        /* TOK | MECH_OID_LEN */
        store_uint16_be((flags & EXPORT_NAME_FLAG_COMPOSITE)
                        ? TOK_TYPE_EXPORT_NAME_COMPOSITE
                        : TOK_TYPE_EXPORT_NAME,
                        p);
        p += 2;
        store_uint16_be(mech->length + 2, p);
        p += 2;

        /* MECH_OID */
        *p++ = 0x06;
        *p++ = mech->length & 0xff;
        memcpy(p, mech->elements, mech->length);
        p += mech->length;
    }

    /* NAME_LEN */
    store_uint32_be(krbNameLen, p);
    p += 4;

    /* NAME */
    memcpy(p, krbName, krbNameLen);
    p += krbNameLen;

    if (flags & EXPORT_NAME_FLAG_COMPOSITE) {
        memcpy(p, attrs.value, attrs.length);
        p += attrs.length;
    }

    assert(p == (unsigned char *)exportedName->value + exportedNameLen);

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    gss_release_buffer(&tmpMinor, &attrs);
    if (GSS_ERROR(major))
        gss_release_buffer(&tmpMinor, exportedName);
    krb5_free_unparsed_name(krbContext, krbName);

    return major;
}

OM_uint32
gssEapCanonicalizeName(OM_uint32 *minor,
                       const gss_name_t input_name,
                       const gss_OID mech_type,
                       gss_name_t *dest_name)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    gss_name_t name;
    gss_OID mech_used;

    if (input_name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;
    }

    GSSEAP_KRB_INIT(&krbContext);

    major = gssEapAllocName(minor, &name);
    if (GSS_ERROR(major)) {
        return major;
    }

    if (mech_type != GSS_C_NO_OID)
        mech_used = mech_type;
    else
        mech_used = input_name->mechanismUsed;

    major = gssEapCanonicalizeOid(minor,
                                  mech_used,
                                  OID_FLAG_NULL_VALID,
                                  &name->mechanismUsed);
    if (GSS_ERROR(major))
        goto cleanup;

    name->flags = input_name->flags;

    *minor = krb5_copy_principal(krbContext, input_name->krbPrincipal,
                                 &name->krbPrincipal);
    if (*minor != 0) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    if (input_name->attrCtx != NULL) {
        major = gssEapDuplicateAttrContext(minor, input_name, name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    *dest_name = name;

cleanup:
    if (GSS_ERROR(major)) {
        gssEapReleaseName(&tmpMinor, &name);
    }

    return major;
}

OM_uint32
gssEapDuplicateName(OM_uint32 *minor,
                    const gss_name_t input_name,
                    gss_name_t *dest_name)
{
    return gssEapCanonicalizeName(minor, input_name,
                                  GSS_C_NO_OID, dest_name);
}

OM_uint32
gssEapDisplayName(OM_uint32 *minor,
                  gss_name_t name,
                  gss_buffer_t output_name_buffer,
                  gss_OID *output_name_type)
{
    OM_uint32 major;
    krb5_context krbContext;
    char *krbName;
    gss_OID name_type;

    GSSEAP_KRB_INIT(&krbContext);

    output_name_buffer->length = 0;
    output_name_buffer->value = NULL;

    if (name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;
    }

    *minor = krb5_unparse_name(krbContext, name->krbPrincipal, &krbName);
    if (*minor != 0) {
        return GSS_S_FAILURE;
    }

    major = makeStringBuffer(minor, krbName, output_name_buffer);
    if (GSS_ERROR(major)) {
        krb5_free_unparsed_name(krbContext, krbName);
        return major;
    }

    krb5_free_unparsed_name(krbContext, krbName);

    if (KRB_PRINC_TYPE(name->krbPrincipal) == KRB5_NT_WELLKNOWN &&
        krb5_principal_compare(krbContext,
                               name->krbPrincipal, krbAnonymousPrincipal())) {
        name_type = GSS_C_NT_ANONYMOUS;
    } else {
        name_type = GSS_EAP_NT_PRINCIPAL_NAME;
    }

    if (output_name_type != NULL)
        *output_name_type = name_type;

    return GSS_S_COMPLETE;
}
