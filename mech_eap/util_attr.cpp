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
 * Attribute provider mechanism.
 */

#include "gssapiP_eap.h"

#include <typeinfo>
#include <string>
#include <sstream>
#include <exception>
#include <stdexcept>
#include <new>

/* lazy initialisation */
static GSSEAP_THREAD_ONCE gssEapAttrProvidersInitOnce = GSSEAP_ONCE_INITIALIZER;
static OM_uint32 gssEapAttrProvidersInitStatus = GSS_S_UNAVAILABLE;

static void
gssEapAttrProvidersInitInternal(void)
{
    OM_uint32 major, minor;

    assert(gssEapAttrProvidersInitStatus == GSS_S_UNAVAILABLE);

    major = gssEapRadiusAttrProviderInit(&minor);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssEapSamlAttrProvidersInit(&minor);
    if (GSS_ERROR(major))
        goto cleanup;

    /* Allow Shibboleth initialization failure to be non-fatal */
    gssEapLocalAttrProviderInit(&minor);

cleanup:
#ifdef GSSEAP_DEBUG
    assert(major == GSS_S_COMPLETE);
#endif

    gssEapAttrProvidersInitStatus = major;
}

static OM_uint32
gssEapAttrProvidersInit(OM_uint32 *minor)
{
    GSSEAP_ONCE(&gssEapAttrProvidersInitOnce, gssEapAttrProvidersInitInternal);

    if (GSS_ERROR(gssEapAttrProvidersInitStatus))
        *minor = GSSEAP_NO_ATTR_PROVIDERS;

    return gssEapAttrProvidersInitStatus;
}

OM_uint32
gssEapAttrProvidersFinalize(OM_uint32 *minor)
{
    OM_uint32 major = GSS_S_COMPLETE;

    if (gssEapAttrProvidersInitStatus == GSS_S_COMPLETE) {
        major = gssEapLocalAttrProviderFinalize(minor);
        if (major == GSS_S_COMPLETE)
            major = gssEapSamlAttrProvidersFinalize(minor);
        if (major == GSS_S_COMPLETE)
            major = gssEapRadiusAttrProviderFinalize(minor);

        gssEapAttrProvidersInitStatus = GSS_S_UNAVAILABLE;
    }

    return major;
}

static gss_eap_attr_create_provider gssEapAttrFactories[ATTR_TYPE_MAX + 1];

/*
 * Register a provider for a particular type and prefix
 */
void
gss_eap_attr_ctx::registerProvider(unsigned int type,
                                   gss_eap_attr_create_provider factory)
{
    assert(type <= ATTR_TYPE_MAX);

    assert(gssEapAttrFactories[type] == NULL);

    gssEapAttrFactories[type] = factory;
}

/*
 * Unregister a provider
 */
void
gss_eap_attr_ctx::unregisterProvider(unsigned int type)
{
    assert(type <= ATTR_TYPE_MAX);

    gssEapAttrFactories[type] = NULL;
}

/*
 * Create an attribute context, that manages instances of providers
 */
gss_eap_attr_ctx::gss_eap_attr_ctx(void)
{
    m_flags = 0;

    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        if (gssEapAttrFactories[i] != NULL) {
            provider = (gssEapAttrFactories[i])();
        } else {
            provider = NULL;
        }

        m_providers[i] = provider;
    }
}

/*
 * Convert an attribute prefix to a type
 */
unsigned int
gss_eap_attr_ctx::attributePrefixToType(const gss_buffer_t prefix) const
{
    unsigned int i;

    for (i = ATTR_TYPE_MIN; i < ATTR_TYPE_MAX; i++) {
        const char *pprefix;

        if (!providerEnabled(i))
            continue;

        pprefix = m_providers[i]->prefix();
        if (pprefix == NULL)
            continue;

        if (strlen(pprefix) == prefix->length &&
            memcmp(pprefix, prefix->value, prefix->length) == 0)
            return i;
    }

    return ATTR_TYPE_LOCAL;
}

/*
 * Convert a type to an attribute prefix
 */
gss_buffer_desc
gss_eap_attr_ctx::attributeTypeToPrefix(unsigned int type) const
{
    gss_buffer_desc prefix = GSS_C_EMPTY_BUFFER;

    if (type < ATTR_TYPE_MIN || type >= ATTR_TYPE_MAX)
        return prefix;

    if (!providerEnabled(type))
        return prefix;

    prefix.value = (void *)m_providers[type]->prefix();
    if (prefix.value != NULL)
        prefix.length = strlen((char *)prefix.value);

    return prefix;
}

bool
gss_eap_attr_ctx::providerEnabled(unsigned int type) const
{
    if (type == ATTR_TYPE_LOCAL &&
        (m_flags & ATTR_FLAG_DISABLE_LOCAL))
        return false;

    if (m_providers[type] == NULL)
        return false;

    return true;
}

void
gss_eap_attr_ctx::releaseProvider(unsigned int type)
{
    delete m_providers[type];
    m_providers[type] = NULL;
}

/*
 * Initialize a context from an existing context.
 */
bool
gss_eap_attr_ctx::initFromExistingContext(const gss_eap_attr_ctx *manager)
{
    bool ret = true;

    m_flags = manager->m_flags;

    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        if (!providerEnabled(i)) {
            releaseProvider(i);
            continue;
        }

        provider = m_providers[i];

        ret = provider->initFromExistingContext(this,
                                                manager->m_providers[i]);
        if (ret == false) {
            releaseProvider(i);
            break;
        }
    }

    return ret;
}

/*
 * Initialize a context from a GSS credential and context.
 */
bool
gss_eap_attr_ctx::initFromGssContext(const gss_cred_id_t cred,
                                     const gss_ctx_id_t ctx)
{
    bool ret = true;

    if (cred != GSS_C_NO_CREDENTIAL &&
        (cred->flags & GSS_EAP_DISABLE_LOCAL_ATTRS_FLAG)) {
        m_flags |= ATTR_FLAG_DISABLE_LOCAL;
    }

    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        if (!providerEnabled(i)) {
            releaseProvider(i);
            continue;
        }

        provider = m_providers[i];

        ret = provider->initFromGssContext(this, cred, ctx);
        if (ret == false) {
            releaseProvider(i);
            break;
        }
    }

    return ret;
}

bool
gss_eap_attr_ctx::initWithJsonObject(JSONObject &obj)
{
    bool ret = false;
    bool foundSource[ATTR_TYPE_MAX + 1];
    unsigned int type;

    for (type = ATTR_TYPE_MIN; type <= ATTR_TYPE_MAX; type++)
        foundSource[type] = false;

    if (obj["version"].integer() != 1)
        return false;

    m_flags = obj["flags"].integer();

    JSONObject sources = obj["sources"];

    /* Initialize providers from serialized state */
    for (type = ATTR_TYPE_MIN; type <= ATTR_TYPE_MAX; type++) {
        gss_eap_attr_provider *provider;
        const char *key;

        if (!providerEnabled(type)) {
            releaseProvider(type);
            continue;
        }

        provider = m_providers[type];
        key = provider->name();
        if (key == NULL)
            continue;

        JSONObject source = sources.get(key);
        if (!source.isnull() &&
            !provider->initWithJsonObject(this, source)) {
            releaseProvider(type);
            return false;
        }

        foundSource[type] = true;
    }

    /* Initialize remaining providers from initialized providers */
    for (type = ATTR_TYPE_MIN; type <= ATTR_TYPE_MAX; type++) {
        gss_eap_attr_provider *provider;

        if (foundSource[type] || !providerEnabled(type))
            continue;

        provider = m_providers[type];

        ret = provider->initFromGssContext(this,
                                           GSS_C_NO_CREDENTIAL,
                                           GSS_C_NO_CONTEXT);
        if (ret == false) {
            releaseProvider(type);
            return false;
        }
    }

    return true;
}

JSONObject
gss_eap_attr_ctx::jsonRepresentation(void) const
{
    JSONObject obj, sources;
    unsigned int i;

    obj.set("version", 1);
    obj.set("flags", m_flags);

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;
        const char *key;

        provider = m_providers[i];
        if (provider == NULL)
            continue; /* provider not initialised */

        key = provider->name();
        if (key == NULL)
            continue; /* provider does not have state */

        JSONObject source = provider->jsonRepresentation();
        sources.set(key, source);
    }

    obj.set("sources", sources);

    return obj;
}

/*
 * Initialize a context from an exported context or name token
 */
bool
gss_eap_attr_ctx::initFromBuffer(const gss_buffer_t buffer)
{
    OM_uint32 major, minor;
    bool ret;
    char *s;
    json_error_t error;

    major = bufferToString(&minor, buffer, &s);
    if (GSS_ERROR(major))
        return false;

    JSONObject obj = JSONObject::load(s, 0, &error);
    if (!obj.isnull()) {
        ret = initWithJsonObject(obj);
    } else
        ret = false;

    GSSEAP_FREE(s);

    return ret;
}

gss_eap_attr_ctx::~gss_eap_attr_ctx(void)
{
    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++)
        delete m_providers[i];
}

/*
 * Locate provider for a given type
 */
gss_eap_attr_provider *
gss_eap_attr_ctx::getProvider(unsigned int type) const
{
    assert(type >= ATTR_TYPE_MIN && type <= ATTR_TYPE_MAX);
    return m_providers[type];
}

/*
 * Get primary provider. Only the primary provider is serialised when
 * gss_export_sec_context() or gss_export_name_composite() is called.
 */
gss_eap_attr_provider *
gss_eap_attr_ctx::getPrimaryProvider(void) const
{
    return m_providers[ATTR_TYPE_MIN];
}

/*
 * Set an attribute
 */
bool
gss_eap_attr_ctx::setAttribute(int complete,
                               const gss_buffer_t attr,
                               const gss_buffer_t value)
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    gss_eap_attr_provider *provider;
    bool ret = false;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL) {
        ret = provider->setAttribute(complete,
                                     (type == ATTR_TYPE_LOCAL) ? attr : &suffix,
                                     value);
    }

    return ret;
}

/*
 * Delete an attrbiute
 */
bool
gss_eap_attr_ctx::deleteAttribute(const gss_buffer_t attr)
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    gss_eap_attr_provider *provider;
    bool ret = false;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL) {
        ret = provider->deleteAttribute(type == ATTR_TYPE_LOCAL ? attr : &suffix);
    }

    return ret;
}

/*
 * Enumerate attribute types with callback
 */
bool
gss_eap_attr_ctx::getAttributeTypes(gss_eap_attr_enumeration_cb cb, void *data) const
{
    bool ret = false;
    size_t i;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider = m_providers[i];

        if (provider == NULL)
            continue;

        ret = provider->getAttributeTypes(cb, data);
        if (ret == false)
            break;
    }

    return ret;
}

struct eap_gss_get_attr_types_args {
    unsigned int type;
    gss_buffer_set_t attrs;
};

static bool
addAttribute(const gss_eap_attr_ctx *manager,
             const gss_eap_attr_provider *provider GSSEAP_UNUSED,
             const gss_buffer_t attribute,
             void *data)
{
    eap_gss_get_attr_types_args *args = (eap_gss_get_attr_types_args *)data;
    gss_buffer_desc qualified;
    OM_uint32 major, minor;

    if (args->type != ATTR_TYPE_LOCAL) {
        manager->composeAttributeName(args->type, attribute, &qualified);
        major = gss_add_buffer_set_member(&minor, &qualified, &args->attrs);
        gss_release_buffer(&minor, &qualified);
    } else {
        major = gss_add_buffer_set_member(&minor, attribute, &args->attrs);
    }

    return GSS_ERROR(major) == false;
}

/*
 * Enumerate attribute types, output is buffer set
 */
bool
gss_eap_attr_ctx::getAttributeTypes(gss_buffer_set_t *attrs)
{
    eap_gss_get_attr_types_args args;
    OM_uint32 major, minor;
    bool ret = false;
    unsigned int i;

    major = gss_create_empty_buffer_set(&minor, attrs);
    if (GSS_ERROR(major))
        throw new std::bad_alloc;

    args.attrs = *attrs;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider = m_providers[i];

        args.type = i;

        if (provider == NULL)
            continue;

        ret = provider->getAttributeTypes(addAttribute, (void *)&args);
        if (ret == false)
            break;
    }

    if (ret == false)
        gss_release_buffer_set(&minor, attrs);

    return ret;
}

/*
 * Get attribute with given name
 */
bool
gss_eap_attr_ctx::getAttribute(const gss_buffer_t attr,
                               int *authenticated,
                               int *complete,
                               gss_buffer_t value,
                               gss_buffer_t display_value,
                               int *more) const
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    gss_eap_attr_provider *provider;
    bool ret;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider == NULL)
        return false;

    ret = provider->getAttribute(type == ATTR_TYPE_LOCAL ? attr : &suffix,
                                 authenticated, complete,
                                 value, display_value, more);

    return ret;
}

/*
 * Map attribute context to C++ object
 */
gss_any_t
gss_eap_attr_ctx::mapToAny(int authenticated,
                           gss_buffer_t type_id) const
{
    unsigned int type;
    gss_eap_attr_provider *provider;
    gss_buffer_desc suffix;

    decomposeAttributeName(type_id, &type, &suffix);

    provider = m_providers[type];
    if (provider == NULL)
        return (gss_any_t)NULL;

    return provider->mapToAny(authenticated, &suffix);
}

/*
 * Release mapped context
 */
void
gss_eap_attr_ctx::releaseAnyNameMapping(gss_buffer_t type_id,
                                        gss_any_t input) const
{
    unsigned int type;
    gss_eap_attr_provider *provider;
    gss_buffer_desc suffix;

    decomposeAttributeName(type_id, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL)
        provider->releaseAnyNameMapping(&suffix, input);
}

/*
 * Export attribute context to buffer
 */
void
gss_eap_attr_ctx::exportToBuffer(gss_buffer_t buffer) const
{
    OM_uint32 minor;
    char *s;

    JSONObject obj = jsonRepresentation();

#if 0
    obj.dump(stdout);
#endif

    s = obj.dump(JSON_COMPACT);

    if (GSS_ERROR(makeStringBuffer(&minor, s, buffer)))
        throw new std::bad_alloc;
}

/*
 * Return soonest expiry time of providers
 */
time_t
gss_eap_attr_ctx::getExpiryTime(void) const
{
    unsigned int i;
    time_t expiryTime = 0;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider = m_providers[i];
        time_t providerExpiryTime;

        if (provider == NULL)
            continue;

        providerExpiryTime = provider->getExpiryTime();
        if (providerExpiryTime == 0)
            continue;

        if (expiryTime == 0 || providerExpiryTime < expiryTime)
            expiryTime = providerExpiryTime;
    }

    return expiryTime;
}

OM_uint32
gss_eap_attr_ctx::mapException(OM_uint32 *minor, std::exception &e) const
{
    unsigned int i;
    OM_uint32 major;

    /* Errors we handle ourselves */
    if (typeid(e) == typeid(std::bad_alloc)) {
        *minor = ENOMEM;
        goto cleanup;
    } else if (typeid(e) == typeid(std::runtime_error)) {
        major = GSS_S_BAD_NAME;
        *minor = GSSEAP_BAD_ATTR_TOKEN;
        goto cleanup;
    } else if (this == NULL) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    /* Errors we delegate to providers */
    major = GSS_S_CONTINUE_NEEDED;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider = m_providers[i];

        if (provider == NULL)
            continue;

        major = provider->mapException(minor, e);
        if (major != GSS_S_CONTINUE_NEEDED)
            break;
    }

    if (major == GSS_S_CONTINUE_NEEDED) {
        *minor = GSSEAP_ATTR_CONTEXT_FAILURE;
        major = GSS_S_FAILURE;
    }

cleanup:
#if 0
    /* rethrow for now for debugging */
    throw e;
#endif

    assert(GSS_ERROR(major));

    return major;
}

/*
 * Decompose attribute name into prefix and suffix
 */
void
gss_eap_attr_ctx::decomposeAttributeName(const gss_buffer_t attribute,
                                         gss_buffer_t prefix,
                                         gss_buffer_t suffix)
{
    char *p = NULL;
    size_t i;

    for (i = 0; i < attribute->length; i++) {
        if (((char *)attribute->value)[i] == ' ') {
            p = (char *)attribute->value + i + 1;
            break;
        }
    }

    prefix->value = attribute->value;
    prefix->length = i;

    if (p != NULL && *p != '\0')  {
        suffix->length = attribute->length - 1 - prefix->length;
        suffix->value = p;
    } else {
        suffix->length = 0;
        suffix->value = NULL;
    }
}

/*
 * Decompose attribute name into type and suffix
 */
void
gss_eap_attr_ctx::decomposeAttributeName(const gss_buffer_t attribute,
                                         unsigned int *type,
                                         gss_buffer_t suffix) const
{
    gss_buffer_desc prefix = GSS_C_EMPTY_BUFFER;

    decomposeAttributeName(attribute, &prefix, suffix);
    *type = attributePrefixToType(&prefix);
}

/*
 * Compose attribute name from prefix, suffix; returns C++ string
 */
std::string
gss_eap_attr_ctx::composeAttributeName(const gss_buffer_t prefix,
                                       const gss_buffer_t suffix)
{
    std::string str;

    if (prefix == GSS_C_NO_BUFFER || prefix->length == 0)
        return str;

    str.append((const char *)prefix->value, prefix->length);

    if (suffix != GSS_C_NO_BUFFER) {
        str.append(" ");
        str.append((const char *)suffix->value, suffix->length);
    }

    return str;
}

/*
 * Compose attribute name from type, suffix; returns C++ string
 */
std::string
gss_eap_attr_ctx::composeAttributeName(unsigned int type,
                                       const gss_buffer_t suffix)
{
    gss_buffer_desc prefix = attributeTypeToPrefix(type);

    return composeAttributeName(&prefix, suffix);
}

/*
 * Compose attribute name from prefix, suffix; returns GSS buffer
 */
void
gss_eap_attr_ctx::composeAttributeName(const gss_buffer_t prefix,
                                       const gss_buffer_t suffix,
                                       gss_buffer_t attribute)
{
    std::string str = composeAttributeName(prefix, suffix);

    if (str.length() != 0) {
        return duplicateBuffer(str, attribute);
    } else {
        attribute->length = 0;
        attribute->value = NULL;
    }
}

/*
 * Compose attribute name from type, suffix; returns GSS buffer
 */
void
gss_eap_attr_ctx::composeAttributeName(unsigned int type,
                                       const gss_buffer_t suffix,
                                       gss_buffer_t attribute) const
{
    gss_buffer_desc prefix = attributeTypeToPrefix(type);

    return composeAttributeName(&prefix, suffix, attribute);
}

/*
 * C wrappers
 */
OM_uint32
gssEapInquireName(OM_uint32 *minor,
                  gss_name_t name,
                  int *name_is_MN,
                  gss_OID *MN_mech,
                  gss_buffer_set_t *attrs)
{
    OM_uint32 major;

    if (name_is_MN != NULL)
        *name_is_MN = (name->mechanismUsed != GSS_C_NULL_OID);

    if (MN_mech != NULL) {
        major = gssEapCanonicalizeOid(minor, name->mechanismUsed,
                                      OID_FLAG_NULL_VALID, MN_mech);
        if (GSS_ERROR(major))
            return major;
    }

    if (name->attrCtx == NULL) {
        *minor = GSSEAP_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor))) {
        return GSS_S_UNAVAILABLE;
    }

    if (attrs != NULL) {
        try {
            if (!name->attrCtx->getAttributeTypes(attrs)) {
                *minor = GSSEAP_NO_ATTR_CONTEXT;
                return GSS_S_UNAVAILABLE;
            }
        } catch (std::exception &e) {
            return name->attrCtx->mapException(minor, e);
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapGetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       int *authenticated,
                       int *complete,
                       gss_buffer_t value,
                       gss_buffer_t display_value,
                       int *more)
{
    if (authenticated != NULL)
        *authenticated = 0;
    if (complete != NULL)
        *complete = 0;

    if (value != NULL) {
        value->length = 0;
        value->value = NULL;
    }

    if (display_value != NULL) {
        display_value->length = 0;
        display_value->value = NULL;
    }

    if (name->attrCtx == NULL) {
        *minor = GSSEAP_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor))) {
        return GSS_S_UNAVAILABLE;
    }

    try {
        if (!name->attrCtx->getAttribute(attr, authenticated, complete,
                                         value, display_value, more)) {
            *minor = GSSEAP_NO_SUCH_ATTR;
            gssEapSaveStatusInfo(*minor, "Unknown naming attribute %.*s",
                                 (int)attr->length, (char *)attr->value);
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapDeleteNameAttribute(OM_uint32 *minor,
                          gss_name_t name,
                          gss_buffer_t attr)
{
    if (name->attrCtx == NULL) {
        *minor = GSSEAP_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (!name->attrCtx->deleteAttribute(attr)) {
            *minor = GSSEAP_NO_SUCH_ATTR;
            gssEapSaveStatusInfo(*minor, "Unknown naming attribute %.*s",
                                 (int)attr->length, (char *)attr->value);
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapSetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       int complete,
                       gss_buffer_t attr,
                       gss_buffer_t value)
{
    if (name->attrCtx == NULL) {
        *minor = GSSEAP_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (!name->attrCtx->setAttribute(complete, attr, value)) {
             *minor = GSSEAP_NO_SUCH_ATTR;
            gssEapSaveStatusInfo(*minor, "Unknown naming attribute %.*s",
                                 (int)attr->length, (char *)attr->value);
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapExportAttrContext(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t buffer)
{
    if (name->attrCtx == NULL) {
        buffer->length = 0;
        buffer->value = NULL;

        return GSS_S_COMPLETE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        name->attrCtx->exportToBuffer(buffer);
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapImportAttrContext(OM_uint32 *minor,
                        gss_buffer_t buffer,
                        gss_name_t name)
{
    gss_eap_attr_ctx *ctx = NULL;

    assert(name->attrCtx == NULL);

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    if (buffer->length != 0) {
        try {
            ctx = new gss_eap_attr_ctx();

            if (!ctx->initFromBuffer(buffer)) {
                delete ctx;
                *minor = GSSEAP_BAD_ATTR_TOKEN;
                return GSS_S_BAD_NAME;
            }
            name->attrCtx = ctx;
        } catch (std::exception &e) {
            delete ctx;
            return name->attrCtx->mapException(minor, e);
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapDuplicateAttrContext(OM_uint32 *minor,
                           gss_name_t in,
                           gss_name_t out)
{
    gss_eap_attr_ctx *ctx = NULL;

    assert(out->attrCtx == NULL);

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (in->attrCtx != NULL) {
            ctx = new gss_eap_attr_ctx();
            if (!ctx->initFromExistingContext(in->attrCtx)) {
                delete ctx;
                *minor = GSSEAP_ATTR_CONTEXT_FAILURE;
                return GSS_S_FAILURE;
            }
            out->attrCtx = ctx;
        }
    } catch (std::exception &e) {
        delete ctx;
        return in->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapMapNameToAny(OM_uint32 *minor,
                   gss_name_t name,
                   int authenticated,
                   gss_buffer_t type_id,
                   gss_any_t *output)
{
    if (name->attrCtx == NULL) {
        *minor = GSSEAP_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        *output = name->attrCtx->mapToAny(authenticated, type_id);
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseAnyNameMapping(OM_uint32 *minor,
                            gss_name_t name,
                            gss_buffer_t type_id,
                            gss_any_t *input)
{
    if (name->attrCtx == NULL) {
        *minor = GSSEAP_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssEapAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (*input != NULL)
            name->attrCtx->releaseAnyNameMapping(type_id, *input);
        *input = NULL;
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseAttrContext(OM_uint32 *minor,
                         gss_name_t name)
{
    if (name->attrCtx != NULL)
        delete name->attrCtx;

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Public accessor for initialisng a context from a GSS context. Also
 * sets expiry time on GSS context as a side-effect.
 */
OM_uint32
gssEapCreateAttrContext(OM_uint32 *minor,
                        gss_cred_id_t gssCred,
                        gss_ctx_id_t gssCtx,
                        struct gss_eap_attr_ctx **pAttrContext,
                        time_t *pExpiryTime)
{
    gss_eap_attr_ctx *ctx = NULL;
    OM_uint32 major;

    assert(gssCtx != GSS_C_NO_CONTEXT);

    major = gssEapAttrProvidersInit(minor);
    if (GSS_ERROR(major))
        return major;

    *minor = GSSEAP_ATTR_CONTEXT_FAILURE;
    major = GSS_S_FAILURE;

    try {
        *pAttrContext = ctx = new gss_eap_attr_ctx();
        if (ctx->initFromGssContext(gssCred, gssCtx)) {
            *minor = 0;
            major = GSS_S_COMPLETE;
        }
    } catch (std::exception &e) {
        if (ctx != NULL)
            major = ctx->mapException(minor, e);
    }

    if (major == GSS_S_COMPLETE) {
        *pExpiryTime = ctx->getExpiryTime();
    } else {
        delete ctx;
        *pAttrContext = NULL;
    }

    return major;
}
