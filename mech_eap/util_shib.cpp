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
 * Copyright 2001-2009 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Local attribute provider implementation.
 */

#include <xmltooling/XMLObject.h>

#include <saml/saml2/core/Assertions.h>

#include <shibsp/exceptions.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibresolver/resolver.h>

#include <sstream>

#include "gssapiP_eap.h"

using namespace shibsp;
using namespace shibresolver;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

gss_eap_shib_attr_provider::gss_eap_shib_attr_provider(void)
{
    m_initialized = false;
    m_authenticated = false;
}

gss_eap_shib_attr_provider::~gss_eap_shib_attr_provider(void)
{
    for_each(m_attributes.begin(),
             m_attributes.end(),
             xmltooling::cleanup<Attribute>())
        ;
}

bool
gss_eap_shib_attr_provider::initFromExistingContext(const gss_eap_attr_ctx *manager,
                                                    const gss_eap_attr_provider *ctx)
{
    const gss_eap_shib_attr_provider *shib;

    if (!gss_eap_attr_provider::initFromExistingContext(manager, ctx)) {
        return false;
    }

    m_authenticated = false;

    shib = static_cast<const gss_eap_shib_attr_provider *>(ctx);
    if (shib != NULL) {
        m_attributes = duplicateAttributes(shib->getAttributes());
        m_authenticated = shib->authenticated();
    }

    m_initialized = true;

    return true;
}

bool
gss_eap_shib_attr_provider::initFromGssContext(const gss_eap_attr_ctx *manager,
                                               const gss_cred_id_t gssCred,
                                               const gss_ctx_id_t gssCtx)
{
    const gss_eap_saml_assertion_provider *saml;
    gss_buffer_desc exportedCtx = GSS_C_EMPTY_BUFFER;
    OM_uint32 major, minor;

#if 0
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;
#endif
    if (!gss_eap_attr_provider::initFromGssContext(manager, gssCred, gssCtx))
        return false;

    saml = static_cast<const gss_eap_saml_assertion_provider *>
        (m_manager->getProvider(ATTR_TYPE_SAML_ASSERTION));

    auto_ptr<ShibbolethResolver> resolver(ShibbolethResolver::create());

    /*
     * For now, leave ApplicationID defaulted.
     * Later on, we could allow this via config option to the mechanism
     * or rely on an SPRequest interface to pass in a URI identifying the
     * acceptor.
     */
#if 0
    if (gssCred != GSS_C_NO_CREDENTIAL &&
        gssEapDisplayName(&minor, gssCred->name, &nameBuf, NULL) == GSS_S_COMPLETE) {
        resolver->setApplicationID((const char *)nameBuf.value);
        gss_release_buffer(&minor, &nameBuf);
    }
#endif

    major = gssEapExportSecContext(&minor, gssCtx, &exportedCtx);
    if (major == GSS_S_COMPLETE) {
        resolver->addToken(&exportedCtx);
        gss_release_buffer(&minor, &exportedCtx);
    }

    if (saml != NULL && saml->getAssertion() != NULL) {
        resolver->addToken(saml->getAssertion());
        m_authenticated = saml->authenticated();
    }

    try {
        resolver->resolve();
        m_attributes = resolver->getResolvedAttributes();
        resolver->getResolvedAttributes().clear();
    } catch (exception &e) {
#if 0
        fprintf(stderr, "%s", e.what());
#endif
    }

    m_initialized = true;

    return true;
}

ssize_t
gss_eap_shib_attr_provider::getAttributeIndex(const gss_buffer_t attr) const
{
    int i = 0;

    assert(m_initialized);

    for (vector<Attribute *>::const_iterator a = m_attributes.begin();
         a != m_attributes.end();
         ++a)
    {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attr->length == (*s).length() &&
                memcmp((*s).c_str(), attr->value, attr->length) == 0) {
                return i;
            }
        }
    }

    return -1;
}

bool
gss_eap_shib_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                         const gss_buffer_t attr,
                                         const gss_buffer_t value)
{
    string attrStr((char *)attr->value, attr->length);
    vector <string> ids(1, attrStr);
    SimpleAttribute *a = new SimpleAttribute(ids);

    assert(m_initialized);

    if (value->length != 0) {
        string valueStr((char *)value->value, value->length);

        a->getValues().push_back(valueStr);
    }

    m_attributes.push_back(a);
    m_authenticated = false;

    return true;
}

bool
gss_eap_shib_attr_provider::deleteAttribute(const gss_buffer_t attr)
{
    int i;

    assert(m_initialized);

    i = getAttributeIndex(attr);
    if (i >= 0)
        m_attributes.erase(m_attributes.begin() + i);

    m_authenticated = false;

    return true;
}

bool
gss_eap_shib_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    assert(m_initialized);

    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
        a != m_attributes.end();
        ++a)
    {
        gss_buffer_desc attribute;

        attribute.value = (void *)((*a)->getId());
        attribute.length = strlen((char *)attribute.value);

        if (!addAttribute(m_manager, this, &attribute, data))
            return false;
    }

    return true;
}

const Attribute *
gss_eap_shib_attr_provider::getAttribute(const gss_buffer_t attr) const
{
    const Attribute *ret = NULL;

    assert(m_initialized);

    for (vector<Attribute *>::const_iterator a = m_attributes.begin();
         a != m_attributes.end();
         ++a)
    {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attr->length == (*s).length() &&
                memcmp((*s).c_str(), attr->value, attr->length) == 0) {
                ret = *a;
                break;
            }
        }
        if (ret != NULL)
            break;
    }

    return ret;
}

bool
gss_eap_shib_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    const Attribute *shibAttr = NULL;
    gss_buffer_desc buf;
    int nvalues, i = *more;

    assert(m_initialized);

    *more = 0;

    shibAttr = getAttribute(attr);
    if (shibAttr == NULL)
        return false;

    nvalues = shibAttr->valueCount();

    if (i == -1)
        i = 0;
    else if (i >= nvalues)
        return false;

    buf.value = (void *)shibAttr->getSerializedValues()[*more].c_str();
    buf.length = strlen((char *)buf.value);

    if (buf.length != 0) {
        if (value != NULL)
            duplicateBuffer(buf, value);

        if (display_value != NULL)
            duplicateBuffer(buf, display_value);
    }

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = false;

    if (nvalues > ++i)
        *more = i;

    return true;
}

gss_any_t
gss_eap_shib_attr_provider::mapToAny(int authenticated,
                                     gss_buffer_t type_id GSSEAP_UNUSED) const
{
    gss_any_t output;

    assert(m_initialized);

    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    vector <Attribute *>v = duplicateAttributes(m_attributes);

    output = (gss_any_t)new vector <Attribute *>(v);

    return output;
}

void
gss_eap_shib_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                  gss_any_t input) const
{
    assert(m_initialized);

    vector <Attribute *> *v = ((vector <Attribute *> *)input);
    delete v;
}

const char *
gss_eap_shib_attr_provider::prefix(void) const
{
    return NULL;
}

const char *
gss_eap_shib_attr_provider::name(void) const
{
    return "local";
}

JSONObject
gss_eap_shib_attr_provider::jsonRepresentation(void) const
{
    JSONObject obj;

    if (m_initialized == false)
        return obj; /* don't export incomplete context */

    JSONObject attrs = JSONObject::array();

    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
         a != m_attributes.end(); ++a) {
        DDF attr = (*a)->marshall();
        JSONObject jobj(attr);
        attrs.append(jobj);
    }

    obj.set("attributes", attrs);

    obj.set("authenticated", m_authenticated);

    return obj;
}

bool
gss_eap_shib_attr_provider::initWithJsonObject(const gss_eap_attr_ctx *ctx,
                                               JSONObject &obj)
{
    if (!gss_eap_attr_provider::initWithJsonObject(ctx, obj))
        return false;

    assert(m_authenticated == false);
    assert(m_attributes.size() == 0);

    JSONObject attrs = obj["attributes"];
    size_t nelems = attrs.size();

    for (size_t i = 0; i < nelems; i++) {
        DDF attr = attrs.get(i).ddf();
        Attribute *attribute = Attribute::unmarshall(attr);
        m_attributes.push_back(attribute);
    }

    m_authenticated = obj["authenticated"].integer();
    m_initialized = true;

    return true;
}

bool
gss_eap_shib_attr_provider::init(void)
{
    if (!ShibbolethResolver::init())
        return false;

    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_LOCAL, createAttrContext);

    return true;
}

void
gss_eap_shib_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_LOCAL);
    ShibbolethResolver::term();
}

OM_uint32
gss_eap_shib_attr_provider::mapException(OM_uint32 *minor,
                                         std::exception &e) const
{
    if (typeid(e) == typeid(AttributeException))
        *minor = GSSEAP_SHIB_ATTR_FAILURE;
    else if (typeid(e) == typeid(AttributeExtractionException))
        *minor = GSSEAP_SHIB_ATTR_EXTRACT_FAILURE;
    else if (typeid(e) == typeid(AttributeFilteringException))
        *minor = GSSEAP_SHIB_ATTR_FILTER_FAILURE;
    else if (typeid(e) == typeid(AttributeResolutionException))
        *minor = GSSEAP_SHIB_ATTR_RESOLVE_FAILURE;
    else if (typeid(e) == typeid(ConfigurationException))
        *minor = GSSEAP_SHIB_CONFIG_FAILURE;
    else if (typeid(e) == typeid(ListenerException))
        *minor = GSSEAP_SHIB_LISTENER_FAILURE;
    else
        return GSS_S_CONTINUE_NEEDED;

    return GSS_S_FAILURE;
}

gss_eap_attr_provider *
gss_eap_shib_attr_provider::createAttrContext(void)
{
    return new gss_eap_shib_attr_provider;
}

Attribute *
gss_eap_shib_attr_provider::duplicateAttribute(const Attribute *src)
{
    DDF obj = src->marshall();
    Attribute *attribute = Attribute::unmarshall(obj);
    obj.destroy();

    return attribute;
}

vector <Attribute *>
gss_eap_shib_attr_provider::duplicateAttributes(const vector <Attribute *>src)
{
    vector <Attribute *> dst;

    for (vector<Attribute *>::const_iterator a = src.begin();
         a != src.end();
         ++a)
        dst.push_back(duplicateAttribute(*a));

    return dst;
}

OM_uint32
gssEapLocalAttrProviderInit(OM_uint32 *minor)
{
    if (!gss_eap_shib_attr_provider::init()) {
        *minor = GSSEAP_SHIB_INIT_FAILURE;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapLocalAttrProviderFinalize(OM_uint32 *minor)
{
    gss_eap_shib_attr_provider::finalize();

    *minor = 0;
    return GSS_S_COMPLETE;
}
