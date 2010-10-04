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

#include "gssapiP_eap.h"

static gss_buffer_desc radiusUrnPrefix = {
    sizeof("urn:x-radius:") - 1,
    (void *)"urn:x-radius:"
};

static int
radiusAllocHandle(const char *configFile,
                  rc_handle **pHandle)
{
    rc_handle *rh;
    int ret;

    *pHandle = NULL;

    if (configFile == NULL || configFile[0] == '\0')
        configFile = RC_CONFIG_FILE;

    rh = rc_read_config((char *)configFile);
    if (rh == NULL) {
        rc_config_free(rh);
        return -1;
    }

    ret = rc_read_dictionary(rh, rc_conf_str(rh, (char *)"dictionary"));
    if (ret != 0) {
        rc_config_free(rh);
        return ret;
    }

    *pHandle = rh;
    return 0;
}

VALUE_PAIR *
gss_eap_radius_attr_provider::copyAvps(const VALUE_PAIR *src)
{
    const VALUE_PAIR *vp;
    VALUE_PAIR *dst = NULL, **pDst = &dst;

    for (vp = src; vp != NULL; vp = vp->next) {
        VALUE_PAIR *vp2;

        vp2 = (VALUE_PAIR *)GSSEAP_CALLOC(1, sizeof(*vp2));
        if (vp2 == NULL) {
            rc_avpair_free(dst);
            return NULL;
        }
        memcpy(vp2, vp, sizeof(*vp));
        vp2->next = NULL;
        *pDst = vp2;
        pDst = &vp2->next;
    }

    return dst;
}

gss_eap_radius_attr_provider::gss_eap_radius_attr_provider(void)
{
    m_rh = NULL;
    m_avps = NULL;
    m_authenticated = false;
}

gss_eap_radius_attr_provider::~gss_eap_radius_attr_provider(void)
{
    if (m_rh != NULL)
        rc_config_free(m_rh);
    if (m_avps != NULL)
        rc_avpair_free(m_avps);
}

bool
gss_eap_radius_attr_provider::allocRadHandle(const std::string &configFile)
{
    m_configFile.assign(configFile);

    return (radiusAllocHandle(m_configFile.c_str(), &m_rh) == 0);
}

bool
gss_eap_radius_attr_provider::initFromExistingContext(const gss_eap_attr_ctx *manager,
                                                      const gss_eap_attr_provider *ctx)
{
    const gss_eap_radius_attr_provider *radius;

    if (!gss_eap_attr_provider::initFromExistingContext(manager, ctx))
        return false;

    radius = static_cast<const gss_eap_radius_attr_provider *>(ctx);

    if (!allocRadHandle(radius->m_configFile))
        return false;

    if (radius->m_avps != NULL)
        m_avps = copyAvps(radius->getAvps());

    return true;
}

bool
gss_eap_radius_attr_provider::initFromGssContext(const gss_eap_attr_ctx *manager,
                                                 const gss_cred_id_t gssCred,
                                                 const gss_ctx_id_t gssCtx)
{
    std::string configFile(RC_CONFIG_FILE);

    if (!gss_eap_attr_provider::initFromGssContext(manager, gssCred, gssCtx))
        return false;

    if (gssCred != GSS_C_NO_CREDENTIAL && gssCred->radiusConfigFile != NULL)
        configFile.assign(gssCred->radiusConfigFile);

    if (!allocRadHandle(configFile))
        return false;

    if (gssCtx != GSS_C_NO_CONTEXT) {
        if (gssCtx->acceptorCtx.avps != NULL) {
            m_avps = copyAvps(gssCtx->acceptorCtx.avps);
            if (m_avps == NULL)
                return false;
        }
    }

    return true;
}

static bool
alreadyAddedAttributeP(std::vector <std::string> &attrs, VALUE_PAIR *vp)
{
    for (std::vector<std::string>::const_iterator a = attrs.begin();
         a != attrs.end();
         ++a) {
        if (strcmp(vp->name, (*a).c_str()) == 0)
            return true;
    }

    return false;
}

static bool
isHiddenAttributeP(int attrid, int vendor)
{
    bool ret = false;

    switch (vendor) {
    case VENDOR_ID_MICROSOFT:
        switch (attrid) {
        case VENDOR_ATTR_MS_MPPE_SEND_KEY:
        case VENDOR_ATTR_MS_MPPE_RECV_KEY:
            ret = true;
            break;
        default:
            break;
        }
    case VENDOR_ID_UKERNA:
        ret = true;
        break;
    default:
        break;
    }

    return ret;
}

bool
gss_eap_radius_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute, void *data) const
{
    VALUE_PAIR *vp;
    std::vector <std::string> seen;

    for (vp = m_avps; vp != NULL; vp = vp->next) {
        gss_buffer_desc attribute;
        char attrid[64];
        if (isHiddenAttributeP(ATTRID(vp->attribute), VENDOR(vp->attribute)))
            continue;

        if (alreadyAddedAttributeP(seen, vp))
            continue;

        snprintf(attrid, sizeof(attrid), "%s%d",
            (char *)radiusUrnPrefix.value, vp->attribute);

        attribute.value = attrid;
        attribute.length = strlen(attrid);

        if (!addAttribute(this, &attribute, data))
            return false;

        seen.push_back(std::string(vp->name));
    }

    return true;
}

void
gss_eap_radius_attr_provider::setAttribute(int complete,
                                           const gss_buffer_t attr,
                                           const gss_buffer_t value)
{
}

void
gss_eap_radius_attr_provider::deleteAttribute(const gss_buffer_t value)
{
}

bool
gss_eap_radius_attr_provider::getAttribute(const gss_buffer_t attr,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{
    OM_uint32 tmpMinor;
    gss_buffer_desc strAttr = GSS_C_EMPTY_BUFFER;
    DICT_ATTR *d;
    int attrid;
    char *s;

    /* XXX vendor */
    duplicateBuffer(*attr, &strAttr);
    s = (char *)strAttr.value;

    if (attr->length < radiusUrnPrefix.length ||
        memcmp(s, radiusUrnPrefix.value, radiusUrnPrefix.length) != 0)
        return false;

    s += radiusUrnPrefix.length;

    if (isdigit(*s)) {
        attrid = strtoul(s, NULL, 10);
    } else {
        d = rc_dict_findattr(m_rh, (char *)s);
        if (d == NULL) {
            gss_release_buffer(&tmpMinor, &strAttr);
            return false;
        }
        attrid = d->value;
    }

    gss_release_buffer(&tmpMinor, &strAttr);

    return getAttribute(attrid, authenticated, complete,
                        value, display_value, more);
}

static bool
isPrintableAttributeP(VALUE_PAIR *vp)
{
    size_t i;
    int gotChar = 0;

    for (i = 0; i < sizeof(vp->strvalue); i++) {
        if (gotChar && vp->strvalue[i] == '\0')
            return true;

        if (!isprint(vp->strvalue[i]))
            return false;

        if (!gotChar)
            gotChar++;
    }

    return true;
}

bool
gss_eap_radius_attr_provider::getAttribute(int attrid,
                                           int vendor,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{
    OM_uint32 tmpMinor;
    VALUE_PAIR *vp;
    int i = *more, count = 0;
    char name[NAME_LENGTH + 1];
    char displayString[AUTH_STRING_LEN + 1];
    gss_buffer_desc valueBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc displayBuf = GSS_C_EMPTY_BUFFER;

    *more = 0;

    if (isHiddenAttributeP(attrid, vendor))
        return false;

    if (i == -1)
        i = 0;

    for (vp = rc_avpair_get(m_avps, attrid, vendor);
         vp != NULL;
         vp = rc_avpair_get(vp->next, attrid, vendor)) {
        if (count++ == i) {
            if (rc_avpair_get(vp->next, attrid, vendor) != NULL)
                *more = count;
            break;
        }
    }

    if (vp == NULL && *more == 0)
        return false;

    if (vp->type == PW_TYPE_STRING) {
        valueBuf.value = (void *)vp->strvalue;
        valueBuf.length = vp->lvalue;
    } else {
        valueBuf.value = (void *)&vp->lvalue;
        valueBuf.length = 4;
    }

    if (value != GSS_C_NO_BUFFER)
        duplicateBuffer(valueBuf, value);

    if (display_value != GSS_C_NO_BUFFER &&
        isPrintableAttributeP(vp)) {
        if (rc_avpair_tostr(m_rh, vp, name, NAME_LENGTH,
                            displayString, AUTH_STRING_LEN) != 0) {
            gss_release_buffer(&tmpMinor, value);
            return false;
        }

        displayBuf.value = (void *)displayString;
        displayBuf.length = strlen(displayString);

        duplicateBuffer(displayBuf, display_value);
    }

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;

    return true;
}

bool
gss_eap_radius_attr_provider::getFragmentedAttribute(int attribute,
                                                     int vendor,
                                                     int *authenticated,
                                                     int *complete,
                                                     gss_buffer_t value) const
{
    OM_uint32 major, minor;

    major = getBufferFromAvps(&minor, m_avps, attribute, vendor, value, TRUE);

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;

    return !GSS_ERROR(major);
}

bool
gss_eap_radius_attr_provider::getAttribute(int attrid,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{

    return getAttribute(ATTRID(attrid), VENDOR(attrid),
                        authenticated, complete,
                        value, display_value, more);
}

gss_any_t
gss_eap_radius_attr_provider::mapToAny(int authenticated,
                                       gss_buffer_t type_id) const
{
    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    return (gss_any_t)copyAvps(m_avps);
}

void
gss_eap_radius_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                    gss_any_t input) const
{
    rc_avpair_free((VALUE_PAIR *)input);
}

bool
gss_eap_radius_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_RADIUS,
                                       "urn:ietf:params:gss-eap:radius-avp",
                                       gss_eap_radius_attr_provider::createAttrContext);
    return true;
}

void
gss_eap_radius_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_RADIUS);
}

gss_eap_attr_provider *
gss_eap_radius_attr_provider::createAttrContext(void)
{
    return new gss_eap_radius_attr_provider;
}

OM_uint32
addAvpFromBuffer(OM_uint32 *minor,
                 rc_handle *rh,
                 VALUE_PAIR **vp,
                 int type,
                 int vendor,
                 gss_buffer_t buffer)
{
    if (rc_avpair_add(rh, vp, type,
                      buffer->value, buffer->length, vendor) == NULL) {
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
getBufferFromAvps(OM_uint32 *minor,
                  VALUE_PAIR *vps,
                  int type,
                  int vendor,
                  gss_buffer_t buffer,
                  int concat)
{
    VALUE_PAIR *vp;
    unsigned char *p;

    buffer->length = 0;
    buffer->value = NULL;

    vp = rc_avpair_get(vps, type, vendor);
    if (vp == NULL)
        return GSS_S_UNAVAILABLE;

    do {
        buffer->length += vp->lvalue;
    } while (concat && (vp = rc_avpair_get(vp->next, type, vendor)) != NULL);

    buffer->value = GSSEAP_MALLOC(buffer->length);
    if (buffer->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    p = (unsigned char *)buffer->value;

    for (vp = rc_avpair_get(vps, type, vendor);
         concat && vp != NULL;
         vp = rc_avpair_get(vp->next, type, vendor)) {
        memcpy(p, vp->strvalue, vp->lvalue);
        p += vp->lvalue;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusAttrProviderInit(OM_uint32 *minor)
{
    return gss_eap_radius_attr_provider::init()
        ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32
gssEapRadiusAttrProviderFinalize(OM_uint32 *minor)
{
    gss_eap_radius_attr_provider::finalize();
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusAllocHandle(OM_uint32 *minor,
                        const gss_cred_id_t cred,
                        gss_ctx_id_t ctx)
{
    const char *configFile = NULL;

    assert(ctx->acceptorCtx.radHandle == NULL);

    if (cred != GSS_C_NO_CREDENTIAL && cred->radiusConfigFile != NULL)
        configFile = cred->radiusConfigFile;

    if (radiusAllocHandle(configFile, &ctx->acceptorCtx.radHandle) != 0)
        return GSS_S_FAILURE;

    /* XXX TODO allocate connection handle */

    /* XXX TODO select based on acceptorCtx.radServer */

    return GSS_S_COMPLETE;
}

/*
 * Encoding is:
 * 4 octet NBO attribute ID | 4 octet attribute length | attribute data
 */
static size_t
avpSize(const VALUE_PAIR *vp)
{
    size_t size = 4 + 1;

    if (vp != NULL)
        size += (vp->type == PW_TYPE_STRING) ? vp->lvalue : 4;

    return size;
}

static bool
avpExport(rc_handle *rh,
          const VALUE_PAIR *vp,
          unsigned char **pBuffer,
          size_t *pRemain)
{
    unsigned char *p = *pBuffer;
    size_t remain = *pRemain;

    assert(remain >= avpSize(vp));

    store_uint32_be(vp->attribute, p);

    if (vp->type == PW_TYPE_STRING) {
        assert(vp->lvalue <= AUTH_STRING_LEN);
        p[4] = (uint8_t)vp->lvalue;
        memcpy(p + 5, vp->strvalue, vp->lvalue);
    } else {
        p[4] = 4;
        store_uint32_be(vp->lvalue, p + 5);
    }

    *pBuffer += 5 + p[4];
    *pRemain -= 5 + p[4];

    return true;

}

static bool
avpImport(rc_handle *rh,
          VALUE_PAIR **pVp,
          unsigned char **pBuffer,
          size_t *pRemain)
{
    unsigned char *p = *pBuffer;
    size_t remain = *pRemain;
    VALUE_PAIR *vp;
    DICT_ATTR *d;

    if (remain < avpSize(NULL))
        return false;

    vp = (VALUE_PAIR *)GSSEAP_CALLOC(1, sizeof(*vp));
    if (vp == NULL) {
        throw new std::bad_alloc;
        return false;
    }

    vp->attribute = load_uint32_be(p);
    p += 4;
    remain -= 4;

    d = rc_dict_getattr(rh, vp->attribute);
    if (d == NULL)
        goto fail;

    assert(sizeof(vp->name) == sizeof(d->name));
    strcpy(vp->name, d->name);
    vp->type = d->type;

    if (remain < p[0])
        goto fail;

    if (vp->type == PW_TYPE_STRING) {
        if (p[0] > AUTH_STRING_LEN)
            goto fail;

        vp->lvalue = (uint32_t)p[0];
        memcpy(vp->strvalue, p + 1, vp->lvalue);
        vp->strvalue[vp->lvalue] = '\0';
        p += 1 + vp->lvalue;
        remain -= 1 + vp->lvalue;
    } else {
        if (p[0] != 4)
            goto fail;

        vp->lvalue = load_uint32_be(p + 1);
        p += 5;
        remain -= 5;
    }

    *pVp = vp;
    *pBuffer = p;
    *pRemain = remain;

    return true;

fail:
    GSSEAP_FREE(vp);
    return false;
}

bool
gss_eap_radius_attr_provider::initFromBuffer(const gss_eap_attr_ctx *ctx,
                                             const gss_buffer_t buffer)
{
    unsigned char *p = (unsigned char *)buffer->value;
    size_t remain = buffer->length;
    OM_uint32 configFileLen, count;
    VALUE_PAIR **pNext = &m_avps;

    if (!gss_eap_attr_provider::initFromBuffer(ctx, buffer))
        return false;

    if (remain < 4)
        return false;

    configFileLen = load_uint32_be(p);
    p += 4;
    remain -= 4;

    if (remain < configFileLen)
        return false;

    std::string configFile((char *)p, configFileLen);
    p += configFileLen;
    remain -= configFileLen;

    if (!allocRadHandle(configFile))
        return false;

    if (remain < 4)
        return false;

    count = load_uint32_be(p);
    p += 4;
    remain -= 4;

    do {
        VALUE_PAIR *attr;

        if (!avpImport(m_rh, &attr, &p, &remain))
            return false;

        *pNext = attr;
        pNext = &attr->next;

        count--;
    } while (remain != 0);

    if (count != 0)
        return false;

    return true;
}

void
gss_eap_radius_attr_provider::exportToBuffer(gss_buffer_t buffer) const
{
    OM_uint32 count = 0;
    VALUE_PAIR *vp;
    unsigned char *p;
    size_t remain = 4 + m_configFile.length() + 4;

    for (vp = m_avps; vp != NULL; vp = vp->next) {
        remain += avpSize(vp);
        count++;
    }

    buffer->value = GSSEAP_MALLOC(remain);
    if (buffer->value == NULL) {
        throw new std::bad_alloc;
        return;
    }
    buffer->length = remain;

    p = (unsigned char *)buffer->value;

    store_uint32_be(m_configFile.length(), p);
    p += 4;
    remain -= 4;

    memcpy(p, m_configFile.c_str(), m_configFile.length());
    p += m_configFile.length();
    remain -= m_configFile.length();

    store_uint32_be(count, p);
    p += 4;
    remain -= 4;

    for (vp = m_avps; vp != NULL; vp = vp->next) {
        avpExport(m_rh, vp, &p, &remain);
    }

    assert(remain == 0);
}

time_t
gss_eap_radius_attr_provider::getExpiryTime(void) const
{
    VALUE_PAIR *vp;

    vp = rc_avpair_get(m_avps, PW_SESSION_TIMEOUT, 0);
    if (vp == NULL || vp->lvalue == 0)
        return 0;

    return time(NULL) + vp->lvalue;
}
