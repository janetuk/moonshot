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

#ifndef _UTIL_RADIUS_H_
#define _UTIL_RADIUS_H_ 1

#ifdef __cplusplus

struct gss_eap_radius_attr_provider : gss_eap_attr_provider {
public:
    gss_eap_radius_attr_provider(void);
    ~gss_eap_radius_attr_provider(void);

    bool initFromExistingContext(const gss_eap_attr_ctx *source,
                                 const gss_eap_attr_provider *ctx);
    bool initFromGssContext(const gss_eap_attr_ctx *source,
                            const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
    void setAttribute(int complete,
                      const gss_buffer_t attr,
                      const gss_buffer_t value);
    void deleteAttribute(const gss_buffer_t value);
    bool getAttribute(const gss_buffer_t attr,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;
    gss_any_t mapToAny(int authenticated,
                       gss_buffer_t type_id) const;
    void releaseAnyNameMapping(gss_buffer_t type_id,
                               gss_any_t input) const;

    void exportToBuffer(gss_buffer_t buffer) const;
    bool initFromBuffer(const gss_eap_attr_ctx *ctx,
                        const gss_buffer_t buffer);

    bool getAttribute(uint32_t attribute,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;
    bool getAttribute(uint16_t attribute,
                      uint16_t vendor,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;

    bool getFragmentedAttribute(uint16_t attribute,
                                uint16_t vendor,
                                int *authenticated,
                                int *complete,
                                gss_buffer_t value) const;

    bool authenticated(void) const { return m_authenticated; }

    time_t getExpiryTime(void) const;

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

private:
    bool allocRadHandle(const std::string &configFile);
    const VALUE_PAIR *getAvps(void) const {
        return m_vps;
    }

    struct rs_handle *m_rh;
    VALUE_PAIR *m_vps;
    bool m_authenticated;
    std::string m_configFile;
};

/* For now */
extern "C" {
#endif

OM_uint32
gssEapRadiusAddAvp(OM_uint32 *minor,
                   struct rs_handle *rh,
                   VALUE_PAIR **vp,
                   uint16_t type,
                   uint16_t vendor,
                   gss_buffer_t buffer);

OM_uint32
gssEapRadiusGetAvp(OM_uint32 *minor,
                   VALUE_PAIR *vps,
                   uint16_t type,
                   uint16_t vendor,
                   gss_buffer_t buffer,
                   int concat);

OM_uint32
gssEapRadiusGetRawAvp(OM_uint32 *minor,
                      VALUE_PAIR *vps,
                      uint16_t type,
                      uint16_t vendor,
                      VALUE_PAIR **vp);
OM_uint32
gssEapRadiusFreeAvps(OM_uint32 *minor,
                     VALUE_PAIR **vps);

OM_uint32 gssEapRadiusAttrProviderInit(OM_uint32 *minor);
OM_uint32 gssEapRadiusAttrProviderFinalize(OM_uint32 *minor);

OM_uint32
gssEapRadiusAllocConn(OM_uint32 *minor,
                      const gss_cred_id_t cred,
                      gss_ctx_id_t ctx);

OM_uint32
gssEapRadiusMapError(OM_uint32 *minor,
                     struct rs_error *err);

#define RS_CONFIG_FILE      SYSCONFDIR "/radsec.conf"
#define RS_DICT_FILE        DATAROOTDIR "/freeradius/dictionary"

#define VENDORPEC_MS                        311 /* RFC 2548 */

#define PW_MS_MPPE_SEND_KEY                 16
#define PW_MS_MPPE_RECV_KEY                 17

#define VENDORPEC_UKERNA                    25622

#define PW_GSS_ACCEPTOR_SERVICE_NAME        128
#define PW_GSS_ACCEPTOR_HOST_NAME           129
#define PW_GSS_ACCEPTOR_SERVICE_SPECIFIC    130
#define PW_GSS_ACCEPTOR_REALM_NAME          131
#define PW_SAML_AAA_ASSERTION               132

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_RADIUS_H_ */
