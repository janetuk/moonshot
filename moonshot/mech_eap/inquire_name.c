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
 * Enumerate name attributes.
 */

#include "gssapiP_eap.h"

OM_uint32 KRB5_CALLCONV
gss_inquire_name(OM_uint32 *minor,
                 gss_name_t name,
                 int *name_is_MN,
                 gss_OID *MN_mech,
                 gss_buffer_set_t *attrs)
{
    OM_uint32 major, tmpMinor;

    *minor = 0;

    if (name_is_MN != NULL)
        *name_is_MN = 0;
    if (MN_mech != NULL)
        *MN_mech = GSS_C_NO_OID;
    if (attrs != NULL)
        *attrs = GSS_C_NO_BUFFER_SET;

    if (name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;
    }

    if (attrs == NULL)
        return GSS_S_COMPLETE;

    GSSEAP_MUTEX_LOCK(&name->mutex);

    major = gssEapInquireName(minor, name, name_is_MN, MN_mech, attrs);

    GSSEAP_MUTEX_UNLOCK(&name->mutex);

    if (GSS_ERROR(major))
        gss_release_buffer_set(&tmpMinor, attrs);

    return major;
}
