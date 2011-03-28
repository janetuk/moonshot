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
 * JSONObject utilities.
 */

#include "gssapiP_eap.h"

#include <typeinfo>
#include <string>
#include <sstream>
#include <exception>
#include <stdexcept>
#include <new>

#define JSON_INIT(obj) do {                                     \
        if ((obj) == NULL)                                      \
            throw new std::bad_alloc;                           \
        m_obj = (obj);                                          \
    } while (0)

#define JSON_CHECK_CONTAINER() do {                             \
        if (!json_is_object(m_obj) && !json_is_array(m_obj)) {  \
            std::string s("JSONObject object is not a container");   \
            throw new std::runtime_error(s);                    \
        }                                                       \
    } while (0)
#define JSON_CHECK_OBJECT() do {                                \
        if (!json_is_object(m_obj)) {                           \
            std::string s("JSONObject object is not a dictionary");   \
            throw new std::runtime_error(s);                    \
        }                                                       \
    } while (0)

#define JSON_CHECK_ARRAY() do {                                 \
        if (!json_is_array(m_obj)) {                            \
            std::string s("JSONObject object is not an array");       \
            throw new std::runtime_error(s);                    \
        }                                                       \
    } while (0)

#define JSON_CHECK(s) do {              \
        if ((s) != 0)                   \
            throw new std::bad_alloc;   \
    } while (0)

JSONObject
JSONObject::load(const char *input, size_t flags, json_error_t *error)
{
    json_t *obj;

    obj = json_loads(input, flags, error);

    return JSONObject(obj, false);
}

JSONObject
JSONObject::load(FILE *fp, size_t flags, json_error_t *error)
{
    json_t *obj;

    obj = json_loadf(fp, flags, error);

    return JSONObject(obj, false);
}

char *
JSONObject::dump(size_t flags) const
{
    char *s = json_dumps(m_obj, flags);

    if (s == NULL)
        throw new std::bad_alloc;

    return s;
}

void
JSONObject::dump(FILE *fp, size_t flags) const
{
    int r = json_dumpf(m_obj, fp, flags);

    if (r != 0)
        throw new std::bad_alloc;
}

size_t
JSONObject::size(void) const
{
    if (json_is_object(m_obj))
        return json_object_size(m_obj);
    else if (json_is_array(m_obj))
        return json_array_size(m_obj);
    else
        return 0;
}

JSONObject::JSONObject(json_t *obj, bool retain)
{
    if (retain)
        json_incref(obj);
    JSON_INIT(obj);
}

JSONObject::JSONObject(const char *value)
{
    json_t *obj = json_string(value);

    JSON_INIT(obj);
}

JSONObject::JSONObject(json_int_t value)
{
    json_t *obj = json_integer(value);

    JSON_INIT(obj);
}

JSONObject::JSONObject(double value)
{
    json_t *obj = json_real(value);

    JSON_INIT(obj);
}

JSONObject::JSONObject(bool value)
{
    json_t *obj = value ? json_true() : json_false();

    JSON_INIT(obj);
}

JSONObject::JSONObject(void)
{
    json_t *obj = json_object();

    JSON_INIT(obj);
}

JSONObject
JSONObject::object(void)
{
    return JSONObject();
}

JSONObject
JSONObject::null(void)
{
    return JSONObject(json_null(), false);
}

JSONObject
JSONObject::array(void)
{
    return JSONObject(json_array(), false);
}

void
JSONObject::set(const char *key, JSONObject &value)
{
    JSON_CHECK_OBJECT();
    JSON_CHECK(json_object_set_new(m_obj, key, value.get()));
}

void
JSONObject::set(const char *key, const char *value)
{
    JSONObject jobj(value);
    set(key, jobj);
}

void
JSONObject::set(const char *key, json_int_t value)
{
    JSONObject jobj(value);
    set(key, jobj);
}

void
JSONObject::del(const char *key)
{
    json_object_del(m_obj, key);
}

JSONObject
JSONObject::get(const char *key) const
{
    json_t *obj;

    obj = json_object_get(m_obj, key);
    if (obj == NULL)
        return JSONObject::null();

    return JSONObject(obj, true);
}

JSONObject
JSONObject::get(size_t index) const
{
    json_t *obj;

    obj = json_array_get(m_obj, index);
    if (obj == NULL)
        return JSONObject::null();

    return JSONObject(obj, true);
}

void
JSONObject::update(JSONObject &value)
{
    JSON_CHECK_OBJECT();
    json_t *other = value.get();
    JSON_CHECK(json_object_update(m_obj, other));
    json_decref(other);
}

JSONObject
JSONObject::operator[](size_t index) const
{
    return get(index);
}

JSONObject
JSONObject::operator[](const char *key) const
{
    return get(key);
}

void
JSONObject::append(JSONObject &value)
{
    JSON_CHECK_ARRAY();
    JSON_CHECK(json_array_append_new(m_obj, value.get()));
}

void
JSONObject::insert(size_t index, JSONObject &value)
{
    JSON_CHECK_ARRAY();
    JSON_CHECK(json_array_insert_new(m_obj, index, value.get()));
}

void
JSONObject::remove(size_t index)
{
    JSON_CHECK_ARRAY();
    JSON_CHECK(json_array_remove(m_obj, index));
}

void
JSONObject::clear(void)
{
    JSON_CHECK_CONTAINER();

    if (json_is_object(m_obj)) {
        JSON_CHECK(json_object_clear(m_obj));
    } else if (json_is_array(m_obj)) {
        JSON_CHECK(json_array_clear(m_obj));
    }
}

void
JSONObject::extend(JSONObject &value)
{
    JSON_CHECK_ARRAY();
    json_t *other = value.get();
    JSON_CHECK(json_array_extend(m_obj, other));
    json_decref(other);
}

const char *
JSONObject::string(void) const
{
    return json_string_value(m_obj);
}

json_int_t
JSONObject::integer(void) const
{
    return json_integer_value(m_obj);
}

double
JSONObject::real(void) const
{
    return json_real_value(m_obj);
}

double
JSONObject::number(void) const
{
    return json_number_value(m_obj);
}

bool
JSONObject::isnull(void) const
{
    return json_is_null(m_obj);
}

JSONObject::JSONObject(DDF &ddf)
{
    if (ddf.isstruct()) {
        DDF elem = ddf.first();
        JSONObject jobj = JSONObject::array();

        while (!elem.isnull()) {
            JSONObject jtmp(elem);
            jobj.append(jtmp);
            elem = ddf.next();
        }
    } else if (ddf.islist()) {
        DDF elem = ddf.first();
        JSONObject jobj = JSONObject::object();

        while (!elem.isnull()) {
            JSONObject jtmp(elem);
            jobj.set(elem.name(), jtmp);
            elem = ddf.next();
        }
    } else if (ddf.isstring()) {
        JSONObject(ddf.string());
    } else if (ddf.isint()) {
        JSONObject((json_int_t)ddf.integer());
    } else if (ddf.isfloat()) {
        JSONObject(ddf.floating());
    } else if (ddf.isempty() || ddf.ispointer()) {
        JSONObject::object();
    } else if (ddf.isnull()) {
        JSONObject::null();
    }

    std::string s("Unbridgeable DDF object");
    throw new std::runtime_error(s);
}

DDF
JSONObject::ddf(void) const
{
    DDF ddf(NULL);

    switch (type()) {
    case JSON_OBJECT: {
        JSONIterator iter = iterator();

        do {
            const char *key = iter.key();
            DDF value = iter.value().ddf();
            ddf.add(value.name(key));
        } while (iter.next());
        break;
    }
    case JSON_ARRAY: {
        size_t i, nelems = size();

        for (i = 0; i < nelems; i++) {
            DDF value = get(i).ddf();
            ddf.add(value);
        }
        break;
    }
    case JSON_STRING:
        ddf.string(string());
        break;
    case JSON_INTEGER:
        ddf.integer(integer());
        break;
    case JSON_REAL:
        ddf.floating(real());
        break;
    case JSON_TRUE:
        ddf.integer(1L);
        break;
    case JSON_FALSE:
        ddf.integer(0L);
        break;
    case JSON_NULL:
        break;
    }

    return DDF(NULL);
}

JSONIterator::JSONIterator(const JSONObject &obj)
{
    m_obj = obj.get();
    m_iter = json_object_iter(m_obj);
}

JSONIterator::~JSONIterator(void)
{
    json_decref(m_obj);
}

const char *
JSONIterator::key(void) const
{
    return json_object_iter_key(m_iter);
}

JSONObject
JSONIterator::value(void) const
{
    return JSONObject(json_object_iter_value(m_iter));
}

bool
JSONIterator::next(void)
{
    m_iter = json_object_iter_next(m_obj, m_iter);
    return m_iter != NULL;
}
