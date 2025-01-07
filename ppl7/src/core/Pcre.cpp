/*******************************************************************************
 * This file is part of "Patrick's Programming Library", Version 7 (PPL7).
 * Web: https://github.com/pfedick/pplib
 *******************************************************************************
 * Copyright (c) 2024, Patrick Fedick <patrick@pfp.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER AND CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "prolog_ppl7.h"

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif
#include "ppl7.h"
#include "ppl7-types.h"

#ifdef HAVE_PCRE2_BITS_16
#define HAVE_PCRE2_WIDE
#define pcre2_code_wide pcre2_code_16
#define pcre2_code_copy_wide pcre2_code_copy_16
#define pcre2_code_free_wide pcre2_code_free_16
#define pcre2_compile_wide pcre2_compile_16
#define pcre2_match_data_create_from_pattern_wide pcre2_match_data_create_from_pattern_16
#define pcre2_match_wide pcre2_match_16
#define pcre2_match_data_free_wide pcre2_match_data_free_16
#define pcre2_get_ovector_pointer_wide pcre2_get_ovector_pointer_16
#define pcre2_match_data_wide pcre2_match_data_16
#define PCRE2_SPTR_WIDE PCRE2_SPTR16
#define pcre2_bits_wide 16


#elif defined HAVE_PCRE2_BITS_32
#define HAVE_PCRE2_WIDE
#define pcre2_code_wide pcre2_code_32
#define pcre2_code_copy_wide pcre2_code_copy_32
#define pcre2_code_free_wide pcre2_code_free_32
#define pcre2_compile_wide pcre2_compile_32
#define pcre2_match_data_create_from_pattern_wide pcre2_match_data_create_from_pattern_32
#define pcre2_match_wide pcre2_match_32
#define pcre2_match_data_free_wide pcre2_match_data_free_32
#define pcre2_get_ovector_pointer_wide pcre2_get_ovector_pointer_32
#define pcre2_match_data_wide pcre2_match_data_32
#define PCRE2_SPTR_WIDE PCRE2_SPTR32
#define pcre2_bits_wide 32

#endif


namespace ppl7 {


RegEx::Pattern::Pattern()
{
    p=NULL;
    bits=0;
}

RegEx::Pattern::Pattern(const Pattern &other)
{
    p=NULL;
    bits=other.bits;
    ppl7::PrintDebug("RegEx::Pattern::Pattern using copy constructor\n");
    if (other.p) {
        if (bits==8) {
            #ifdef HAVE_PCRE2_BITS_8
            p=pcre2_code_copy_8((pcre2_code_8*)other.p);
            #endif
        } else if (bits ==16 || bits==32) {
            #ifdef HAVE_PCRE2_WIDE
            p=pcre2_code_copy_wide((pcre2_code_wide*)other.p);
            #endif
        }
        if (!p) throw OutOfMemoryException("copy of RegEx::Pattern failed");
    }
}

RegEx::Pattern::Pattern(const Pattern &&other)
{
    ppl7::PrintDebug("RegEx::Pattern::Pattern using move constructor\n");
    p=other.p;
    bits=other.bits;
}

RegEx::Pattern::~Pattern()
{
    if (p) {
        #ifdef HAVE_PCRE2_BITS_8
        if (bits==8) pcre2_code_free_8((pcre2_code_8*)p);
        #endif
        #ifdef HAVE_PCRE2_WIDE
        if (bits==16 || bits==32)pcre2_code_free_wide((pcre2_code_wide*)p);
        #endif
    }
    p=NULL;
    bits=0;
}

RegEx::Pattern RegEx::compile(const String& regex, int flags)
{
#ifndef HAVE_PCRE2
    throw UnsupportedFeatureException("PCRE2");
#endif
#ifndef HAVE_PCRE2_BITS_8
    throw UnsupportedFeatureException("PCRE2 with 8 bits character width");
#else
    PCRE2_SIZE erroffset;
    int errorcode;
    int options=PCRE2_UTF|PCRE2_NO_UTF_CHECK;
    if (flags&Flags::CASELESS) options|=PCRE2_CASELESS;
    if (flags&Flags::ANCHORED) options|=PCRE2_ANCHORED;
    if (flags&Flags::MULTILINE) options|=PCRE2_MULTILINE;
    if (flags&Flags::EXTENDED) options|=PCRE2_EXTENDED;
    if (flags&Flags::DOTALL) options|=PCRE2_DOTALL;
    if (flags&Flags::UNGREEDY) options|=PCRE2_UNGREEDY;
    
    const char *r=regex.c_str();
    pcre2_code_8 *re=NULL;
    if (r[0]=='/') {    // PerlRegEx
        ByteArray expr=regex;
        const char* oo=::strrchr((const char*)expr, '/');
        if (oo) {
            expr.set(oo - (const char*)expr, 0);
            oo++;
            if (::strchr(oo, 'i')) options|=PCRE2_CASELESS;
            if (::strchr(oo, 'm')) options|=PCRE2_MULTILINE;
            if (::strchr(oo, 'x')) options|=PCRE2_EXTENDED;
            if (::strchr(oo, 's')) options|=PCRE2_DOTALL;
            if (::strchr(oo, 'a')) options|=PCRE2_ANCHORED;
            if (::strchr(oo, 'u')) options|=PCRE2_UNGREEDY;
        }
        re=pcre2_compile_8((PCRE2_SPTR8)expr+1,PCRE2_ZERO_TERMINATED, options,
            &errorcode,&erroffset, NULL);

    } else {
        re=pcre2_compile_8((PCRE2_SPTR8)regex.c_str(),PCRE2_ZERO_TERMINATED, options,
            &errorcode,&erroffset, NULL);
    }
    if (!re) throw IllegalRegularExpressionException();

    RegEx::Pattern pattern;
    pattern.bits=8; 
    pattern.p=re;
    return pattern;
#endif
}

RegEx::Pattern RegEx::compile(const WideString& regex, int flags)
{
#ifndef HAVE_PCRE2
    throw UnsupportedFeatureException("PCRE2");
#endif
#ifndef HAVE_PCRE2_WIDE
    throw UnsupportedFeatureException("PCRE2 with wide character width");
#else
    PCRE2_SIZE erroffset;
    int errorcode;
    int options=0;
    if (flags&Flags::CASELESS) options|=PCRE2_CASELESS;
    if (flags&Flags::ANCHORED) options|=PCRE2_ANCHORED;
    if (flags&Flags::MULTILINE) options|=PCRE2_MULTILINE;
    if (flags&Flags::EXTENDED) options|=PCRE2_EXTENDED;
    if (flags&Flags::DOTALL) options|=PCRE2_DOTALL;
    if (flags&Flags::UNGREEDY) options|=PCRE2_UNGREEDY;
    
    const wchar_t *r=regex.getPtr();
    pcre2_code_wide *re=NULL;
    
    if (r[0]==L'/') {    // PerlRegEx
        WideString r=regex;
        ByteArray expr=regex;
        wchar_t* oo=(wchar_t*)::wcsrchr((const wchar_t*)expr.ptr(), '/');
        if (oo) {
            oo[0]=0;
            r.set((wchar_t*)expr.ptr()+1);
            oo++;
            if (::wcschr(oo, L'i')) options|=PCRE2_CASELESS;
            if (::wcschr(oo, L'm')) options|=PCRE2_MULTILINE;
            if (::wcschr(oo, L'x')) options|=PCRE2_EXTENDED;
            if (::wcschr(oo, L's')) options|=PCRE2_DOTALL;
            if (::wcschr(oo, L'a')) options|=PCRE2_ANCHORED;
            if (::wcschr(oo, L'u')) options|=PCRE2_UNGREEDY;
        }
        re=pcre2_compile_wide((PCRE2_SPTR_WIDE)r.getPtr(),PCRE2_ZERO_TERMINATED, options,
            &errorcode,&erroffset, NULL);

    } else {
        re=pcre2_compile_wide((PCRE2_SPTR_WIDE)regex.getPtr(),PCRE2_ZERO_TERMINATED, options,
            &errorcode,&erroffset, NULL);
    }
    if (!re) throw IllegalRegularExpressionException();

    RegEx::Pattern pattern;
    pattern.bits=pcre2_bits_wide; 
    pattern.p=re;
    return pattern;
#endif
}

bool RegEx::match(const String& regex, const String& subject, int flags)
{
    RegEx::Pattern pattern=RegEx::compile(regex,flags);
    return RegEx::match(pattern,subject);
}

bool RegEx::match(const WideString& regex, const WideString& subject, int flags)
{
    RegEx::Pattern pattern=RegEx::compile(regex,flags);
    return RegEx::match(pattern,subject);
}


bool RegEx::match(const Pattern& pattern, const String& subject)
{
    if (pattern.p==NULL) throw IllegalRegularExpressionException();
#ifndef HAVE_PCRE2_BITS_8
    throw UnsupportedFeatureException("PCRE2 with 8 bits character width");
#else
    pcre2_match_data_8 *md=pcre2_match_data_create_from_pattern_8((pcre2_code_8*)pattern.p, NULL);
    int rc = pcre2_match_8((pcre2_code_8*)pattern.p,(PCRE2_SPTR8)subject.c_str(),subject.size(),0,0,md,NULL);
    if (rc<0) {
        pcre2_match_data_free_8(md);
        if (rc==PCRE2_ERROR_NOMATCH) return false;
        throw IllegalRegularExpressionException();
    }
    pcre2_match_data_free_8(md);
    return true;
#endif
}

bool RegEx::match(const Pattern& pattern, const WideString& subject)
{
    if (pattern.p==NULL) {
        ppl7::PrintDebug("debug 1\n");
        throw IllegalRegularExpressionException();
    }
#ifndef HAVE_PCRE2_WIDE
    throw UnsupportedFeatureException("PCRE2 with wide character width");
#else
    pcre2_match_data_wide *md=pcre2_match_data_create_from_pattern_wide((pcre2_code_wide*)pattern.p, NULL);
    int rc = pcre2_match_wide((pcre2_code_wide*)pattern.p,(PCRE2_SPTR_WIDE)subject.getPtr(),subject.size(),0,0,md,NULL);
    if (rc<0) {
        pcre2_match_data_free_wide(md);
        if (rc==PCRE2_ERROR_NOMATCH) return false;
        //ppl7::PrintDebug("debug 2, rc=%d\n", rc);
        throw IllegalRegularExpressionException();
    }
    pcre2_match_data_free_wide(md);
    return true;
#endif
}

bool RegEx::capture(const String& regex, const String& subject, std::vector<String>& matches, int flags)
{
    RegEx::Pattern pattern=RegEx::compile(regex,flags);
    return RegEx::capture(pattern,subject,matches);
}

bool RegEx::capture(const Pattern& pattern, const String& subject, std::vector<String>& matches)
{
    if (pattern.p==NULL) throw IllegalRegularExpressionException();
#ifndef HAVE_PCRE2_BITS_8
    throw UnsupportedFeatureException("PCRE2 with 8 bits character width");
#else
    pcre2_match_data_8 *md=pcre2_match_data_create_from_pattern_8((pcre2_code_8*)pattern.p, NULL);
    PCRE2_SPTR8 subj=(PCRE2_SPTR8)subject.c_str();
    int rc = pcre2_match_8((pcre2_code_8*)pattern.p,subj,subject.size(),0,0,md,NULL);
    if (rc<0) {
        pcre2_match_data_free_8(md);
        if (rc==PCRE2_ERROR_NOMATCH) return false;
        throw IllegalRegularExpressionException();
    }
    matches.clear();
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_8(md);
    for (int i=0; i<rc; i++) {
        PCRE2_SPTR8 substring_start = subj + ovector[2*i];
        PCRE2_SIZE substring_length = ovector[2*i+1] - ovector[2*i];
        matches.push_back(String((const char*)substring_start,substring_length));

    }
    pcre2_match_data_free_8(md);
    return true;
#endif
}

bool RegEx::capture(const WideString& regex, const WideString& subject, std::vector<WideString>& matches, int flags)
{
    RegEx::Pattern pattern=RegEx::compile(regex,flags);
    return RegEx::capture(pattern,subject,matches);
}

bool RegEx::capture(const Pattern& pattern, const WideString& subject, std::vector<WideString>& matches)
{
    if (pattern.p==NULL) throw IllegalRegularExpressionException();
#ifndef HAVE_PCRE2_WIDE
    throw UnsupportedFeatureException("PCRE2 with 8 bits character width");
#else
    pcre2_match_data_wide *md=pcre2_match_data_create_from_pattern_wide((pcre2_code_wide*)pattern.p, NULL);
    PCRE2_SPTR_WIDE subj=(PCRE2_SPTR_WIDE)subject.getPtr();
    int rc = pcre2_match_wide((pcre2_code_wide*)pattern.p,subj,subject.size(),0,0,md,NULL);
    if (rc<0) {
        pcre2_match_data_free_wide(md);
        if (rc==PCRE2_ERROR_NOMATCH) return false;
        throw IllegalRegularExpressionException();
    }
    matches.clear();
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_wide(md);
    for (int i=0; i<rc; i++) {
        PCRE2_SPTR_WIDE substring_start = subj + ovector[2*i];
        PCRE2_SIZE substring_length = ovector[2*i+1] - ovector[2*i];
        matches.push_back(WideString((const wchar_t*)substring_start,substring_length));

    }
    pcre2_match_data_free_wide(md);
    return true;
#endif
}




String RegEx::replace(const String& regex, const String& subject, const String &replacement, int flags, int max)
{
    RegEx::Pattern pattern=RegEx::compile(regex,flags);
    return RegEx::replace(pattern,subject,replacement,max);
}

String RegEx::replace(const Pattern& pattern, const String& subject, const String &replacement, int max)
{
    if (pattern.p==NULL) throw IllegalRegularExpressionException();
#ifndef HAVE_PCRE2_BITS_8
    throw UnsupportedFeatureException("PCRE2 with 8 bits character width");
#else
    pcre2_match_data_8 *md=pcre2_match_data_create_from_pattern_8((pcre2_code_8*)pattern.p, NULL);
    String result=subject;
    PCRE2_SIZE offset=0;
    int count=0;
    while (1) {
        PCRE2_SPTR8 subj=(PCRE2_SPTR8)result.c_str()+offset;
        int rc = pcre2_match_8((pcre2_code_8*)pattern.p,subj,PCRE2_ZERO_TERMINATED,0,0,md,NULL);
        if (rc<0) {
            pcre2_match_data_free_8(md);
            if (rc==PCRE2_ERROR_NOMATCH) return result;
            throw IllegalRegularExpressionException();
        } else if (rc==0) {
            pcre2_match_data_free_8(md);
            return result;

        }
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_8(md);
        result=result.left(ovector[0]+offset)+replacement+result.mid(offset+ovector[1]);
        offset=ovector[1];
        count++;
        if (max>0 && count>=max) break;
    }
    pcre2_match_data_free_8(md);
    return result;
#endif    
}

WideString RegEx::replace(const WideString& regex, const WideString& subject, const WideString &replacement, int flags, int max)
{
    RegEx::Pattern pattern=RegEx::compile(regex,flags);
    return RegEx::replace(pattern,subject,replacement,max);
}

WideString RegEx::replace(const Pattern& pattern, const WideString& subject, const WideString &replacement, int max)
{
    if (pattern.p==NULL) throw IllegalRegularExpressionException();
#ifndef HAVE_PCRE2_WIDE
    throw UnsupportedFeatureException("PCRE2 with 8 bits character width");
#else
    pcre2_match_data_wide *md=pcre2_match_data_create_from_pattern_wide((pcre2_code_wide*)pattern.p, NULL);
    WideString result=subject;
    PCRE2_SIZE offset=0;
    int count=0;
    while (1) {
        PCRE2_SPTR_WIDE subj=(PCRE2_SPTR_WIDE)result.getPtr()+offset;
        int rc = pcre2_match_wide((pcre2_code_wide*)pattern.p,subj,PCRE2_ZERO_TERMINATED,0,0,md,NULL);
        if (rc<0) {
            pcre2_match_data_free_wide(md);
            if (rc==PCRE2_ERROR_NOMATCH) return result;
            throw IllegalRegularExpressionException();
        } else if (rc==0) {
            pcre2_match_data_free_wide(md);
            return result;

        }
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_wide(md);
        result=result.left(ovector[0]+offset)+replacement+result.mid(offset+ovector[1]);
        offset=ovector[1];
        count++;
        if (max>0 && count>=max) break;
    }
    pcre2_match_data_free_wide(md);
    return result;
#endif  
}

/*! \brief Fügt dem String Escape-Zeichen zu, zur Verwendung in einem Regulären Ausdruck
 *
 * \desc
 * Der Befehl scannt den String nach Zeichen mit besonderer Bedeutung in einer Perl-Regular-Expression und
 * escaped diese mit einem Backslash. Das Ergebnis kann dann in einer Regular Expression verwendet werden.
 *
 * Folgende Zeichen werden escaped: - + \ * /
 */
String RegEx::escape(const String &subject)
{
    if (subject.size() == 0) return subject;

	String t;
	String compare="-+\\*/";
	String letter;
    const char*ptr=subject.c_str();
	for (size_t i=0;i < subject.size();i++) {
		letter.set(ptr[i]);
		if (compare.instr(letter, 0) >= 0) t+="\\";
		t+=letter;
	}
    return t;
}

/*! \brief Fügt dem String Escape-Zeichen zu, zur Verwendung in einem Regulären Ausdruck
 *
 * \desc
 * Der Befehl scannt den String nach Zeichen mit besonderer Bedeutung in einer Perl-Regular-Expression und
 * escaped diese mit einem Backslash. Das Ergebnis kann dann in einer Regular Expression verwendet werden.
 *
 * Folgende Zeichen werden escaped: - + \ * /
 */
WideString RegEx::escape(const WideString &subject)
{
    if (subject.size() == 0) return subject;

	WideString t;
	WideString compare=L"-+\\*/";
	WideString letter;
    const wchar_t*ptr=subject.getPtr();
	for (size_t i=0;i < subject.size();i++) {
		letter.set(ptr[i]);
		if (compare.instr(letter, 0) >= 0) t+=L"\\";
		t+=letter;
	}
    return t;
}



} // EOF namespace ppl7

