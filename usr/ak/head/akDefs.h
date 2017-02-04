/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file: akDefs.h
 */
#ifndef __AK_DEFS_H__
#define  __AK_DEFS_H__


#include "calDefs.h"

/* Error codes */
#define AK_AUTH_SUCCESS				0  /* no error */
#define AK_AUTH_ERR_GENERAL			1  /* general error */
#define AK_AUTH_ERR_UNSUPPORTED		2  /* not supported functionality */
#define AK_AUTH_ERR_INVALIDPARAM	3  /* invalid parameter */
#define AK_AUTH_ERR_EXPORTKEY		4  /* unable to export a container with generated key */
#define AK_AUTH_ERR_IMPORTKEY		5  /* unable to import key container */
#define AK_AUTH_ERR_SMALLBUFFER		6  /* buffer size is small to store the data */
#define AK_AUTH_ERR_NOTINITIALIZED	7  /* AK_Initialize is not called before the call */
#define AK_AUTH_ERR_ALLOC_FAILED    8  /* memory allocation failed */
#define AK_AUTH_ERR_KEYGEN_FAILED   9  /* Auth key generation failed */
#define AK_AUTH_ERR_CANT_GET_ATTKEY 10 /* couldn't retrieve attestation key */
#define AK_AUTH_ERR_CANT_GET_KCPK   11 /* couldn't retrieve kcpk */
#define AK_AUTH_ERR_JWS_HEADER      12 /* couldn't create JWS header */
#define AK_AUTH_ERR_JWS_PAYLOAD     13 /* couldn't create JWS payload */
#define AK_AUTH_ERR_JWS_SIGNATURE   14 /* couldn't create JWS signature */
#define AK_AUTH_ERR_USERAUTHRESULT	15 /* userAuthResult verification failed */
#define AK_AUTH_ERR_INCORRECT_PWD	16
#define AK_AUTH_ERR_UNAVAILABLE		17  /* the platform feature is unavailable */
#define AK_AUTH_ERR_PRNG			18  /* failed to generate random data or seed PRNG */
#define AK_AUTH_ERR_LOCKED			19  /* Authenticator is Locked. */
#define AK_AUTH_ERR_NOT_READY_TO_USE 20  /* Platform feature is available but not ready user currently. May be disabled. */
#define AK_AUTH_CANCELED            21  /*user canceled*/
#define AK_AUTH_ERR_END             AK_AUTH_CANCELED + 1

#define AK_INFO_VERSION				2 /* AK version */

#define AK_MAX_AAID_SIZE            100
#define AK_MAX_ORIGIN_SIZE          1024
#define AK_MAX_USERID_SIZE          128
#define AK_MAX_NONCE_SIZE           128
#define AK_MAX_ATTCERT_SIZE         2048
#define AK_MAX_PASSWORD_SIZE        128
#define AK_MAX_USERAUTHRESULT_SIZE  1024
#define AK_MAX_DEVICEID_SIZE        128
#define AK_MAX_TRANSACTION_SIZE     2048
#define AK_MAX_JWS_ALG_SIZE         8

#define AK_MIN_AAID_SIZE            3
#define AK_MIN_ORIGIN_SIZE          4
#define AK_MIN_USERID_SIZE          1
#define AK_MIN_NONCE_SIZE           8
#define AK_MIN_ATTCERT_SIZE         16

/* Definitions for User Authentication Result */
#define AK_UAR_VERSION						1
#define AK_UAR_TAG_MATCHER_RESULT			0x7204
#define AK_UAR_TAG_TRUSTLET_OBJECT			0x7205
#define AK_UAR_MAX_MATCHER_RESULT_SIZE		508
#define AK_UAR_MAX_AAID_SIZE				25
#define AK_UAR_MAX_CHALLENGE_SIZE			32
#define AK_UAR_ENROLLID_SIZE				32
#define AK_UAR_MAX_ENROLLID_SIZE			256
#define AK_UAR_MAX_BIO_DATA_SIZE			2
#define AK_UAR_MAX_TRUSTLET_OBJECT_SIZE		(AK_UAR_MAX_CHALLENGE_SIZE + AK_UAR_ENROLLID_SIZE + AK_UAR_MAX_BIO_DATA_SIZE + 6)
#define Base64StringPtr		char*

typedef unsigned char		ak_byte_t;
typedef unsigned short int	ak_word_t;
typedef unsigned int		ak_dword_t;
typedef ak_dword_t			ak_result_t;


/* Defines AK interface packaging type (returned from AK_Initialize). */
typedef enum { AK_JWS, AK_TLV } ak_package_t;

typedef struct ak_info_t
{
	ak_dword_t		version;
	ak_package_t	PackageType;
	cal_type_t		CALtype;
} ak_info_t;

/* Matcher Result structure */
typedef struct ak_MatcherResult_t
{
	char	  AAID[AK_UAR_MAX_AAID_SIZE];
	ak_word_t ChallengeSize;
	ak_byte_t Challenge[AK_UAR_MAX_CHALLENGE_SIZE];
	ak_word_t EnrollIDSize;
    ak_byte_t EnrollID[AK_UAR_ENROLLID_SIZE];
    ak_word_t BioDataSize;
    ak_byte_t BioData[AK_UAR_MAX_BIO_DATA_SIZE];
} ak_MatcherResult_t;

#endif
