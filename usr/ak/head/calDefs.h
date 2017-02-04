/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:            calDefs.h
 ***************************************************************************************
 * Description:		Declares macros and types for CAL.
 * Version:         1.0.
 */
#ifndef __CAL_DEFS_H__
#define __CAL_DEFS_H__

/* The version of this CAL API */
#define CAL_API_VERSION				1

/* CAL Error codes */
#define CAL_SUCCESS					0  /* no error */
#define CAL_ERR_GENERAL				1  /* general error */
#define CAL_ERR_UNSUPPORTED			2  /* not supported functionality */
#define CAL_ERR_UNAVAILABLE			3  /* the platform feature is unavailable */
#define CAL_ERR_INVALIDPARAM		4  /* invalid parameter */
#define CAL_ERR_SMALLBUFFER			5  /* buffer size is small to store the data */
#define CAL_ERR_NOTINITIALIZED		6  /* CAL_Initialize is not called before the call */
#define CAL_ERR_ALLOC_FAILED		7  /* memory allocation failed */
#define CAL_ERR_INCORRECT_PASSWORD	8  /* incorrect password for Wrapping key has been used in CAL_GetWrappingKey */
#define CAL_ERR_ATTESTATION_SEED    9  /* unable to obtain attestation seed (currently used in TEE CAL) */
#define CAL_ERR_APPID_MISMATCH		10 /* failed to verify wrapped object source application ID (returned from CAL_UnwrapObject) */
#define CAL_ERR_LOCKED				11 /* the functionality is locked (e.g. TPM is locked) */
#define CAL_ERR_NOT_READY_TO_USE	12 /* platform feature is available but may be disabled */
#define CAL_ERR_CANCELED			13 /* cryptographic operation is canceled (e.g. by User) */


#define CAL_ERR_USE_PASSWORD_PANEL			14 /* using customer's password panel to verify  (e.g. by User) */


/* These macros define maximum sizes in bytes 
 * and can be used to allocate buffers on stack. 
 * Actual sizes can be less.
 */
#define CAL_MAX_HASH_SIZE       32  /* Max size for cryptographic hash (256-bit) */
#define CAL_MAX_MAC_SIZE		32  /* Max size for Message Authentication Code (256-bit) */
#define CAL_MAX_BLOCK_SIZE      16  /* Max size for cypher block (128-bit) */
#define CAL_MAX_APPID_LEN		256 /* Max application ID length in bytes */

/* The version of cal_bind_info_t structure */
#define CAL_BIND_INFO_VERSION	1

/* Define NULL if not defined */
#ifndef NULL
	#ifdef __cplusplus
		#define NULL	0
	#else
		#define NULL ((void *)0)
	#endif
#endif

#ifdef __cplusplus
	#define CAL_EXTERN	extern "C"
#else
	#define CAL_EXTERN	extern
#endif

/* Data types for CAL API */
typedef	char				cal_char_t;
typedef unsigned char		cal_byte_t;
typedef unsigned short int	cal_word_t;
typedef unsigned int		cal_dword_t;
typedef cal_dword_t			cal_result_t;
typedef void*				cal_handle_t;

/* Defines CAL type returned from CAL_GetInfo and used by cryptoGetCAL. */
typedef enum { CAL_DEF = 0, CAL_SFT, CAL_TEE, CAL_TPM, CAL_WB, CAL_KC, CAL_KS } cal_type_t;

/**
 * Defines a BLOB data.
 */
typedef struct cal_blob_t
{
    cal_byte_t* pData;
    cal_dword_t length;
} cal_blob_t;

/**
 * Defines a BLOB of const data (or const BLOB).
 */
typedef struct cal_cblob_t
{
    const cal_byte_t* pData;
    const cal_dword_t length;
} cal_cblob_t;

/* A key type (attestation, signature, wrapping and MAC keys) */
typedef enum { CAL_KEY_ATT = 0, CAL_KEY_SIG, CAL_KEY_WRAP, CAL_KEY_MAC } cal_keytype_t;

/* A cryptographic algorithm identifiers */
typedef enum 
{
	CAL_ALG_NONE = 0, 
	CAL_ALG_ECDSA, 
	CAL_ALG_RSA, 
	CAL_ALG_AES, 
	CAL_ALG_SHA1, 
	CAL_ALG_SHA2_256, 
	CAL_ALG_SHA2_512, 
	CAL_ALG_CMAC,
	CAL_ALG_SM2,	/* Chinese signature algorithm based on elliptic curves */
	CAL_ALG_SM3,	/* Chinese hashing algorithm with 256-bit hash */
	CAL_ALG_SM4		/* Chinese block cipher algorithm */
} cal_algid_t;

/* A cryptographic parameter (curve, padding scheme, mode) for signature and wrapping algorithms */
typedef enum 
{
	CAL_PARAM_NONE = 0,		/* no additional parameter */
	CAL_PARAM_SECP_R1,		/* SECP R1 or NIST curve */
	CAL_PARAM_SECP_K1,		/* SECP K1 or Koblitz curve */
	CAL_PARAM_RSASSA_PKCS1,	/* RSA with PKCS#1 padding scheme */
	CAL_PARAM_RSASSA_PSS,	/* RSA with PSS padding scheme */
	CAL_PARAM_CBC_PKCSPAD	/* CBC block cipher mode with PKCS#7 padding */
} cal_param_t;

/**
 * Represents a public key. 
 * If algid is CAL_ALG_ECDSA or CAL_ALG_SM2 - public key is (x, y) pair.
 * If algid is CAL_ALG_RSA - public key is (n, e) pair.
 */
typedef union cal_pubkey_t
{
	cal_algid_t algid;
	struct
	{
		cal_algid_t algid;
		cal_blob_t  x;
		cal_blob_t  y;
	} ec;
	struct
	{
		cal_algid_t algid;
		cal_blob_t  n;
		cal_blob_t  e;
	} rsa;
} cal_pubkey_t;

/**
 * Public key BLOB structure.
 * pPubKey		is the pointer to cal_pubkey_t structure.
 * nPubKeyLen	the size in bytes of the buffer pointed to by pPubKey.
 *				Note that nPubKeyLen = sizeof(cal_pubkey_t) + <public key size>.
 *				Required nPubKeyLen can be obtained by calling CAL_ExportPubKey and 
 *				passing NULL for pPubKey.
 */
typedef struct cal_pubkey_blob_t
{
	cal_pubkey_t* pPubKey;
	cal_dword_t	  nPubKeyLen;
} cal_pubkey_blob_t;

/**
 Cryptographic algorithm information structure.
 */
typedef struct cal_alg_info_t
{
	cal_algid_t AlgId;       /* Cryptographic algorithm identifier */
	cal_dword_t nbitKeySize; /* Key size or curve in bits for AlgId */
	cal_param_t AlgParam;    /* Cryptographic algorithm parameter */
} cal_alg_info_t;

/**
 A structure specifies several parameters for a key.
 */
typedef struct cal_key_params_t
{
	cal_alg_info_t	AlgInfo; /* Key algorithm */
	cal_blob_t		KeyID;   /* Key ID if a key is in secure storage */
	cal_blob_t		Params;	 /* Additional parameters */
} cal_key_params_t;

/**
 * Represents CAL information (CAL version, type and cryptographic algorithms).
 */
typedef struct cal_info_t
{
    cal_dword_t    version;  /* The version of CAL implementation */
	cal_type_t     CALtype;	 /* Specifies particular CAL type (cannot be CAL_DEF). */
	cal_alg_info_t AttInfo;  /* Attestation algorithm information. */
	cal_alg_info_t SigInfo;  /* Signing algorithm information. */
	cal_alg_info_t WrapInfo; /* Wrapping algorithm information */
	cal_alg_info_t MACInfo;  /* MAC algorithm information */
	cal_alg_info_t HashInfo; /* Hash algorithm information */
} cal_info_t;

/**
 Specifies binding type
 */
typedef enum
{
	CAL_BIND_FREE,        /* Do not bind */
	CAL_BIND_SELF,		  /* Bind to self (application) */
	CAL_BIND_APPLICATION, /* Bind to the other application */
	CAL_BIND_PLATFORM     /* Bind to the platform */
} cal_bind_t;

/**
 * Defines binding parameters for CAL_GetKey function.
 */
typedef struct cal_bind_info_t
{
	cal_dword_t version;		/* Should be set to CAL_BIND_INFO_VERSION */
	cal_bind_t  BindTarget;		/* Specifies Binding Target */
	cal_blob_t	AppID;			/* Application ID to/from which object should be wrapped/unwrapped */
	cal_char_t* pszPassword;	/* Password that will be used to derive a key */
	cal_blob_t  Salt;			/* Salt used with pszPassword to derive a key */
	cal_blob_t	DrvBLOB;		/* Additional data to derive a key */
} cal_bind_info_t;

#endif /* __CAL_DEFS_H__ */
