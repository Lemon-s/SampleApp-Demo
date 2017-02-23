/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:			uaf_ak_tlv.h
 ***************************************************************************************
 * Version:			0.1
 */
#ifndef __UAFAK_DEFS_H__
#define __UAFAK_DEFS_H__

#include "calDefs.h"

#define SystemVersion [[UIDevice currentDevice] systemVersion].floatValue

#define MAX_PUBLIC_KEY_SIZE		512
#define MAX_ATT_CERT_SIZE		512
#define MAX_KEYHANLDE_EXT_SIZE	64

#define MAX_GETINFO_CMD_RESPONSE_SIZE       512
#define MAX_REGISTER_CMD_RESPONSE_SIZE      512
#define MAX_SIGN_CMD_RESPONSE_SIZE          512
#define MAX_DEREGISTER_CMD_RESPONSE_SIZE    128
#define MAX_MANAGEPIN_CMD_RESPONSE_SIZE		128

/** The UVT is wrapped with the local container key. */
#define UVT_FORMAT_LOCAL        1

/** The UVT is wrapped by another Trusted Application (TA). */
#define UVT_FORMAT_OTHER_TA     2

/** The size of the AAID */
#define AAID_SIZE				9

/** Max number of bytes for AFI_RAW_USER_VERIFICATION_INDEX */
#define UAF_RAW_UVI_SIZE        32  

/** The size of the assertion scheme */
#define ASSERTION_SCHEME_SIZE	8

#define USERNAME_SIZE			1
#define MAX_APPID_SIZE			512
#define MAX_CHALLENGE_SIZE		32
#define MAX_USERNAME_SIZE		255
#define MAX_KHACCESSTOKEN_SIZE	32
#define MAX_TRANSACTION_SIZE	32768
#define MAX_USERTOKEN_SIZE		256
#define MAX_KEYHANDLE_NUM		16
#define MAX_WRAPPED_KEY_LENGTH	256
#define MAX_KEYHANDLE_SIZE		512
#define MAX_ENROLLID_LENGTH		CAL_MAX_HASH_SIZE
#define MAX_TCTOKEN_SIZE		(MAX_CHALLENGE_SIZE + CAL_MAX_HASH_SIZE + TLV_TAG_AND_LENGTH_SIZE*2 + 1)
#define MAX_UVT_SIZE			256
#define MAX_EXPECTED_TAGS_NUM	10
#define MAX_PIN_NUMBER			5
#define MAX_PIN_FAIL_NUM		10
#define MAX_PIN_LENGTH			64
#define MAX_PIN_CONFIG_SIZE		(MAX_PIN_NUMBER * (MAX_PIN_LENGTH + MAX_ENROLLID_LENGTH + 3*sizeof(ak_word_t)))
#define MAX_NNL_AK_CONFIG_SIZE	(MAX_PIN_CONFIG_SIZE + 3*sizeof(ak_dword_t) + 3*sizeof(ak_word_t) + 128)
#define MAX_AUTHENTICATORS_NUM  32
#define MAX_CERTIFICATES_NUM	16

// Command Tags
#define TAG_UAFV1_GETINFO_CMD				0x3401
#define TAG_UAFV1_GETINFO_CMD_RESP			0x3601
#define TAG_UAFV1_REGISTER_CMD				0x3402
#define TAG_UAFV1_REGISTER_CMD_RESP			0x3602
#define TAG_UAFV1_SIGN_CMD					0x3403
#define TAG_UAFV1_SIGN_CMD_RESP				0x3603
#define TAG_UAFV1_DEREGISTER_CMD			0x3404
#define TAG_UAFV1_DEREGISTER_CMD_RESP		0x3604
#define TAG_UAFV1_OPEN_SETTINGS_CMD			0x3406
#define TAG_UAFV1_OPEN_SETTINGS_CMD_RESP	0x3606
#define TAG_UAFV1_MANAGE_PIN_CMD			0x3407
#define TAG_UAFV1_MANAGE_PIN_CMD_RESP		0x3607
#define TAG_UAFV1_ADD_AUTHNR_CMD			0x3408
#define TAG_UAFV1_ADD_AUTHNR_CMD_RESP		0x3608

// Authenticator Command TAGs
#define TAG_KEYHANDLE						0x2801
#define TAG_USERNAME_AND_KEYHANDLE			0x3802
#define TAG_USERVERIFY_TOKEN				0x2803
#define TAG_APPID							0x2804
#define TAG_KEYHANDLE_ACCESS_TOKEN			0x2805
#define TAG_USERNAME						0x2806
#define TAG_ATTESTATION_TYPE				0x2807
#define TAG_STATUS_CODE						0x2808
#define TAG_AUTHENTICATOR_METADATA			0x2809
#define TAG_ASSERTION_SCHEME				0x280A
#define TAG_AUTHENTICATOR_INDEX				0x280D
#define TAG_API_VERSION						0x280E
#define TAG_AUTHENTICATOR_ASSERTION			0x280F
#define TAG_TRANSACTION_CONTENT				0x2810
#define TAG_AUTHENTICATOR_INFO				0x3811
#define TAG_SUPPORTED_EXTENSION_ID			0x2812

// UAFV1 protocol TAGS
#define TAG_UAFV1_REG_ASSERTION				0x3E01
#define TAG_UAFV1_AUTH_ASSERTION			0x3E02
#define TAG_UAFV1_KRD						0x3E03
#define TAG_UAFV1_SIGNEDDATA				0x3E04
#define TAG_ATTESTATION_CERT				0x2E05
#define TAG_SIGNATURE						0x2E06
#define TAG_ATTESTATION_BASIC_FULL			0x3E07
#define TAG_ATTESTATION_BASIC_SURROGATE		0x3E08
#define TAG_KEYID							0x2E09
#define TAG_FINAL_CHALLENGE					0x2E0A
#define TAG_AAID							0x2E0B
#define TAG_PUB_KEY							0x2E0C
#define TAG_COUNTERS						0x2E0D
#define TAG_ASSERTION_INFO					0x2E0E
#define TAG_AUTHENTICATOR_NONCE				0x2E0F
#define TAG_TRANSACTION_CONTENT_HASH		0x2E10
#define TAG_EXTENSION_CRITICAL				0x3E11
#define TAG_EXTENSION_OPTIONAL				0x3E12
#define TAG_EXTENSION_ID					0x2E13
#define TAG_EXTENSION_DATA					0x2E14

// UVT TAGs
#define TAG_UVT_AUTHNR_NAME					0x6205
#define TAG_UVT_RESULT						0x6206
#define TAG_UVT_USER_ID						0x6207
#define TAG_UVT_FINAL_CHALLENGE				0x620A
#define TAG_UVT_TIMESTAMP					0x620B
#define TAG_UVT_MATCHING_SCORE				0x620C


#define AFI_UVI_RAW_USER_VERIFICATION_INDEX 0x0103
#define AFI_UVI_USER_VERIFICATION_INDEX     0x0104

// NNL Customized TAG
#define TAG_NNL_AK_ADDITIONAL_INFO			0x28F1
#define TAG_NNL_AK_CONFIG					0x28F2
#define TAG_NNL_AK_MANAGEPIN				0x28F3
#define TAG_TRANSACTION_CONFIRMATION_TOKEN	0x38F4
#define TAG_TC_TOKEN_TYPE					0x28F5
#define TAG_TC_TOKEN_CONTENT				0x28F6

// NNL MANAGE PIN Command
#define TAG_NNL_PIN_CREATE					0x0001
#define TAG_NNL_PIN_VERIFY					0x0002
#define TAG_NNL_PIN_CHANGE					0x0003
#define TAG_NNL_PIN_RESET					0x0004

// UAF Status Code
#define UAF_CMD_STATUS_OK					0x00
#define UAF_CMD_STATUS_ERR_UNKNOWN			0x01
#define UAF_CMD_STATUS_ACCESS_DENIED		0x02
#define UAF_CMD_STATUS_USER_NOT_ENROLLED	0x03   // 用户没有在认证器注册
#define UAF_CMD_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT 0x04   //不能获取交易内容
#define UAF_CMD_STATUS_USER_CANCELLED		0x05
#define UAF_CMD_STATUS_CMD_NOT_SUPPORTED	0x06
#define UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED 0x07

// AK Status Code
#define UAF_STATUS_ERR_INVALID_KEYHANDLE    0x0007
#define UAF_STATUS_ERR_INVALID_PARAM        0x0008
#define UAF_STATUS_ERR_NOTINITIALIZED		0x0009
#define UAF_STATUS_ERR_UNSUPPORTED_ALG		0x000A
#define UAF_STATUS_ERR_BUFFER_SMALL			0x000B
#define UAF_STATUS_ERR_CONFIG				0x000C

// PIN Authenticator ERROR code
#define UAF_PIN_STATUS_ERR_PIN_SLOTRESET        0x000D
#define UAF_PIN_STATUS_ERR_PIN_NOTSET	        0x000E
#define UAF_PIN_STATUS_ERR_PIN_SLOTOCCUPIED		0x000F
#define UAF_PIN_STATUS_ERR_PIN_INVALIDPARAM		0x0010
#define UAF_PIN_STATUS_ERR_AUTH_ALREADY_EXISTS	0x0011

// UAF Auth Factor
#define USER_VERIFY_PRESENCE				0x0001
#define USER_VERIFY_FINGERPRINT				0x0002
#define USER_VERIFY_PASSCODE				0x0004
#define USER_VERIFY_VOICEPRINT				0x0008
#define USER_VERIFY_FACEPRINT				0x0010
#define USER_VERIFY_LOCATION				0x0020
#define USER_VERIFY_EYEPRINT				0x0040
#define USER_VERIFY_PATTERN					0x0080
#define USER_VERIFY_HANDPRINT				0x0100
#define USER_VERIFY_NONE					0x0200
#define USER_VERIFY_ALL						0x0400

// UAF Key Protection
#define KEY_PROTECTION_SOFTWARE				0x0001
#define KEY_PROTECTION_HARDWARE				0x0002
#define KEY_PROTECTION_TEE					0x0004
#define KEY_PROTECTION_SECURE_ELEMENT		0x0008
#define KEY_PROTECTION_REMOTE_HANDLE		0x0010

// UAF Matcher Protection
#define MATCHER_PROTECTION_SOFTWARE			0x0001
#define MATCHER_PROTECTION_TEE				0x0002
#define MATCHER_PROTECTION_ON_CHIP			0x0004

// UAF Secure Display
#define TC_DISPLAY_NOTSUPPORTED				0x0000
#define TC_DISPLAY_ANY						0x0001
#define TC_DISPLAY_PRIVILEGED_SOFTWARE		0x0002
#define TC_DISPLAY_TEE						0x0004
#define TC_DISPLAY_HARDWARE					0x0008
#define TC_DISPLAY_REMOTE					0x0010

// UAF Crypto Suite
#define UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW		0x0001
#define UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER		0x0002
#define UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW			0x0003
#define UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER			0x0004
#define UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW		0x0005
#define UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER		0x0006
#define UAF_ALG_SIGN_SECP256R1_SM2_SM3_RAW			0x0007
#define UAF_ALG_SIGN_RSASSA_PKCS1_SHA256_RAW		0x0008
#define UAF_ALG_SIGN_RSASSA_PKCS1_SHA256_DER		0x0009

// UAF Public Key Format
#define UAF_ALG_KEY_ECC_X962_RAW			0x100;
#define UAF_ALG_KEY_ECC_X962_DER			0x101;
#define UAF_ALG_KEY_RSA_2048_PSS_RAW		0x102;
#define UAF_ALG_KEY_RSA_2048_PSS_DER		0x103;

// UAF Auth mode
#define UAF_USER_VERIFIED					0x01
#define UAF_SECURE_DISPLAY					0x02

// Authenticator type
#define UAF_TYPE_BASIC_AUTHNR				0x0000
#define UAF_TYPE_2NDF_AUTHNR				0x0001
#define UAF_TYPE_ROAMNG_AUTHNR				0x0002
#define UAF_TYPE_INTERNAL_STORAGE			0x0004
#define UAF_TYPE_BUILTIN_ENROLL_UI			0x0008
#define UAF_TYPE_BUILTIN_SETTING_UI			0x0010
#define UAF_TYPE_EXPECT_APPID				0x0020
#define UAF_TYPE_USERENROLLED				0x0040

// Transaction confirmation type
#define TYPE_TCT_PLAINTEXT					0
#define TYPE_TCT_WRAPPED					1

typedef unsigned char		ak_byte_t;
typedef unsigned short int	ak_word_t;
typedef unsigned int		ak_dword_t;
typedef ak_dword_t			ak_result_t;

/**
 * This defines the authenticators meta data. Refer to the UAF specification for details.
 */
typedef struct metadata_t {
    /**
     * Indicates whether the authenticator is bound or roaming, and whether it is first- or second-factor only.
     */
    ak_word_t authenticatorType;
    
    /**
     * Indicates maximum number of key handles this authenticator can receive and process in a single command.
     */
    ak_byte_t maxKeyHandle;
    
    /**
     * Represents a single USER_VERIFY constant
     */
    ak_dword_t userVerification;
    
    /**
     * Represents the bit fields defined by the KEY_PROTECTION constants
     */
    ak_word_t keyProtection;
    
    /**
     * Represents the bit fields defined by the MATCHER_PROTECTION constants
     */
    ak_word_t matcherProtection;
    
    /**
     * Representing the bit fields defined by the TRANSACTION_CONFIRMATIOM_DISPLAY constants
     */
    ak_word_t tcDisplay;
    
    /**
     * The authentication algorithm supported by the authenticator.
     */
    ak_word_t authenticationAlg;
} metadata_t;

/**
 * Contains information about the authenticator
 */
typedef struct authenticatorInfo_t
{
    /**
     * This contains the AAID for the authenticator
     */
    ak_byte_t aaid[AAID_SIZE];
    
    /**
     * Represents the meta data for the authenticator.
     */
    metadata_t metadata;
    
    /**
     * Represents the assertion scheme for the authenticator.
     */
    ak_byte_t scheme[ASSERTION_SCHEME_SIZE];
    
    /**
     * Represents the attestation type of the authenticator
     */
    ak_word_t attestationType;
    
    /**
     * Represents the ID of the trustlet container that produces the UVT
     */
    cal_blob_t containerID;
    
    /**
     * Represents the UVT wrapping format. The allowed values are UVT_FORMAT_LOCAL or UVT_TA_OTHER.
     */
    ak_byte_t UVTFormat;
    
    /**
     * The contains the certificate for the authenticator.
     */
    cal_blob_t*  certificate;
} authenticatorInfo_t;

/**
 * This is called to retrieve information about the authenticator.
 * @param [in] authenticatorIndex The index of the authenticator.
 * @param [out] ppInfo The authenticator information. This should be a static object as the caller retains the pointer.
 */
typedef ak_result_t (*fnGetInfoPtr)(const ak_byte_t authenticatorIndex, authenticatorInfo_t **ppInfo);

/**
 * Contains a pointer to the GetInfo function.
 */
typedef struct authenticator_t
{
    fnGetInfoPtr GetInfo;
} authenticator_t;

#endif /* __UAFAK_DEFS_H__ */

