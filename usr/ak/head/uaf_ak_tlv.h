/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:			uaf_ak_tlv.h
 ***************************************************************************************
 * Version:			0.1
 */
#ifndef __UAFAK_TLV_H__
#define __UAFAK_TLV_H__

#include "uaf_ak_defs.h"

#define ENROLLMENT_CONFIG_VERSION	1

// TODO: These should be moved to test application
#define TAG_SIZE sizeof(ak_word_t)
#define TAG_LENGTH_SIZE sizeof(ak_word_t)
#define TLV_TAG_AND_LENGTH_SIZE (TAG_SIZE + TAG_LENGTH_SIZE)


// TODO: Using short and consistent naming
#define TLV_T_SIZE	sizeof(ak_word_t)
#define TLV_L_SIZE	sizeof(ak_word_t)
#define TLV_TL_SIZE	(TLV_T_SIZE + TLV_L_SIZE)

/////////////////////////// Response_TL_SIZE + Status_TL_SIZE + Status_V_SIZE
#define RESPONSE_HEADER_SIZE	(TLV_TL_SIZE + TLV_TL_SIZE + sizeof(ak_word_t))

#define ASM_KHACCESSTOKEN_SIZE		  32


/* TODO: 
   1. #pragma pack (1 byte packing) should be removed to avoid unaligned access.
	  The code that uses the structures should be checked and corrected, since it may
	  rely on assumption that the structures are 1 byte packed.
   2. Consider to rearrange the order of members for structures to hold less space in memory.
*/

typedef struct ak_tlv_t
{
	ak_word_t tag;
	ak_word_t length;
	ak_byte_t* value;
} ak_tlv_t;

typedef struct ak_tlvs_t
{
    ak_word_t numTags;
    ak_tlv_t tlvs[MAX_EXPECTED_TAGS_NUM];
} ak_tlvs_t;


typedef ak_byte_t* tlv_t;

/**
 * Structure holding tag and length
 */
typedef struct ak_tagLength_t {
	ak_word_t tag;
	ak_word_t length;
} ak_tagLength_t;

/**
 * Structure holding maximum number of tags.
 */

typedef struct tlvs_t
{
    ak_word_t numTags;
    tlv_t tlvs[MAX_EXPECTED_TAGS_NUM];
} tlvs_t;

/**
 * This structure stores a PIN slot.
 */
typedef struct ak_pin_slot_t
{
	ak_word_t index;
	ak_word_t pinSize;
	ak_byte_t pin[MAX_PIN_LENGTH];
	ak_byte_t enrollID[MAX_ENROLLID_LENGTH];
    ak_word_t failCounter;
} ak_pin_slot_t;

/**
 * This structure stores a collection of PIN slots.
 */
typedef struct ak_pins_t
{
	ak_word_t pinNum;
	ak_pin_slot_t pins[MAX_PIN_NUMBER];
} ak_pins_t;

/**
 * This structure stores the AK config information, which is 
 * obtained from the TAG_NNL_AK_CONFIG.
 */
typedef struct ak_config_t
{
	ak_dword_t version;
    ak_dword_t signCounter;
	ak_dword_t regCounter;
	ak_pins_t  PINConfig;
} ak_config_t;

/**
 * This structure stores the pointers to the decrypted usernames for
 * the matching keyhandles.
 */
typedef struct ak_decryptedUN_t {
	ak_byte_t KHindex;
	ak_byte_t *pUsername;
}ak_decryptedUN_t;

/**
 * This is a generic structure holding input arguments used in various requests. 
 * It can also hold number of request specific TAGs.
 */
typedef struct input_args_t
{
	ak_word_t	operationType;
	ak_byte_t	authenticatorID;
    cal_blob_t	finalChallenge;
    cal_blob_t	khAccessToken;
	cal_blob_t	username;
	ak_word_t	attestationType;
    cal_blob_t	transactionContent;
	cal_blob_t	userVerifyToken;
	cal_blob_t	tcToken;
	cal_blob_t	keyHandles[MAX_KEYHANDLE_NUM];
	ak_byte_t	keyHandlesNum;
	ak_config_t *pConfig;
    ak_tlvs_t   extensionTags;
	cal_blob_t	attestationCerts[MAX_CERTIFICATES_NUM];
	ak_byte_t	attestationCertsNum;
	ak_byte_t*	authenticatorAAID;

	/* TODO: change to pointer type save space and avoid copying */
    
	ak_word_t			authNum;

} input_args_t;

/**
 * This is an structure holding input arguments for CreateUAFV1RegResponse function.
 */
typedef struct regResponseArgs_t
{
    ak_byte_t		*pAAID;
    ak_word_t		authenticatorVersion;
	ak_byte_t		authenticationMode;
    ak_word_t		publicKeyAlgAndEncoding;
    ak_word_t		signatureAlgAndEncoding;
	ak_word_t		attestationType;
    cal_blob_t		*pFinalChallenge;
    cal_blob_t		keyID;
    ak_dword_t		regCounter;
    ak_dword_t		signCounter;
    cal_blob_t		uauthPub;
    cal_cblob_t		*pAttestationCertificate; /* const BLOB (should not be modified) */
    cal_blob_t		keyHandle;
    cal_handle_t	hAttestationKey;
} regResponseArgs_t;

/**
 * This is an structure holding input arguments for CreateUAFV1SignResponse function.
 */
typedef struct signResponseArgs_t
{
    ak_byte_t	 *pAAID;
    ak_word_t    authenticatorVersion;
    ak_byte_t    authenticationMode;
    ak_word_t	 signatureAlgAndEncoding;
    cal_blob_t   authenticatorNonce;
    cal_blob_t   *pFinalChallenge;
    cal_blob_t   *pTransactionText;
	cal_blob_t	 keyID;
	ak_byte_t	 keyHandleNum;
	cal_blob_t	 usernames[MAX_KEYHANDLE_NUM];
	cal_blob_t	 *pKeyHandles[MAX_KEYHANDLE_NUM];
    ak_dword_t   signCounter;
    ak_dword_t   tagNum;
    tlv_t        *pTags;
    ak_dword_t   criticalTagNum;
    tlv_t        *pCriticalTags;
    cal_handle_t hUAuthKey;
} signResponseArgs_t;
//#pragma pack(pop) TODO: remove the pragma lines with review comment.




/**
 * Copies the specified byte array into the destination buffer.
 *
 * @param pDest			the destination buffer.
 * @param pDestLength	the available length of desination buffer;
 *						on output the value is decremented by count of bytes successfully written. 
 * @param pValue		the byte array to be copied.
 * @param pValue		the length of the byte array to be copied. 
 *
 * @return				the pointer to a new position of the destination buffer,
 *						available for subsequent writing;
 *						on any error NULL is returned.			
 */
ak_byte_t* AK_WriteBytes(ak_byte_t* pDest, ak_word_t* pDestLength, const ak_byte_t* pValue, ak_word_t length);

ak_byte_t* AK_WriteByte(ak_byte_t* pDest, ak_word_t* pDestLength, ak_byte_t value);
ak_byte_t* AK_WriteWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t value);
ak_byte_t* AK_WriteDWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_dword_t value);

/**
 * Writes the specified TLV object into the destination buffer.
 *
 * @param pDest			the destination buffer.
 * @param pDestLength	the available length of desination buffer;
 *						on output the value is decremented by count of bytes successfully written. 
 * @param tag			the tag of TLV object.
 * @param pValue		the value of TLV object.
 * @param pValue		the length of TLV object. 
 *
 * @return				the pointer to a new position of the destination buffer,
 *						available for subsequent writing;
 *						on any error NULL is returned.			
 */
ak_byte_t* AK_WriteTlvBytes(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, const ak_byte_t* pValue, ak_word_t length);

ak_byte_t* AK_WriteTlvByte(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, ak_byte_t value);
ak_byte_t* AK_WriteTlvWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, ak_word_t value);
ak_byte_t* AK_WriteTlvDWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, ak_dword_t value);

/**
 * Copies byte array of specified length from the source buffer into the value buffer.
 *
 * @param pValue		the value buffer.
 * @param length		the requested count of bytes to be copied.
 * @param pSrc			the source buffer.
 * @param pSrcLength	the available length of source buffer;
 *						on output the value is decremented by count of bytes successfully read. 
 *
 * @return				the pointer to a new position of the source buffer,
 *						available for subsequent reading;
 *						on any error NULL is returned.			
 */
const ak_byte_t* AK_GetBytes(ak_byte_t* pValue, ak_word_t length, const ak_byte_t* pSrc, ak_word_t* pSrcLength);

const ak_byte_t* AK_GetByte(ak_byte_t* pValue, const ak_byte_t* pSrc, ak_word_t* pSrcLength);
const ak_byte_t* AK_GetWord(ak_word_t* pValue, const ak_byte_t* pSrc, ak_word_t* pSrcLength);
const ak_byte_t* AK_GetDWord(ak_dword_t* pValue, const ak_byte_t* pSrc, ak_word_t* pSrcLength);

/**
 * Gets the TLV object from the source buffer.
 *
 * @param pTlv			the TLV object.
 * @param pSrc			the source buffer.
 * @param pSrcLength	the available length of source buffer;
 *						on output the value is decremented by count of bytes successfully read. 
 *
 * @return				the pointer to a new position of the source buffer,
 *						available for subsequent reading;
 *						on any error NULL is returned.			
 */
const ak_byte_t* AK_GetTlv(ak_tlv_t* pTlv, const ak_byte_t* pSrc, ak_word_t* pSrcLength);

/**
 * Gets the TLV object from the source buffer and verifies whether it matches the specified tag.
 * Useful for parsing of sequences.
 *
 * @param pTlv			the TLV object.
 * @param tag			the expected tag.
 * @param pSrc			the source buffer.
 * @param pSrcLength	the available length of source buffer;
 *						on output the value is decremented by count of bytes successfully read. 
 *
 * @return				the pointer to a new position of the source buffer,
 *						available for subsequent reading;
 *						on any error NULL is returned.			
 */
const ak_byte_t* AK_GetTlvTag(ak_tlv_t* pTlv, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength);

/**
 * Gets the TLV object from the source buffer, verifies whether it matches the specified tag and length,
 * then copies the value byte array of TLV object into the value buffer.
 * Useful for parsing of sequences.
 *
 * @param pValue		the value buffer.
 * @param length		the requested count of bytes to be copied.
 * @param tag			the expected tag.
 * @param pSrc			the source buffer.
 * @param pSrcLength	the available length of source buffer;
 *						on output the value is decremented by count of bytes successfully read. 
 *
 * @return				the pointer to a new position of the source buffer,
 *						available for subsequent reading;
 *						on any error NULL is returned.			
 */
const ak_byte_t* AK_GetTlvBytes(ak_byte_t* pValue, ak_word_t length, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength);

const ak_byte_t* AK_GetTlvByte(ak_byte_t* pValue, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength);
const ak_byte_t* AK_GetTlvWord(ak_word_t* pValue, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength);
const ak_byte_t* AK_GetTlvDWord(ak_dword_t* pValue, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength);

ak_byte_t* AK_SkipBytes(ak_byte_t* pBuf, ak_word_t* pBufLength, ak_word_t length);

/**
 * Mix the server challenge into the entropy pool of the Authenticator.
 */
ak_result_t MixServerChallenge(cal_blob_t blobData);

/**
 * Encrypt and export the AK configuration which will be stored by MFAC
 *
 * @param pAKConfig pointer to the AK configuration to be exported
 * @param pConfigResp pointer to the array where the encrypted AK is going to be stored
 * @param pConfigRespLength pointer to the length of the encrypted AK configuration
 *
 * @return UAF_STATUS_ERR_BUFFER_SMALL if the encrypted config length > MAX_NNLCONFIG_SIZE
 *		   UAF_STATUS_ERR_UNKNOWN if the encryption failed
 *		   UAF_STATUS_OK if succeeded
 */
ak_result_t ExportConfig(ak_config_t *pAKConfig /*IN*/,
						 ak_byte_t *pConfigResp /*OUT*/,
						 ak_word_t *pConfigRespLength /*OUT*/);

/**
 * Parses TLV based request and extracts input arguments into a generic structure.
 *
 * @param pRequest			pointer to the TLV request
 * @param requestLength		length of the TLV request
 * @param pInputArgs		pointer to the output structure
 *
 * @return UAF_STATUS_ERR_UNSUPPORTED_CMD if the tlv command is not recognized
 *		   UAF_STATUS_ERR_UNKNOWN if failed to decrypt the AK configuration
 *		   UAF_STATUS_ERR_INVALID_PARAM if failed to parse the TLV request
 *		   UAF_STATUS_OK if succeeded
 */
ak_result_t ExtractInputArgs(const ak_byte_t* pRequest, ak_word_t requestLength, input_args_t *pInputArgs);

							   
#undef DUMP_HEX
#ifdef DUMP_HEX
void DumpData(const unsigned char* pData, unsigned long numBytes);
#define BDATA(_p_,_n_) DumpData(_p_,_n_)
#include <stdio.h>
#else
#define BDATA(_p_,_n_)
#endif

#endif /* __UAFAK_TLV_H__ */

