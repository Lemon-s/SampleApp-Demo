/* Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved. */


#include "uaf_ak_defs.h"
#include "uaf_ak_tlv.h"
#include <string.h>

//#define TEST_MODE

static const unsigned int HOST_ENDIAN = 0x03020100;
#define BIG_ENDIAN 3
#define ENDIANESS *(unsigned char*)&HOST_ENDIAN

#define SwapWord(val)  ( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )
#define SwapDWord(val) ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
	(((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )

static cal_byte_t g_publicKeyX[] = {
	0xd5, 0x46, 0x2d, 0x4c, 0x87, 0xef, 0x92, 0xd8, 0xa6, 0x93, 0x1d, 0x73, 0xb0, 0x07, 0x11, 0x26, 
	0x0f, 0xb5, 0xf8, 0xdd, 0x48, 0x5e, 0x71, 0xaa, 0xef, 0xdf, 0xb4, 0xa8, 0x50, 0xe9, 0xad, 0x5f};

static cal_byte_t g_publicKeyY[] = {
	0xf1, 0x3d, 0x3e, 0xde, 0xe0, 0x69, 0xf4, 0x48, 0x6b, 0xb3, 0xb1, 0xc8, 0xa5, 0x9b, 0xde, 0xb7, 
	0xe5, 0x09, 0x26, 0x08, 0xc2, 0xc1, 0x40, 0xa6, 0x2c, 0x5c, 0x4c, 0x90, 0xdc, 0x5c, 0xbe, 0xf8};

/**
 * validate the presence of necessary field in input argument
 *
 * @param pInputArgs pointer to the parsed input arguments
 */
ak_result_t ValidateInput(input_args_t *pInputArgs);

ak_result_t VerifyAKDir(
	const ak_byte_t *pSignature,
	ak_dword_t nSignatureSize,
	const ak_byte_t *pData,
	ak_dword_t nDataSize);


ak_byte_t* AK_WriteBytes(ak_byte_t* pDest, ak_word_t* pDestLength, const ak_byte_t* pValue, ak_word_t length)
{
	if (NULL == pDest || NULL == pDestLength || NULL == pValue)
		return NULL;

	if (*pDestLength < length)
	{
//		PRINT_ERROR("AK_WriteBytes: destination buffer[%u] is too small for data[%u].", *pDestLength, length);
		return NULL;
	}

//	nnl_memcpy(pDest, pValue, length);
    memcpy(pDest, pValue, length);
	*pDestLength -= length;
	return pDest + length;
}

ak_byte_t* AK_WriteByte(ak_byte_t* pDest, ak_word_t* pDestLength, ak_byte_t value)
{
	return AK_WriteBytes(pDest, pDestLength, &value, sizeof(ak_byte_t));
}

ak_byte_t* AK_WriteWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t value)
{
	if (ENDIANESS == BIG_ENDIAN)
		value = SwapWord(value);	
    
	//return AK_WriteBytes(pDest, pDestLength, (ak_byte_t*)&value, sizeof(ak_word_t));
    return AK_WriteBytes(pDest, pDestLength, (ak_byte_t*)&value, sizeof(ak_word_t));
}

ak_byte_t* AK_WriteDWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_dword_t value)
{
	if (ENDIANESS == BIG_ENDIAN)
		value = SwapDWord(value);	
    
	return AK_WriteBytes(pDest, pDestLength, (ak_byte_t*)&value, sizeof(ak_dword_t)); 
}


ak_byte_t* AK_WriteTlvBytes(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, const ak_byte_t* pValue, ak_word_t length)
{
	if (NULL == pDest || NULL == pDestLength || NULL == pValue)
		return NULL;

	pDest = AK_WriteWord(pDest, pDestLength, tag);
	pDest = AK_WriteWord(pDest, pDestLength, length);
	pDest = AK_WriteBytes(pDest, pDestLength, pValue, length);
	if (NULL == pDest)
	{
//		PRINT_ERROR("AK_WriteTlvBytes: failed to write a tag 0x%X.", tag);
	}

	return pDest;
}

ak_byte_t* AK_WriteTlvByte(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, ak_byte_t value)
{
	return AK_WriteTlvBytes(pDest, pDestLength, tag, &value, sizeof(ak_byte_t));
}

ak_byte_t* AK_WriteTlvWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, ak_word_t value)
{
	if (ENDIANESS == BIG_ENDIAN)
		value = SwapWord(value);	

	return AK_WriteTlvBytes(pDest, pDestLength, tag, (ak_byte_t*)&value, sizeof(ak_word_t));
}

ak_byte_t* AK_WriteTlvDWord(ak_byte_t* pDest, ak_word_t* pDestLength, ak_word_t tag, ak_dword_t value)
{
	if (ENDIANESS == BIG_ENDIAN)
		value = SwapDWord(value);	
    
	return AK_WriteTlvBytes(pDest, pDestLength, tag, (ak_byte_t*)&value, sizeof(ak_dword_t)); 
}



const ak_byte_t* AK_GetBytes(ak_byte_t* pValue, ak_word_t length, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	if (NULL == pValue || NULL == pSrc || NULL == pSrcLength)
		return NULL;

	if (*pSrcLength < length)
	{
//		PRINT_ERROR("AK_GetBytes: source buffer[%u] is too small for data[%u].", *pSrcLength, length);
		return NULL;
	}

	memcpy(pValue, pSrc, length);

	*pSrcLength -= length;
	return pSrc + length;
}

const ak_byte_t* AK_GetByte(ak_byte_t* pValue, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	return AK_GetBytes(pValue, sizeof(ak_byte_t), pSrc, pSrcLength);
}

const ak_byte_t* AK_GetWord(ak_word_t* pValue, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	pSrc = AK_GetBytes((ak_byte_t*)pValue, sizeof(ak_word_t), pSrc, pSrcLength);

	if (ENDIANESS == BIG_ENDIAN && NULL != pSrc)
		*pValue = SwapWord(*pValue);
	
	return pSrc;
}

const ak_byte_t* AK_GetDWord(ak_dword_t* pValue, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	pSrc = AK_GetBytes((ak_byte_t*)pValue, sizeof(ak_dword_t), pSrc, pSrcLength);

	if (ENDIANESS == BIG_ENDIAN && NULL != pSrc)
		*pValue = SwapDWord(*pValue);
	
	return pSrc;
}


const ak_byte_t* AK_GetTlv(ak_tlv_t* pTlv, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	if (NULL == pTlv || NULL == pSrc || NULL == pSrcLength)
		return NULL;

	pSrc = AK_GetWord(&pTlv->tag, pSrc, pSrcLength);
	if (NULL == pSrc)
		return NULL;

	pSrc = AK_GetWord(&pTlv->length, pSrc, pSrcLength);
	if (NULL == pSrc)
	{
//		PRINT_ERROR("AK_GetTlv: failed to read a tag 0x%X.", pTlv->tag);
		return NULL;
	}

	if (*pSrcLength < pTlv->length)
	{
//		PRINT_ERROR("AK_GetTlv: failed to read a tag 0x%X.", pTlv->tag);
		return NULL;
	}

	pTlv->value = (ak_byte_t*)pSrc;

	*pSrcLength -= pTlv->length;
	return pSrc + pTlv->length;
}

const ak_byte_t* AK_GetTlvTag(ak_tlv_t* pTlv, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	pSrc = AK_GetTlv(pTlv, pSrc, pSrcLength);
	if (NULL == pSrc)
		return NULL;

	if (pTlv->tag != tag)
	{
//		PRINT_ERROR("AK_GetTlvTag: failed to read a tag 0x%X.", tag);
		return NULL;
	}

	return pSrc;
}

const ak_byte_t* AK_GetTlvBytes(ak_byte_t* pValue, ak_word_t length, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	ak_tlv_t tlv = {0};
	
	pSrc = AK_GetTlvTag(&tlv, tag, pSrc, pSrcLength);
	if (NULL == pSrc)
		return NULL;

	if (tlv.length != length)
	{
//		PRINT_ERROR("AK_GetTlvBytes: failed to read a tag 0x%X. Invalid length %u.", tag, tlv.length);
		return NULL;
	}

	return AK_GetBytes(pValue, length, tlv.value, &tlv.length);
}

const ak_byte_t* AK_GetTlvByte(ak_byte_t* pValue, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	return AK_GetTlvBytes(pValue, sizeof(ak_byte_t), tag, pSrc, pSrcLength);
}

const ak_byte_t* AK_GetTlvWord(ak_word_t* pValue, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	pSrc = AK_GetTlvBytes((ak_byte_t*)pValue, sizeof(ak_word_t), tag, pSrc, pSrcLength);

	if (ENDIANESS == BIG_ENDIAN && NULL != pSrc)
		*pValue = SwapWord(*pValue);
	
	return pSrc;
}

const ak_byte_t* AK_GetTlvDWord(ak_dword_t* pValue, ak_word_t tag, const ak_byte_t* pSrc, ak_word_t* pSrcLength)
{
	pSrc = AK_GetTlvBytes((ak_byte_t*)pValue, sizeof(ak_dword_t), tag, pSrc, pSrcLength);

	if (ENDIANESS == BIG_ENDIAN && NULL != pSrc)
		*pValue = SwapDWord(*pValue);
	
	return pSrc;
}

ak_byte_t* AK_SkipBytes(ak_byte_t* pBuf, ak_word_t* pBufLength, ak_word_t length)
{
	if (NULL == pBuf || NULL == pBufLength)
		return NULL;

	if (*pBufLength < length)
	{
//		PRINT_ERROR("AK_SkipBytes: destination buffer[%u] is too small for data[%u].", *pBufLength, length);
		return NULL;
	}

	*pBufLength -= length;
	return pBuf + length;
}



ak_result_t MixServerChallenge(cal_blob_t blobData)
{
    /* TODO:
     Typically a RandSeed function is deterministic, i.e. whenever we call RandSeed(x) we'll get the same order of Random values.
     Mixing-in the serverChallenge MUST be done differently.
     --> Check whether gpCAL->CAL_RandSeed(&blobData) really mixes serverChallenge in our Entropy pool instead of setting the entropy pool.
     and if it does the right thing rename it to CAL_RandAdd()
     */
    /* TODO:
     I don't see issues with this. See CAL_RandSeed function description in CAL.h:
     "Stirs RNG internal entropy pool with given seed data."
     I think from description it should be clear that it doesn't throw existing seed, creating entirely new seed.
     Regarding of renaming the function:
     1. In NIST SP 800-90 the term reseeding and Reseed_function by default implying to mix with existing seed.
     2. OpenSSL also uses RAND_seed for mixing with internal state, so CAL_RandSeed at least is consistent with OpenSSL.
     CAL_RandAdd may be the cause of confusing with OpenSSL's RAND_Add function which means little different thing.
     */
//    if (NULL == gpCAL)
//    {
//        return UAF_CMD_STATUS_ERR_UNKNOWN;
//    }
//    
//    if (CAL_SUCCESS != gpCAL->CAL_RandSeed(&blobData))
//    {
//        return UAF_CMD_STATUS_ERR_UNKNOWN;
//    }
//    
    return UAF_CMD_STATUS_OK;
}





/**
 * Mix the server challenge into the entropy pool of the Authenticator.
 *
 * @param pChallenge pointer to the finalChallenge from the input
 * @param nChallengeLen length of the challenge
 */
//ak_result_t MixServerChallenge(cal_blob_t blobData)
//{
//  /* TODO: 
//     Typically a RandSeed function is deterministic, i.e. whenever we call RandSeed(x) we'll get the same order of Random values.
//     Mixing-in the serverChallenge MUST be done differently.
//     --> Check whether gpCAL->CAL_RandSeed(&blobData) really mixes serverChallenge in our Entropy pool instead of setting the entropy pool.
//     and if it does the right thing rename it to CAL_RandAdd()
//   */
//  /* TODO:
//	 I don't see issues with this. See CAL_RandSeed function description in CAL.h:
//	 "Stirs RNG internal entropy pool with given seed data."
//	 I think from description it should be clear that it doesn't throw existing seed, creating entirely new seed.
//	 Regarding of renaming the function:
//	 1. In NIST SP 800-90 the term reseeding and Reseed_function by default implying to mix with existing seed.
//	 2. OpenSSL also uses RAND_seed for mixing with internal state, so CAL_RandSeed at least is consistent with OpenSSL.
//		CAL_RandAdd may be the cause of confusing with OpenSSL's RAND_Add function which means little different thing.
//  */
//	if (NULL == gpCAL)
//	{
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//	}
//
//	if (CAL_SUCCESS != gpCAL->CAL_RandSeed(&blobData))
//	{
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//	}
//
//	return UAF_CMD_STATUS_OK;
//}
//
///**
// * Validate the presence of necessary field in input argument
// *
// * @param pInputArgs pointer to the parsed input arguments
// */
//ak_result_t ValidateInput(input_args_t* pInputArgs)
//{
//    if (NULL == pInputArgs) {
//        PRINT_ERROR("Input argument is null");
//		return UAF_STATUS_ERR_INVALID_PARAM;
//    }
//
//	if (TAG_UAFV1_GETINFO_CMD == pInputArgs->operationType ||
//		TAG_UAFV1_OPEN_SETTINGS_CMD == pInputArgs->operationType)
//			return UAF_CMD_STATUS_OK;
//
//	if (TAG_UAFV1_REGISTER_CMD == pInputArgs->operationType) 
//	{
//        if (NULL == pInputArgs->khAccessToken.pData || 0 == pInputArgs->khAccessToken.length) {
//            PRINT_ERROR("KHAccessToken is null or empty.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//        }
//        if (NULL == pInputArgs->finalChallenge.pData || 0 == pInputArgs->finalChallenge.length) {
//            PRINT_ERROR("finalChallenge is null or empty.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//        }
//        if (NULL == pInputArgs->username.pData || 0 == pInputArgs->username.length) {
//            PRINT_ERROR("Username is null or empty.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//        }
//	}
//	else if (TAG_UAFV1_SIGN_CMD == pInputArgs->operationType) 
//	{
//        if (NULL == pInputArgs->khAccessToken.pData || 0 == pInputArgs->khAccessToken.length) {
//            PRINT_ERROR("KHAccessToken is null or empty.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//        }
//        if (NULL == pInputArgs->finalChallenge.pData || 0 == pInputArgs->finalChallenge.length) {
//            PRINT_ERROR("finalChallenge is null or empty.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//        }
//	}
//	else if (TAG_UAFV1_MANAGE_PIN_CMD == pInputArgs->operationType) 
//	{
//        if (NULL == pInputArgs->finalChallenge.pData || 0 == pInputArgs->finalChallenge.length) {
//            PRINT_ERROR("finalChallenge is null or empty.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//        }
//	}
//	
//	return UAF_CMD_STATUS_OK;
//}
//
///**
// * Decrypt the exported AK configuration and parse it to an ak_config_t structure,
// * which contains the signcounter and a number of MAX_PIN_NUMBER pin slots.
// *
// * @param pConfig [IN/OUT]	the output ak_config_t structure.
// * @param pBuffer [IN]		the source buffer containing value part of TAG_NNL_AK_CONFIG tag
// * @param length [IN]		the length of source buffer
// */
//ak_result_t GetAKConfig(ak_config_t* pConfig, const ak_byte_t* pBuffer, ak_word_t length)
//{
//	ak_result_t result = UAF_CMD_STATUS_OK;
//
//	cal_blob_t wrapped = {0}; 
//	cal_blob_t unwrapped = {0};
//
//	const ak_byte_t* ptr = NULL;
//	ak_word_t remainder = 0;
//
//	ak_word_t i = 0;
//
//    PRINT_TIME("GetAKConfig");
//	if (NULL == pConfig || NULL == pBuffer)
//		return UAF_STATUS_ERR_INVALID_PARAM;
//
//	if (MAX_NNL_AK_CONFIG_SIZE < length) 
//	{
//		PRINT_ERROR("GetAKConfig: length of NNL_AK_CONFIG is larger than MAX_NNLCONFIG_SIZE.");
//		return UAF_STATUS_ERR_INVALID_PARAM;
//	}
//
//	if (0 == length)
//	{
//		return UAF_CMD_STATUS_OK;
//	}
//
//	// Unwrap
//	//
//	wrapped.pData = (ak_byte_t*)pBuffer;
//	wrapped.length = length;
//
//	result = UnwrapData(&wrapped, &unwrapped, 0, UVT_FORMAT_LOCAL);
//	if (UAF_CMD_STATUS_OK != result)
//	{
//		PRINT_ERROR("GetAKConfig: failed to unwrap data.");
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//	}
//
//	// Parse unwrapped data into ak_config_t structure
//	//
//	ptr = unwrapped.pData;
//	remainder = (ak_word_t)unwrapped.length;
//
//	ptr = AK_GetDWord(&pConfig->version, ptr, &remainder);
//	ptr = AK_GetDWord(&pConfig->signCounter, ptr, &remainder);
//	ptr = AK_GetDWord(&pConfig->regCounter, ptr, &remainder);
//	ptr = AK_GetWord(&pConfig->PINConfig.pinNum, ptr, &remainder);
//	if (NULL == ptr)
//	{
//		PRINT_ERROR("GetAKConfig: failed to parse configuration.");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//	if (ENROLLMENT_CONFIG_VERSION != pConfig->version) 
//	{
//		PRINT_ERROR("GetAKConfig: version of enrollment configuration doesn't match.");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//	if (MAX_PIN_NUMBER < pConfig->PINConfig.pinNum)
//	{
//		PRINT_ERROR("GetAKConfig: invalid enrollment configuration.");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//
//	for (i = 0; i < pConfig->PINConfig.pinNum; ++i)
//	{
//		// Get members of each ak_pin_slot_t structure
//		ptr = AK_GetWord(&pConfig->PINConfig.pins[i].index, ptr, &remainder);
//		ptr = AK_GetWord(&pConfig->PINConfig.pins[i].pinSize, ptr, &remainder);
//		ptr = AK_GetBytes(pConfig->PINConfig.pins[i].pin, MAX_PIN_LENGTH, ptr, &remainder);
//		ptr = AK_GetBytes(pConfig->PINConfig.pins[i].enrollID, MAX_ENROLLID_LENGTH, ptr, &remainder);
//		ptr = AK_GetWord(&pConfig->PINConfig.pins[i].failCounter, ptr, &remainder);
//
//		if (NULL == ptr)
//		{
//			PRINT_ERROR("GetAKConfig: failed to parse PIN configuration.");
//			result = UAF_CMD_STATUS_ERR_UNKNOWN;
//			goto cleanup;
//		}
//	}
//
//cleanup:
//	if (NULL != unwrapped.pData)
//	{
//		nnl_memset_s(unwrapped.pData, 0, unwrapped.length);
//		nnl_free(unwrapped.pData);
//	}
//    PRINT_TIME("GetAKConfig finishing");
//
//	return result;
//}
//
//
//ak_result_t GetExtensionTags(ak_tlv_t* pTlv, input_args_t* pInputArgs)
//{
//	if (NULL == pTlv || NULL == pInputArgs)
//		return UAF_STATUS_ERR_INVALID_PARAM;
//	if (pTlv->value == NULL)
//		return UAF_STATUS_ERR_INVALID_PARAM;	
//
//	switch (pTlv->tag)
//	{
//	case TAG_NNL_AK_CONFIG:
//		return GetAKConfig(pInputArgs->pConfig, pTlv->value, pTlv->length);
//
//	default:
//		if (MAX_EXPECTED_TAGS_NUM == pInputArgs->extensionTags.numTags) 
//		{
//			PRINT_ERROR("GetExtensionTags: failed because of too many extensions.");
//			return UAF_STATUS_ERR_INVALID_PARAM;
//		}
//		pInputArgs->extensionTags.tlvs[pInputArgs->extensionTags.numTags++] = *pTlv;
//		return UAF_CMD_STATUS_OK;
//	}
//}
//
///**
// * Given a TLV request, extract the operation type and the various arguments that may be present. Validate
// * the input parameters to make sure they are correct.
// *
// * @param pRequest [IN] the TLV request
// * @param requestLength [IN] the length of the TLV request
// * @param pInputArgs [OUT] contains the operation type and arguments extracted from the TLV request
// *
// * @return status
// */
//ak_result_t ExtractInputArgs(const ak_byte_t* pRequest, ak_word_t requestLength, input_args_t *pInputArgs)
//{
//	const ak_byte_t* ptr = pRequest;
//	ak_word_t remainder = requestLength;
//
//	ak_tlv_t cmd = {0};
//	ak_word_t numOfCerts = 0;
//
//	if (NULL == pRequest || NULL == pInputArgs || NULL == gpCAL)
//		return UAF_STATUS_ERR_INVALID_PARAM;
//
//	// Get command TLV
//	ptr = AK_GetTlv(&cmd, ptr, &remainder);
//	if (NULL == ptr)
//	{
//		PRINT_ERROR("ExtractInputArgs: incorrect buffer length.");
//		return UAF_STATUS_ERR_INVALID_PARAM;
//	}
//
//	if (remainder > 0)
//	{
//		// There is unexpected data.
//		// Should we return error or just ignore it ?
//	}
//
//	// Set command
//	pInputArgs->operationType = cmd.tag;
//	PRINT_INFO("ExtractInputArgs: tag=0x%X length=%u", cmd.tag, cmd.length);
//
//	// Parse command data
//	ptr = cmd.value;
//	remainder = cmd.length;
//
//	if (TAG_UAFV1_REGISTER_CMD == cmd.tag || 
//		TAG_UAFV1_SIGN_CMD == cmd.tag || 
//		TAG_UAFV1_MANAGE_PIN_CMD == cmd.tag)
//	{
//		while (remainder > 0)
//		{
//			ak_tlv_t tlv = {0};
//
//			ptr = AK_GetTlv(&tlv, ptr, &remainder);
//			if (NULL == ptr)
//			{
//				PRINT_ERROR("ExtractInputArgs: incorrect buffer length.");
//				return UAF_STATUS_ERR_INVALID_PARAM;
//			}
//
//			switch (tlv.tag)
//			{
//			case TAG_AUTHENTICATOR_INDEX:
//				if (tlv.length != sizeof(ak_byte_t)) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_AUTHENTICATOR_INDEX length != 1.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				AK_GetByte(&pInputArgs->authenticatorID, tlv.value, &tlv.length);
//				break;
//
//			case TAG_APPID:
//				if (tlv.length > MAX_APPID_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_APPID size is too large.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				// current AK does not require AppID
//				break;
//
//			case TAG_FINAL_CHALLENGE:
//				if (tlv.length > MAX_CHALLENGE_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_FINAL_CHALLENGE size is too large.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				PRINT_INFO("ExtractInputArgs: TAG_FINAL_CHALLENGE OK.");
//				pInputArgs->finalChallenge.length = tlv.length;
//				pInputArgs->finalChallenge.pData = tlv.value;
//				break;
//
//			case TAG_USERNAME:
//				if (tlv.length > MAX_USERNAME_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_USERNAME size is too large.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				PRINT_INFO("ExtractInputArgs: TAG_USERNAME OK.");
//				pInputArgs->username.length = tlv.length;
//				pInputArgs->username.pData = tlv.value;
//				break;
//
//			case TAG_ATTESTATION_TYPE:
//				if (tlv.length != sizeof(ak_word_t)) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_ATTESTATION_TYPE size != 2.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				AK_GetWord(&pInputArgs->attestationType, tlv.value, &tlv.length);
//				break;
//
//			case TAG_KEYHANDLE_ACCESS_TOKEN:
//					if (tlv.length != ASM_KHACCESSTOKEN_SIZE) 
//					{
//						PRINT_ERROR("ExtractInputArgs: failed because MAX_KHACCESSTOKEN_SIZE size is too large.");
//						return UAF_STATUS_ERR_INVALID_PARAM;
//					}
//					if (pInputArgs->khAccessToken.length == 0)
//					{
//						PRINT_INFO("ExtractInputArgs: TAG_KEYHANDLE_ACCESS_TOKEN OK.");
//						pInputArgs->khAccessToken.length = tlv.length;
//						pInputArgs->khAccessToken.pData = tlv.value;					
//					}
//					// Otherwise ignore it: KHAccessToken passed as a parameter to UAF_AK_Process function
//					break;
//			case TAG_USERVERIFY_TOKEN:
//				if (tlv.length > MAX_UVT_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_USERVERIFY_TOKEN size is too large.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				PRINT_INFO("ExtractInputArgs: TAG_USERVERIFY_TOKEN OK.");
//				pInputArgs->userVerifyToken.length = tlv.length;
//				pInputArgs->userVerifyToken.pData = tlv.value;
//				break;
//
//			case TAG_TRANSACTION_CONTENT:
//				if (TAG_UAFV1_SIGN_CMD != pInputArgs->operationType || tlv.length > MAX_TRANSACTION_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_TRANSACTION_CONTENT is invalid.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				PRINT_INFO("ExtractInputArgs: TAG_TRANSACTION_CONTENT OK.");
//				pInputArgs->transactionContent.length = tlv.length;
//				pInputArgs->transactionContent.pData = tlv.value;
//				break;
//
//			case TAG_KEYHANDLE:
//				if (tlv.length > MAX_KEYHANDLE_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_KEYHANDLE is too large.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				if (pInputArgs->keyHandlesNum >= MAX_KEYHANDLE_NUM) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because of too many TAG_KEYHANDLE.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}				
//				PRINT_INFO("ExtractInputArgs: TAG_KEYHANDLE OK.");
//				pInputArgs->keyHandles[pInputArgs->keyHandlesNum].length = tlv.length;
//				pInputArgs->keyHandles[pInputArgs->keyHandlesNum++].pData = tlv.value;
//				break;
//
//			case TAG_TRANSACTION_CONFIRMATION_TOKEN:
//				if (tlv.length > MAX_TCTOKEN_SIZE) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because TAG_TRANSACTION_CONFIRMATION_TOKEN is too large.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				PRINT_INFO("ExtractInputArgs: TAG_TRANSACTION_CONFIRMATION_TOKEN OK.");
//				pInputArgs->tcToken.length = tlv.length;
//				pInputArgs->tcToken.pData = tlv.value;
//				break;
//
//			default:
//				if (UAF_CMD_STATUS_OK != GetExtensionTags(&tlv, pInputArgs)) 
//				{
//					PRINT_ERROR("ExtractInputArgs: failed because customized extension is invalid.");
//					return UAF_STATUS_ERR_INVALID_PARAM;
//				}
//				PRINT_INFO("ExtractInputArgs: EXTENSION [0x%X] OK.", tlv.tag);
//				break;
//			}
//		}
//	}
//#ifdef AK_ENABLE_AUTO_CONFIG
//	else if (TAG_UAFV1_ADD_AUTHNR_CMD == cmd.tag)
//	{
//		ak_tlv_t aaid = { 0 };
//	    /* TODO: ifdefed out to implement the ability to add new authenticators.
//	     */
//    
//		// Currently this command represents a predefined sequence
//
//
//		// Get AUTHENTICATOR data
//		//
//		PRINT_INFO("ExtractInputArgs: Parsing [0x%X] OK.", cmd.tag);
//
//		// TAG_AAID
//		ptr = AK_GetTlvTag(&aaid, TAG_AAID, ptr, &remainder);
//		if ((NULL == ptr) || (AAID_SIZE != aaid.length))
//		{
//			PRINT_ERROR("ExtractInputArgs Add Authenticator: failed to get TAG_AAID.");
//			return UAF_STATUS_ERR_INVALID_PARAM;
//		}
//
//		pInputArgs->authenticatorAAID = aaid.value;
//
//		while(remainder > 0 && numOfCerts < MAX_CERTIFICATES_NUM)
//		{
//			ak_tlv_t cert = {0};
//			// TAG_ATTESTATION_CERT
//			ptr = AK_GetTlvTag(&cert, TAG_ATTESTATION_CERT, ptr, &remainder);
//			if (NULL == ptr || cert.length <= 0)
//			{
//				PRINT_ERROR("ExtractInputArgs: failed to get TAG_ATTESTATION_CERT.");
//				return UAF_STATUS_ERR_INVALID_PARAM;
//			}
//			pInputArgs->attestationCerts[numOfCerts].length = cert.length;
//			pInputArgs->attestationCerts[numOfCerts].pData = cert.value;
//
//			//Update the gCertificates
//			numOfCerts++;
//		}
//
//
//		PRINT_INFO("ExtractInputArgs: TAG_UAFV1_ADD_AUTHNR_CMD OK.");
//		
//	}
////	else if (TAG_AKDIR_UPDATE_CMD == cmd.tag && 0)
////	{
////	    /* TODO: ifdefed out to implement the ability to add new authenticators.
////	     */
////
////		// Currently this command represents a predefined sequence
////
////		ak_tlv_t sig = {0};
////
////		// TAG_AKDIR_SIGNATURE
////		ptr = AK_GetTlvTag(&sig, TAG_AKDIR_SIGNATURE, ptr, &remainder);
////		if (NULL == ptr || sig.length != MAX_AKDIR_SIGNATURE_SIZE)
////		{
////			PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_SIGNATURE.");
////			return UAF_STATUS_ERR_INVALID_PARAM;
////		}
////
////		if (UAF_CMD_STATUS_OK != VerifyAKDir(sig.value, sig.length, ptr, remainder))
////		{
////			PRINT_ERROR("ExtractInputArgs: failed to verify signature.");
////			return UAF_CMD_STATUS_ERR_UNKNOWN;
////		}
////		PRINT_INFO("ExtractInputArgs: TAG_AKDIR_SIGNATURE OK.");
////
////		// TAG_AKDIR_VERSION
////		ptr = AK_GetTlvDWord(&pInputArgs->AkDirVersion, TAG_AKDIR_VERSION, ptr, &remainder);
////		if (NULL == ptr)
////		{
////			PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_VERSION.");
////			return UAF_STATUS_ERR_INVALID_PARAM;
////		}
////		PRINT_INFO("ExtractInputArgs: TAG_AKDIR_VERSION OK.");
////
////		// Get list of TAG_AKDIR_AUTHENTICATOR
////		while (remainder > 0)
////		{
////			authenticatorCtx_t* ctx = NULL;
////
////			ak_tlv_t tlv = {0};
////
////			const ak_byte_t* buf = NULL;
////			ak_word_t len = 0;
////
////			if (pInputArgs->authNum >= MAX_AUTHENTICATORS_NUM)
////			{
////				// Should not we return error?
////				break;
////			}
////			ctx = &pInputArgs->authCtxList[pInputArgs->authNum];
////			pInputArgs->authNum++;
////
////			// TAG_AKDIR_AUTHENTICATOR
////			ptr = AK_GetTlvTag(&tlv, TAG_AKDIR_AUTHENTICATOR, ptr, &remainder);
////			if (NULL == ptr)
////			{
////				PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_VERSION.");
////				return UAF_STATUS_ERR_INVALID_PARAM;
////			}
////
////			// Get TAG_AKDIR_AUTHENTICATOR data
////			//
////			buf = tlv.value;
////			len = tlv.length;
////
////			// TAG_AKDIR_AAID
////			buf = AK_GetTlvBytes(ctx->aaid, AAID_SIZE, TAG_AKDIR_AAID, buf, &len);
////			if (NULL == buf)
////			{
////				PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_AAID.");
////				return UAF_STATUS_ERR_INVALID_PARAM;
////			}
////
////			// TAG_AKDIR_CONTAINER_ID
////			buf = AK_GetTlvTag(&tlv, TAG_AKDIR_CONTAINER_ID, buf, &len);
////			if (NULL == buf)
////			{
////				PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_CONTAINER_ID.");
////				return UAF_STATUS_ERR_INVALID_PARAM;
////			}
////			ctx->containerID.length = tlv.length;
////			ctx->containerID.pData = tlv.value;
////
////			// TAG_AKDIR_UVT_PROTECTION
////			buf = AK_GetTlvByte(&ctx->UVTProtection, TAG_AKDIR_UVT_PROTECTION, buf, &len);
////			if (NULL == buf)
////			{
////				PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_UVT_PROTECTION.");
////				return UAF_STATUS_ERR_INVALID_PARAM;
////			}
////
////			// TAG_AKDIR_CERTIFICATE
////			buf = AK_GetTlvTag(&tlv, TAG_AKDIR_CERTIFICATE, buf, &len);
////			if (NULL == buf)
////			{
////				PRINT_ERROR("ExtractInputArgs: failed to get TAG_AKDIR_CERTIFICATE.");
////				return UAF_STATUS_ERR_INVALID_PARAM;
////			}
////			//TODO: use this approach
////			////pCtx->certificate.length = tlv.length;
////			////pCtx->certificate.pData = tlv.value;
////			// which requires modifications in UpdateAKDirectory and related functions
////
////
////			ctx->certificate.length = tlv.length;
////			ctx->certificate.pData = (ak_byte_t*)nnl_malloc(tlv.length);
////			nnl_memcpy(ctx->certificate.pData, tlv.value, tlv.length);
////
////			PRINT_INFO("ExtractInputArgs: TAG_AKDIR_AUTHENTICATOR OK.");
////		}
////	}
//
//#endif
//	else if (TAG_UAFV1_DEREGISTER_CMD == cmd.tag ||
//			 TAG_UAFV1_GETINFO_CMD == cmd.tag)
//	{
//		// No args
//	}
//	else
//	{
//		PRINT_ERROR("ExtractInputArgs: unsupported command 0x%X.", cmd.tag);
//		return UAF_CMD_STATUS_CMD_NOT_SUPPORTED;
//	}
//    PRINT_TIME("ExtractInputArgs");
//	return ValidateInput(pInputArgs);
//}
//
//
///**
// * Encrypt and export the AK configuration which will be stored by MFAC
// *
// * @param pAKConfig	[IN]			pointer to the AK configuration to be exported
// * @param pConfig [IN/OUT]			the output buffer
// * @param pConfigLength [IN/OUT]	the length of output
// */
///* TODO: Consider to change enrollment config to be TLV-formed data
//					 (e.g. define TAGs for the members of ak_config_t structure write members into TAGs).
//					 It will allow to get rid of backward compatibility issues in the future,
//					 when new members are added/removed into configuration structure.
//					 Only version tracking itself is not enough for easy backward compatibility support.
//*/
///*Separate defect was filled for this change: DE4382 */
//ak_result_t ExportConfig(ak_config_t* pAKConfig, ak_byte_t* pConfig, ak_word_t* pConfigLength)
//{
//	ak_result_t result = UAF_CMD_STATUS_OK;
//
//	ak_byte_t* dst = NULL;
//	ak_word_t dstLen = 0;
//
//	ak_word_t i = 0;
//
//	cal_blob_t clear = {0};
//	cal_blob_t wrapped = {0};
//
//	ak_word_t cfgLen = 0;
//
//	// Veryfy input arguments
//	//
//	if (NULL == pAKConfig || NULL == pConfig || NULL == pConfigLength)
//		return UAF_STATUS_ERR_INVALID_PARAM;
//
//	// Add version of enrolment configuration
//	pAKConfig->version = ENROLLMENT_CONFIG_VERSION;
//
//	// Encode AK configuration into the output buffer in clear.
//	// Later it will be replaced with wrapped data.
//	//
//	dst = pConfig;
//	dstLen = *pConfigLength;
//
//	// Serialize ak_config_t structure
//	dst = AK_WriteDWord(dst, &dstLen, pAKConfig->version);
//	dst = AK_WriteDWord(dst, &dstLen, pAKConfig->signCounter);
//	dst = AK_WriteDWord(dst, &dstLen, pAKConfig->regCounter);
//	dst = AK_WriteWord(dst, &dstLen,  pAKConfig->PINConfig.pinNum);
//	// Serialize each ak_pin_slot_t structure
//	for (i = 0; i < pAKConfig->PINConfig.pinNum; ++i)
//	{
//		dst = AK_WriteWord(dst, &dstLen, pAKConfig->PINConfig.pins[i].index);
//		dst = AK_WriteWord(dst, &dstLen, pAKConfig->PINConfig.pins[i].pinSize);
//		// For easy handling the serialized AK Config size we are writing whole PIN buffer.
//		// Should be changed to write exact size of PIN when AK Config is serialized into TLV
//		dst = AK_WriteBytes(dst, &dstLen, pAKConfig->PINConfig.pins[i].pin, MAX_PIN_LENGTH);
//		dst = AK_WriteBytes(dst, &dstLen, pAKConfig->PINConfig.pins[i].enrollID, MAX_ENROLLID_LENGTH);
//		dst = AK_WriteWord(dst, &dstLen,  pAKConfig->PINConfig.pins[i].failCounter);
//	}
//	if (NULL == dst)
//	{
//		PRINT_ERROR("ExportConfig: failed to encode AK configuration.");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//
//	// Wrap
//	//
//	clear.length = (ak_dword_t)(dst - pConfig);
//	clear.pData = pConfig;
//
//	result = WrapData(&clear, &wrapped);
//	// On success wpapped.pData was allocated
//	if (UAF_CMD_STATUS_OK != result)
//	{
//		PRINT_ERROR("ExportConfig: failed to wrap data.");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//
//	// Finalize with length
//	//
//	cfgLen = (ak_word_t)(TLV_TL_SIZE + wrapped.length);
//	if (*pConfigLength < cfgLen)
//	{
//		PRINT_ERROR("ExportConfig: buffer[%u] is too small for data[%u].", *pConfigLength, cfgLen);
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//	/* TODO: why don't we check that (encLen + TLV_TAG_AND_LENGTH_SIZE) < MAX_NNL_AK_CONFIG_SIZE?
//	   If this is the case we'll never be able to read it again.
//	 */
//	if (MAX_NNL_AK_CONFIG_SIZE < cfgLen)
//	{
//		PRINT_ERROR("ExportConfig: data[%u] is too big.", cfgLen);
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//	
//	// Finalize with data
//	//
//	// Wipe pConfig before writing encrypted Config data
//	nnl_memset_s(pConfig, 0, cfgLen);
//
//	// Write the TAG_NNL_AK_CONFIG to the response buffer
//	dst = pConfig;
//	dstLen = cfgLen;
//
//	// This is safe, since output length already checked
//	AK_WriteTlvBytes(dst, &dstLen, TAG_NNL_AK_CONFIG, wrapped.pData, (ak_word_t)wrapped.length);
//	*pConfigLength = cfgLen;
//
//cleanup:
//	if (UAF_CMD_STATUS_OK != result)
//	{
//		// Wipe pConfig 
//		nnl_memset_s(pConfig, 0, *pConfigLength);
//	}
//	if (NULL != wrapped.pData)
//	{
//		nnl_memset_s(wrapped.pData, 0, wrapped.length);
//		nnl_free(wrapped.pData);
//	}
//
//	return result;
//}
//
///**
// * Verify the signature on the directory.
// *
// * DE4410: Keep this routine as is. We will repurpose it to verify the signature on for
// * the TAG_ADDAUTHENTICATOR_CMD command.
// */
//ak_result_t VerifyAKDir(const ak_byte_t *pSignature, ak_dword_t nSignatureSize,
//						const ak_byte_t *pData, ak_dword_t nDataSize)
//{
//	ak_result_t result = UAF_CMD_STATUS_OK;
//
//	cal_pubkey_blob_t PubKeyBLOB = {0};
//	cal_handle_t  hPubKey = NULL;
//
//	cal_blob_t SignatureBLOB = {0};
//	cal_blob_t DataBLOB = {0};
//
//	cal_pubkey_t PubKeyBuff;
//
//	if (NULL == pSignature || NULL == pData)
//		return UAF_STATUS_ERR_INVALID_PARAM;
//	if (NULL == gpCAL)
//		return UAF_STATUS_ERR_NOTINITIALIZED;
//
//
//	PubKeyBLOB.pPubKey = &PubKeyBuff;
//
//	/* Import Key */
//	//PubKeyBLOB.nPubKeyLen = ;
//	PubKeyBLOB.pPubKey->ec.algid = CAL_ALG_ECDSA;
//	PubKeyBLOB.pPubKey->ec.x.length = 32;
//	PubKeyBLOB.pPubKey->ec.x.pData = &g_publicKeyX[0];
//	PubKeyBLOB.pPubKey->ec.y.length = 32;
//	PubKeyBLOB.pPubKey->ec.y.pData = &g_publicKeyY[0];
//
//	if (CAL_SUCCESS != gpCAL->CAL_ImportPubKey(&PubKeyBLOB, &hPubKey)) 
//	{
//		PRINT_ERROR("UnwrapKeyHandle: failed to unwrap the UAuth key.");
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//	}
//
//	SignatureBLOB.length = nSignatureSize;
//	SignatureBLOB.pData = (ak_byte_t *)pSignature;
//
//	DataBLOB.length = nDataSize;
//	DataBLOB.pData = (ak_byte_t *)pData;
//
//	if (CAL_SUCCESS != gpCAL->CAL_Verify(hPubKey, &DataBLOB, &SignatureBLOB))
//	{
//		PRINT_ERROR("CAL_Verify is Failed");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto cleanup;
//	}
//
//cleanup:
//	gpCAL->CAL_CloseHandle(hPubKey);
//
//	return result;
//}

#ifdef DUMP_HEX
void DumpData( const unsigned char* pData, unsigned long numBytes)
{
#define CHAR_PER_LINE 16

#define APPEND_ADDR(_a_)    { ptr += sprintf(ptr, "%06x: ", (_a_)); }
#define APPEND_HEX(_h_)     { ptr += sprintf(ptr, "%02x ",  (_h_)); }
#define APPEND_CHAR(_c_)    { ptr += sprintf(ptr, "%c", ((0x1f<(_c_))&&((_c_)<0x7f))? (_c_) : '.'); }
#define APPEND_TEXT_DELIM() { ptr += sprintf(ptr, " "); }
#define SKIP_HEX()          { ptr += sprintf(ptr, "   "); }

	unsigned char buf[100];
	unsigned char* ptr = &buf[0];
	unsigned int i;
	unsigned int j;

    for (i=0; i<numBytes; i+=CHAR_PER_LINE) {
		ptr = &buf[0];
        APPEND_ADDR(i);
        for (j=0; j<CHAR_PER_LINE; j++) {
            if (i+j < numBytes){
				APPEND_HEX(pData[i+j]);
            }
            else {
				SKIP_HEX();
            }
        }
		APPEND_TEXT_DELIM();
        for (j=0; j<CHAR_PER_LINE; j++) {
            if (i+j < numBytes){
                APPEND_CHAR(pData[i+j]);
            }
        }
		gCAL_sft.CAL_Log(buf);
    }
}
#endif
