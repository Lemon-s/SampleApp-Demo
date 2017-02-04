/* Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved. */

#include "akDefs.h"
#include "uaf_ak_tlv.h"
#include "uaf_ak_defs.h"
#include "uaf_ak_token_verifier.h"
#include "uaf_ak_util.h"
#include "gmrz_jv_ecc_cal_ext.h"


/*
 * Verify the transaction confirmation token during secure transaction
 * @param pInfo[IN] pointer to the input
 */
ak_result_t VerifyTCT(input_args_t *pInputArgs) 
{
	const ak_byte_t* src = NULL;
	ak_word_t srcLen = 0;

	cal_blob_t hash = {0};
	ak_byte_t hashBuffer[CAL_MAX_HASH_SIZE] = {0};

	ak_tlv_t tcTokenContent = {0};
	ak_byte_t tcTokenType = 0;
	cal_blob_t tcTokenHash = {0};
	cal_blob_t tcTokenChallenge = {0};


	// Verify input arguments
	//
	if (NULL == pInputArgs)
		return UAF_STATUS_ERR_INVALID_PARAM;

	// Verify input data
	//
	// If current operation is not a secure transaction, always return UAF_CMD_STATUS_OK
	// (pInputArgs->transactionContent is a value of TAG_TRANSACTION_CONTENT) 
	if (NULL == pInputArgs->transactionContent.pData || 0 == pInputArgs->transactionContent.length)
		return UAF_CMD_STATUS_OK;
	// If no TCT is present, fail the verification
	// (pInputArgs->tcToken is a value of TAG_TRANSACTION_CONFIRMATION_TOKEN)
	if (NULL == pInputArgs->tcToken.pData || 0 == pInputArgs->tcToken.length)
	{
//		PRINT_ERROR("VerifyTCT: failed because no valid TCT is present.");
        printf("VerifyTCT: failed because no valid TCT is present.");
		return UAF_CMD_STATUS_ACCESS_DENIED;
	}
	// Verify a presence of final challenge
	if (NULL == pInputArgs->finalChallenge.pData || 0 == pInputArgs->finalChallenge.length) 
	{
//		PRINT_ERROR("VerifyTCT: challenge is not present.");
        printf("VerifyTCT: challenge is not present.");
		return UAF_CMD_STATUS_ACCESS_DENIED;
	}


	// Determine the exact size of the hash
    
    hash.length = 32;
//	if (NULL == gpCAL || CAL_SUCCESS != gpCAL->CAL_HashData(NULL, &hash)) 
//	{
//		PRINT_ERROR("VerifyTCT: CAL_HashData failed to get the size of the hash.");
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//	}


	// Decode TAG_TRANSACTION_CONTENT value
	//
	//			TAG_TC_TOKEN_TYPE | length (always 1) | type value (plaintext or wrapped)
	//			TAG_TC_TOKEN_CONTENT | length | hash of transaction | finalChallenge
	//
	src = pInputArgs->tcToken.pData;
	srcLen = (ak_word_t)pInputArgs->tcToken.length;

	src = AK_GetTlvByte(&tcTokenType, TAG_TC_TOKEN_TYPE, src, &srcLen);
	src = AK_GetTlvTag(&tcTokenContent, TAG_TC_TOKEN_CONTENT, src, &srcLen);
	if (NULL == src)
	{
//		PRINT_ERROR("VerifyTCT: failed to decode TAG_TRANSACTION_CONTENT value.");
        printf("VerifyTCT: failed to decode TAG_TRANSACTION_CONTENT value.");
		return UAF_CMD_STATUS_ERR_UNKNOWN;
	}
	if (TYPE_TCT_PLAINTEXT != tcTokenType)
	{
		// Only TYPE_TCT_PLAINTEXT is supported currently.
		// Should we ignore tcTokenType value, or return error in this case?
	}


	// Split tcTokenContent value, 
	// which is a concatenation of Hash and FinalChallenge
	//
	if (tcTokenContent.length < hash.length)
	{
//		PRINT_ERROR("VerifyTCT: failed to decode TAG_TC_TOKEN_CONTENT value.");
        printf("VerifyTCT: failed to decode TAG_TC_TOKEN_CONTENT value.");
        
		return UAF_CMD_STATUS_ERR_UNKNOWN;
	}

	tcTokenHash.pData = tcTokenContent.value;
	tcTokenHash.length = hash.length;

	tcTokenChallenge.pData = tcTokenContent.value + hash.length;
	tcTokenChallenge.length = tcTokenContent.length - hash.length;


	// Verify final challenge
	//
	if (0 != CompareBlobs(pInputArgs->finalChallenge.pData, (ak_word_t)pInputArgs->finalChallenge.length,
						  tcTokenChallenge.pData, (ak_word_t)tcTokenChallenge.length))
	{
//		PRINT_ERROR("VerifyTCT: failed because challenge doesn't match.");
        printf("VerifyTCT: failed to decode TAG_TC_TOKEN_CONTENT value.");
		return UAF_CMD_STATUS_ACCESS_DENIED;
	}

	// Verify hash
	//
	// Compute TC hash
	hash.pData = hashBuffer;
    hash.length = CAL_MAX_HASH_SIZE;
    uint8_t *hashcopy =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:pInputArgs->transactionContent.pData length:pInputArgs->transactionContent.length];
    
    
    memcpy(hash.pData, hashcopy, hash.length);
  
//	if (CAL_SUCCESS != gpCAL->CAL_HashData(&pInputArgs->transactionContent, &hash))
    if (hashcopy) 
	{
//		PRINT_ERROR("VerifyTCT: failed to calculate TCHash.");
        printf("VerifyTCT: failed to calculate TCHash.");
		return UAF_CMD_STATUS_ERR_UNKNOWN;
	}
	if (0 != CompareBlobs(hash.pData, (ak_word_t)hash.length,
						  tcTokenHash.pData, (ak_word_t)tcTokenHash.length)) 
	{
//		PRINT_ERROR("VerifyTCT: invalid transaction hash.");
        printf("VerifyTCT: failed to calculate TCHash.");
		return UAF_CMD_STATUS_ACCESS_DENIED;
	}

	return UAF_CMD_STATUS_OK;
}


