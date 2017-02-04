/* Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved. */

/* TODO: merge this file with ak_token_verifier.c ? */
#include "akDefs.h"
#include "uaf_ak_defs.h"
#include "uaf_ak_tlv.h"
#include "uaf_ak_uvt.h"
#include "uaf_ak_keyhandle.h"
#include "uaf_ak_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/**
 * Performs TLV encoding of specified UVT structure providing lengths of both
 * ToBeWrappedData and ClearData.
 *
 * @param pUvt						the UVT data to be encoded
 * @param pDest						the output buffer
 * @param destLength				the output buffer length
 * @param pToBeWrappedDataLength	the resulting length of ToBeWrappedData
 * @param pClearDataLength			the resulting length of ClearData
 */
ak_result_t EncodeUVTData(const uvt_t* pUvt, ak_byte_t* pDest, ak_word_t destLength, ak_word_t* outputDataLength);

/**
 * Performs TLV decoding of UVT structure members.
 *
 * @param pSrc		the source data buffer
 * @param srcLength	the source data length
 * @param pUvt		the resulting UVT data
 */
ak_result_t DecodeUVTData(const ak_byte_t* pSrc, ak_word_t srcLen, uvt_t* pUvt);



ak_result_t EncodeUVT(const uvt_t* pUvt, ak_byte_t* pUvtOut, ak_word_t* pUvtOutLength)
{
	ak_result_t result = UAF_CMD_STATUS_OK;

	ak_byte_t buffer[MAX_UVT_SIZE] = {0};

	cal_blob_t wrapped = {0};
	cal_blob_t toBeWrapped = {0};

	ak_word_t toBeWrappedDataLength = 0;

	ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;

	//////// Verify input arguments
	//
	if (NULL == pUvt || NULL == pUvtOut || NULL == pUvtOutLength) 
	{
//		PRINT_ERROR("EncodeUVT: invalid input argument.");
        printf("%s","EncodeUVT: invalid input argument.");
		return UAF_STATUS_ERR_INVALID_PARAM;
	}

	/////// Encode UVT members
	//
	ptr = buffer;
	toBeWrapped.pData = ptr;

	result = EncodeUVTData(pUvt, ptr, sizeof(buffer), &toBeWrappedDataLength);
	if (UAF_CMD_STATUS_OK != result) 
	{
//		PRINT_ERROR("EncodeUVT: failed to encode UVT data.");
         printf("%s","EncodeUVT: failed to encode UVT data.");
		goto cleanup;
	}

	toBeWrapped.length = toBeWrappedDataLength;

	//////// Build WrappedData
	//
//	result = WrapData(&toBeWrapped, &wrapped);
//	if (UAF_CMD_STATUS_OK != result) 
//	{
////		PRINT_ERROR("EncodeUVT: failed to wrap UVT data.");
//        printf("%s","EncodeUVT: failed to wrap UVT data.");
//		goto cleanup;
//	}

	/////// Finalize
	//
	ptr = pUvtOut;
	remainder = *pUvtOutLength;

    ptr = AK_WriteTlvBytes(ptr, &remainder,  TAG_USERVERIFY_TOKEN, wrapped.pData, (ak_word_t)wrapped.length);

	if (NULL == ptr)
	{
//		PRINT_ERROR("EncodeUVT: failed to encode UVT.");
        printf("EncodeUVT: failed to encode UVT.");
		result = UAF_STATUS_ERR_BUFFER_SMALL;
		goto cleanup;
	}
	// Finalize with length
	*pUvtOutLength = (ak_word_t)(ptr - pUvtOut);

cleanup:
	memset(buffer, 0, sizeof(buffer));
	if (NULL != wrapped.pData) 
	{
		memset(wrapped.pData, 0, wrapped.length);
		free(wrapped.pData);
	}

	return result;
}

ak_result_t DecodeUVT(const ak_byte_t* pUvtIn, ak_word_t uvtInLength, ak_byte_t* pUvtOut, ak_word_t uvtOutLength, uvt_t* pUvt, cal_blob_t containerID, ak_byte_t uvtFormat)
{
	ak_result_t result = UAF_CMD_STATUS_OK;

	cal_blob_t wrapped = {0};
	cal_blob_t unwrapped = {0};

	const ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;

	//////// Verify input arguments
	//
	if (NULL == pUvtIn || NULL == pUvtOut || NULL == pUvt)
	{
//		PRINT_ERROR("DecodeUVT: invalid input argument.");
        printf("DecodeUVT: invalid input argument.");
		return UAF_STATUS_ERR_INVALID_PARAM;
	}
	
	//////// Decode UVT tag
	//
    
    wrapped.length = uvtInLength;
    wrapped.pData = (cal_byte_t*)pUvtIn;
    
	//////// Unwrap WrappedData
	//
	unwrapped.length = uvtOutLength;
	unwrapped.pData = pUvtOut;

//    result = UnwrapData(&wrapped, &unwrapped, &containerID, uvtFormat);
//    
//	if (UAF_CMD_STATUS_OK != result)
//	{
////		PRINT_ERROR("DecodeUVT: failed to unwrap UVT data.");
//        printf("DecodeUVT: failed to unwrap UVT data.");
//		return result;
//	}

	/* TODO: we have clear part in UVT, but it is not used at all. What is the purpose? */
	//////// Decode UVT members
	//
	result = DecodeUVTData(unwrapped.pData, (ak_word_t)unwrapped.length, pUvt);
	if (UAF_CMD_STATUS_OK != result) 
	{
//		PRINT_ERROR("DecodeUVT: failed to decode UVT data.");
       printf("DecodeUVT: failed to decode UVT data.");
		return result;
	}

	return result;
}

//TODO: review for FP specific processing
ak_result_t VerifyUVT(input_args_t* pInfo, ak_byte_t* aaid, ak_byte_t* pKHOut, ak_word_t* pKHOutLength, ak_byte_t* pUviOut, ak_word_t* pUviOutLength, cal_blob_t containerID, ak_byte_t uvtFormat)
{
	ak_result_t result = UAF_CMD_STATUS_OK;

	ak_byte_t buffer[MAX_UVT_SIZE] = {0};

	uvt_t uvt = {0};

	ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;

	//////// Verify input arguments
	//
	if (NULL == pInfo || NULL == aaid || NULL == pKHOut || NULL == pKHOutLength || NULL == pUviOut || NULL == pUviOutLength)
	{
//		PRINT_ERROR("VerifyUVT: invalid input argument.");
        printf("VerifyUVT: invalid input argument.");
		return UAF_STATUS_ERR_INVALID_PARAM;
	}

	//////// Verify input data
	//
	if (NULL == pInfo->userVerifyToken.pData || 0 == pInfo->userVerifyToken.length) 
	{
//		PRINT_ERROR("VerifyUVT: UVT is not present.");
        printf("VerifyUVT: UVT is not present.");

		return UAF_CMD_STATUS_ACCESS_DENIED;
	}

	if (NULL == pInfo->finalChallenge.pData || 0 == pInfo->finalChallenge.length) 
	{
//		PRINT_ERROR("VerifyUVT: challenge is not present.");
        printf("VerifyUVT: challenge is not present.");

		return UAF_CMD_STATUS_ACCESS_DENIED;
	}

	// Decode UVT
	result = DecodeUVT(pInfo->userVerifyToken.pData, (ak_word_t)pInfo->userVerifyToken.length, buffer, sizeof(buffer), &uvt, containerID, uvtFormat);
	if (UAF_CMD_STATUS_OK != result)
	{
//		PRINT_ERROR("VerifyUVT: failed to decode UVT.");
        printf("VerifyUVT: failed to decode UVT.");
		goto cleanup;
	}

	// Verify UVT data
//	if (0 != CompareBlobs(pInfo->finalChallenge.pData, (ak_word_t)pInfo->finalChallenge.length, 
//						  uvt.finalChallenge.pData, (ak_word_t)uvt.finalChallenge.length))
//	{
////		PRINT_ERROR("VerifyUVT: challenge does not match.");
//        printf("VerifyUVT: challenge does not match.");
//		result = UAF_CMD_STATUS_ACCESS_DENIED;
//		goto cleanup;
//	}

    // Check if aaid matches authenticator name
//	if (0 != CompareBlobs(aaid, AAID_SIZE,
//						  uvt.authrnName.pData, (ak_word_t)uvt.authrnName.length))
//	{
////		PRINT_ERROR("VerifyUVT: AAID does not match.");
//        printf("VerifyUVT: AAID does not match.");
//		result = UAF_CMD_STATUS_ACCESS_DENIED;
//		goto cleanup;
//	}

	if (NULL == uvt.userID.pData)
	{
//		PRINT_ERROR("VerifyUVT: userID is not present.");
         printf("VerifyUVT: userID is not present.");
		result = UAF_CMD_STATUS_ACCESS_DENIED;
		goto cleanup;
	}

    // MAX_ENROLLID_LENGTH in length
    if (MAX_ENROLLID_LENGTH != uvt.userID.length)
    {
//        PRINT_ERROR("VerifyUVT: invalid enrollID length. length entered is: %d", uvt.userID.length);
        printf("VerifyUVT: invalid enrollID length. length entered is: %d", uvt.userID.length);
        result = UAF_CMD_STATUS_ACCESS_DENIED;
        goto cleanup;
    }
    

	// TODO: verify timestamp

	// Finalize

    /* output data for kh(userID) */
	ptr = pKHOut;
	remainder = *pKHOutLength;
    ptr = AK_WriteBytes(ptr, &remainder, uvt.userID.pData, (ak_word_t)uvt.userID.length);
    if (NULL == ptr)
    {
//        PRINT_ERROR("VerifyUVT: output buffer is too small.");
        printf("VerifyUVT: output buffer is too small.");
        result = UAF_STATUS_ERR_BUFFER_SMALL;
        goto cleanup;
    }
    *pKHOutLength = (ak_word_t)(ptr - pKHOut);
    
    
    //optional RAW UVI data
    
    if (NULL == uvt.rawUVI.pData)
    {
//        PRINT_INFO("VerifyUVT: RAW User Verification Index is not present.");
         printf("VerifyUVT: RAW User Verification Index is not present.");
        *pUviOutLength = 0;
        goto cleanup;
    }

    /* Output data for UVI response */
    ptr = pUviOut;
    remainder = *pUviOutLength;
    
    ptr = AK_WriteBytes(ptr, &remainder, uvt.rawUVI.pData, (ak_word_t)uvt.rawUVI.length);
	if (NULL == ptr)
	{
//		PRINT_ERROR("VerifyUVT: output buffer is too small.");
        printf("VerifyUVT: output buffer is too small.");
		result = UAF_STATUS_ERR_BUFFER_SMALL;
		goto cleanup;
	}
    *pUviOutLength = (ak_word_t)(ptr - pUviOut);

cleanup:
	memset(buffer, 0, MAX_UVT_SIZE);

	return result;
}


ak_result_t EncodeUVTData(const uvt_t* pUvt, ak_byte_t* pDest, ak_word_t destLength, ak_word_t* outputDataLen)
{
	ak_byte_t* ptr = pDest;
	ak_word_t remainder = destLength;

	if (NULL == pUvt || NULL == pDest || NULL == outputDataLen)
	{
//		PRINT_ERROR("EncodeUVTData: invalid input argument.");
        printf("EncodeUVTData: invalid input argument.");
		return UAF_STATUS_ERR_INVALID_PARAM;
	}

	if (NULL != pUvt->authrnName.pData)
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_UVT_AUTHNR_NAME, pUvt->authrnName.pData, (ak_word_t)pUvt->authrnName.length);

	if (NULL != pUvt->userID.pData)
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_UVT_USER_ID, pUvt->userID.pData, (ak_word_t)pUvt->userID.length);

	if (NULL != pUvt->finalChallenge.pData)
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_UVT_FINAL_CHALLENGE, pUvt->finalChallenge.pData, (ak_word_t)pUvt->finalChallenge.length);

	if (NULL != pUvt->matchingScore.pData)
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_UVT_MATCHING_SCORE, pUvt->matchingScore.pData, (ak_word_t)pUvt->matchingScore.length);

	ptr = AK_WriteTlvDWord(ptr, &remainder, TAG_UVT_TIMESTAMP, pUvt->timestamp);

	if (NULL == ptr)
	{
//		PRINT_ERROR("EncodeUVTData: failed to encode ToBeWrappedData.");
        printf("EncodeUVTData: failed to encode ToBeWrappedData.");
		return UAF_STATUS_ERR_BUFFER_SMALL;
	}
	// Finalize
	*outputDataLen = (ak_word_t)(ptr - pDest);

	return UAF_CMD_STATUS_OK;
}

ak_result_t DecodeUVTData(const ak_byte_t* pSrc, ak_word_t srcLength, uvt_t* pUvt)
{
    ak_result_t result = UAF_CMD_STATUS_OK;
    
    const ak_byte_t* ptr = NULL;
    ak_word_t remainder = 0;
    
//    PRINT_TIME("DecodeUVTData");
    printf("DecodeUVTData");
    if (NULL == pUvt || NULL == pSrc)
    {
//        PRINT_ERROR("DecodeUVTData: invalid input argument.");
        printf("DecodeUVTData: invalid input argument.");
        return UAF_STATUS_ERR_INVALID_PARAM;
    }
    
    //// Decode
    //
    ptr = pSrc;
    remainder = srcLength;
    
    while (remainder > 0)
    {
        ak_tlv_t tlv = {0};
        
        ptr = AK_GetTlv(&tlv, ptr, &remainder);
        if (NULL == ptr)
        {
//            PRINT_ERROR("DecodeUVTData: incorrect buffer length.");
            printf("DecodeUVTData: incorrect buffer length.");
            return UAF_STATUS_ERR_INVALID_PARAM;
        }
        
        //TODO: verify data of obtained tags
        switch (tlv.tag)
        {
            case TAG_UVT_RESULT:
//                PRINT_INFO("DecodeUVTData: TAG_UVT_RESULT");
                printf("DecodeUVTData: TAG_UVT_RESULT");
                AK_GetByte(&pUvt->result, tlv.value, &tlv.length);
                break;
            case TAG_UVT_FINAL_CHALLENGE:
//                PRINT_INFO("DecodeUVTData: TAG_UVT_FINAL_CHALLENGE");
                printf("DecodeUVTData: TAG_UVT_FINAL_CHALLENGE");
                pUvt->finalChallenge.length = tlv.length;
                pUvt->finalChallenge.pData = tlv.value;
                break;
            case TAG_UVT_AUTHNR_NAME:
//                PRINT_INFO("DecodeUVTData: TAG_UVT_AUTHNR_NAME");
                printf("DecodeUVTData: TAG_UVT_AUTHNR_NAME");
                pUvt->authrnName.length = tlv.length;
                pUvt->authrnName.pData = tlv.value;
                break;
            case TAG_UVT_USER_ID:
//                PRINT_INFO("DecodeUVTData: TAG_UVT_USER_ID");
                printf("DecodeUVTData: TAG_UVT_USER_ID");
                pUvt->userID.length = tlv.length;
                pUvt->userID.pData = tlv.value;
                break;
            case TAG_UVT_TIMESTAMP:
//                PRINT_INFO("DecodeUVTData: TAG_UVT_TIMESTAMP");
                printf("DecodeUVTData: TAG_UVT_TIMESTAMP");
                AK_GetDWord(&pUvt->timestamp, tlv.value, &tlv.length);
                break;
            case AFI_UVI_RAW_USER_VERIFICATION_INDEX:
//                PRINT_INFO("DecodeUVTData: AFI_UVI_RAW_USER_VERIFICATION_INDEX");
                 printf("DecodeUVTData: AFI_UVI_RAW_USER_VERIFICATION_INDEX");
                pUvt->rawUVI.length = tlv.length;
                pUvt->rawUVI.pData = tlv.value;
                break;
            case TAG_UVT_MATCHING_SCORE:
//                PRINT_INFO("DecodeUVTData: TAG_UVI_MATCHING_SCORE");
                printf("DecodeUVTData: TAG_UVI_MATCHING_SCORE");
                pUvt->matchingScore.length = tlv.length;
                pUvt->matchingScore.pData = tlv.value;
                break;
            default:
//                PRINT_INFO("DecodeUVTData: unknown tag: 0x%X", tlv.tag);
                printf("DecodeUVTData: unknown tag: 0x%X", tlv.tag);
                break;
        }
    }
//    PRINT_TIME("DecodeUVTData finishing");
    printf("DecodeUVTData finishing");
    return result;
}
