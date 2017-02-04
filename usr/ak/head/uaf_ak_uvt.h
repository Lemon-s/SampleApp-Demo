/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:			uaf_ak_uvt.h
 ***************************************************************************************
 * Version:			0.1
 */
#ifndef __UAFAK_UVT_H__
#define __UAFAK_UVT_H__

#include "uaf_ak_tlv.h"

/**
* User Verification Token (UVT).
* The TLV structure for UVT looks as following:
*     TAG_USERVERIFY_TOKEN
*         TAG_UVT_CLEAR_DATA
*             ...
*         TAG_UVT_WRAPPED_DATA
*             ...
* where,
* all members of uvt_t must be protected by wrapping key and exposed under the TAG_UVT_WRAPPED_DATA,
* and the first four members of uvt_t must be duplicated under the TAG_UVT_CLEAR_DATA of UVT.
* 
*/

/* TODO: Consider to rearrange the order of members in the structure, 
                 so it will hold less space in memory (e.g. move result and timestamp to the end).
*/
typedef struct uvt_t
{
	cal_blob_t	authrnName;
	ak_byte_t	result;
	cal_blob_t	userID;
    cal_blob_t	rawUVI;

	cal_blob_t	finalChallenge;
	ak_dword_t  timestamp;
	cal_blob_t	matchingScore;
} uvt_t;


/**
 * Performs a full encoding of the User Verification Token (UVT) data into the specified output buffer
 * and returns an encoded data length through a provided output parameter pUvtOutLength.
 *
 * @param pUvt			the UVT data to be encoded			
 * @param pUvtOut		the output buffer
 * @param pUvtOutLength	the output buffer length; on output - the resulting data length
 */
ak_result_t EncodeUVT(const uvt_t* pUvt, ak_byte_t* pUvtOut, ak_word_t* pUvtOutLength);

/**
 * Performs a full decoding of the User Verification Token (UVT) data.
 *
 * @param pUvtIn		the input buffer pointing to the Value of TAG_USERVERIFY_TOKEN Tag			
 * @param uvtInLength	the Length of the Value of TAG_USERVERIFY_TOKEN Tag
 * @param pUvtOut		the output buffer for unwrapped data			
 * @param uvtOutLength	the output buffer length
 * @param pUvt			the resulting UVT data
 */
ak_result_t DecodeUVT(const ak_byte_t* pUvtIn, ak_word_t uvtInLength, ak_byte_t* pUvtOut, ak_word_t uvtOutLength, uvt_t* pUvt, cal_blob_t containerID, ak_byte_t uvtFormat);

/*
 * Verifies the UVT during registration or authentication and provides EnrollID in output arguments.
 *
 * @param pInfo			the input arguments
 * @param authCtx		the authenticator context
 * @param pOut			the output buffer
 * @param pOutLength	the output buffer length; on output - the resulting data length
 */
ak_result_t VerifyUVT(input_args_t* pInfo, ak_byte_t* aaid, ak_byte_t* pKHOut, ak_word_t* pKHOutLength, ak_byte_t* pUVIOut, ak_word_t* pUVIOutLength, cal_blob_t containerID, ak_byte_t uvtFormat);

#endif /* __UAFAK_UVT_H__ */

