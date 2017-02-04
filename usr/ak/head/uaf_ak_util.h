/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:			uaf_ak_util.h
 ***************************************************************************************
 * Version:			0.1
 */
#ifndef __UAFAK_UTIL_H__
#define __UAFAK_UTIL_H__


/**
 * Performs wrapping/unwrapping of specified input data with wrapping key (CAL_KEY_WRAP).
 * 
 * Provides convenient shortcut for sequence of CAL_GetKey-CAL_(Un)WrapObject-CAL_(Un)WrapObject calls.
 * Caller should allocate a buffer large enough to receive an output data,
 * otherwise, pOut->pData must be set to NULL.
 * In the later case the function will allocate a buffer of necessary size, 
 * and caller is responsible to free it with nnl_free function.
 *
 * TODO: Move these function to separate utils file, 
 *       and use them to improve code readability.
 *
 * @param pIn	input data blob
 * @param pOut	output data blob
 *
 */
ak_result_t WrapData(const cal_blob_t* pIn, cal_blob_t* pOut);
ak_result_t UnwrapData(const cal_blob_t* pIn, cal_blob_t* pOut, cal_blob_t* containerID, ak_byte_t uvtFormat);
ak_result_t GenerateUviTlv(const ak_byte_t* keyID, ak_byte_t keyIDLen, ak_byte_t* rawUvi, ak_byte_t rawUviLen, ak_byte_t* outBuffer, ak_byte_t outBufferLen);

int CompareBlobs(const ak_byte_t* buffer1, ak_word_t length1, const ak_byte_t* buffer2, ak_word_t length2);

#endif /* __UAFAK_UTIL_H__ */

