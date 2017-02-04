/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:			uaf_ak_keyhandle.h
 ***************************************************************************************
 * Version:			0.1
 */
#ifndef __UAFAK_KEYHANDLE_H__
#define __UAFAK_KEYHANDLE_H__

#include "uaf_ak_tlv.h"

/* TODO: 
   1. #pragma pack (1 byte packing) should be removed to avoid unaligned access.
	  The code that uses the structures should be checked and corrected, since it may
	  rely on assumption that the structures are 1 byte packed.
   2. Consider to rearrange the order of members for structures to hold less space in memory.
*/
//#pragma pack(push,1)

#define KEY_CONTAINER_VERSION	1

/**
 * Arguments for CreateKeyHandle function. Note that caller may specify the number 
 * of TLVs to include into KeyHandle.
 */
typedef struct createKeyHandleArgs_t
{
    cal_blob_t   *pKHAccessToken;
    cal_handle_t hUauthPriv;
	cal_blob_t   *pUsername;
	cal_blob_t   authenticatorInput;
	ak_byte_t isSecondFactor;
	ak_dword_t   versionOfKeyContainer;
    ak_tlvs_t       *pTLVs;
} createKeyHandleArgs_t;
//#pragma pack(pop) TODO:remove commented pragma macro with review comment.

/** TODO: HIGHLY RECOMMENDED: pSize SHOULD be set to available length input! 
    This *pSize on input needs to be verified in each of the functions below
*/
/**
 * Creates and returns a wrapped key handle as specific in UAF AK design. Note that the KeyHandle
 * may have additional tags in it, if these are provided by pArgs.
 * 
 * @param pArgs[IN] pointer to the createKeyHandleArgs_t input
 * @param pKeyHandle[IN/OUT] pointer to the output buffer where pKeyHandle must be stored
 * @param pKeyHandleLength[OUT] pointer to the size of the output
 *
 * @return UAF_STATUS_ERR_UNKNOWN if failed to wrap the UAuth key or the key handle
 *		   UAF_STATUS_ERR_BUFFER_SMALL if the key handle if too big
 *		   UAF_STATUS_OK if suceeded
 */
ak_result_t CreateKeyHandle(createKeyHandleArgs_t *pArgs,
                            ak_byte_t *pKeyHandle,
                            ak_word_t *pKeyHandleLength); /* TODO: why pSize and not pKeyHandleLength as in uaf_ak_defs.h? */

/**
 * Unwraps given wrapped KeyHandle and returns in clear. Note that TAGS are returned separately.
 * 
 * @param pArgs[IN] pointer to the createKeyHandleArgs_t input
 * @param pKeyHandlesIn[IN] pointer to the start of the array that contains the wrapped keyhandle
 * @param nKeyHandlesInNum[IN] number of wrapped keyhandles
 * @param usernamesin[IN/OUT] pointer to the raw buffer where unwrapped usernames are going to be stored. 
 This argument was added for avoiding memory allocation for blobs in usernamesOut.
 The minimum size of buffer should be MAX_USERNAME_SIZE * MAX_KEYHANDLE_NUM
 * @param usernamesOut[OUT] pointer to the start of the array that stores the username blobs. 
 Each blob in this array will point to the memory in usernamesin buffer. 
 The minimum array size should be MAX_KEYHANDLE_NUM
 * @param pKeyHandlesOut[OUT] if more than one key handles are found, it stores the address of the pointers
 *							  that point to the wrapped key handles that is going to be returned
 * @param nKeyHandlesOutNum[IN/OUT] Initially this pointer will show the number of available slots in pKeyHandlesOut.
 As output will point to the number of matching key handles.
 * @param pTags[OUT] pointer to the unwrapped extensions
 *
 * @return keyhandle that contains the UAuth key if only one key handle is found or null otherwise
 */
cal_handle_t UnwrapKeyHandle(createKeyHandleArgs_t *pArgs,
                             cal_blob_t *pTransactionContent,
                             cal_blob_t *pKeyHandlesIn,
							 ak_byte_t nKeyHandlesInNum,
							 ak_byte_t *usernamesin,
							 cal_blob_t *usernamesOut,
							 cal_blob_t **pKeyHandlesOut,
							 ak_byte_t *nKeyHandlesOutNum,
                             ak_tlvs_t *pTags);

#endif /* __UAFAK_KEYHANDLE_H__ */

