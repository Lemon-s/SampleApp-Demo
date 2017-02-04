/* Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved. */

#include "akDefs.h"

#include "uaf_ak_defs.h"
#include "uaf_ak_tlv.h"
#include "uaf_ak_keyhandle.h"
#include "uaf_ak_util.h"
#include "gmrz_jv_ecc_cal_ext.h"
#include "gmrz_jv_util_func.h"
#include <stdlib.h>

/**
 * Creates and returns a wrapped key handle as specific in UAF AK design. Note that the KeyHandle
 * may have additional tags in it, if these are provided by pArgs.
 * 
 * @param pArgs pointer to the createKeyHandleArgs_t input
 * @param pKeyHandle pointer to the output byte array where pKeyHandle will be stored
 * @param pKeyHandleLength pointer to the size of the output
 */
ak_result_t CreateKeyHandle(createKeyHandleArgs_t *pArgs,
                            ak_byte_t  *pKeyHandle,
                            ak_word_t *pKeyHandleLength)
{
    
    NSLog(@"CreateKeyHandle\n");
  /* TODO: see comment on pSize in related header file: pSize needs to be checked on Input! */
	ak_word_t khSize = 0;
	ak_byte_t *pOut = pKeyHandle, *pEncKH = NULL;
	ak_dword_t nEncKHLen = 0;
	ak_word_t i;
//	ak_byte_t *pExportKeySize;
	ak_result_t res = UAF_CMD_STATUS_OK;
	ak_word_t remainder = 0;
//	ak_word_t tmpReminder;

//	cal_handle_t		hWrapKey = NULL;
	cal_blob_t			ExportKeyBLOB = {0};
	cal_key_params_t	KeyParams;
	cal_blob_t			InBLOB = {0}; 
	cal_blob_t			OutBLOB = {0};
	//added by hyl
        cal_blob_t              Hash = {0};

	/* TODO: should check gpCAL as well */
	if (NULL == pArgs || NULL == pKeyHandle || NULL == pKeyHandleLength )
		return UAF_STATUS_ERR_INVALID_PARAM;

	remainder = *pKeyHandleLength;

//	/* Get Wrap Key */
//	if(CAL_SUCCESS != gpCAL->CAL_GetKey(CAL_KEY_WRAP, NULL, &hWrapKey))
//	{
//		PRINT_ERROR("CreateKeyHandle: failed to get the wrap key.");
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//	}
//
//    	/* Determine the size of private key BLOB. */
	ExportKeyBLOB.length = 0;
	ExportKeyBLOB.pData = NULL;	

//	/* Export Key */
//	if(CAL_SUCCESS != gpCAL->CAL_ExportKey(hWrapKey, pArgs->hUauthPriv, NULL, NULL, &ExportKeyBLOB)) {
//		PRINT_ERROR("CreateKeyHandle: failed to get the size of the wrapped UAuthKey.");
//		return UAF_CMD_STATUS_ERR_UNKNOWN;
//    	}

	/* TODO: check output buffer length before write */

	/* Write the version of key container */
//	pOut = AK_WriteDWord(pOut, &remainder, pArgs->versionOfKeyContainer);
//    pOut = AK_WriteDWord(pOut, &remainder, 0x3E07);
    
    
//	pOut = AK_WriteBytes(pOut, &remainder, pArgs->pKHAccessToken->pData, (ak_word_t)pArgs->pKHAccessToken->length); /* Write KHAccessToken*/
    
  
    
    pOut = AK_WriteBytes(pOut, &remainder, (cal_byte_t *)pArgs->pKHAccessToken->pData, 32);
	//deleted by hyl
#if 0
	pExportKeySize = pOut;
	pOut = AK_WriteWord(pOut, &remainder, (ak_word_t)ExportKeyBLOB.length); /* Write size of the wrapped UAuth Key */

	if(remainder < ExportKeyBLOB.length || NULL == pOut)
	{
		res = UAF_STATUS_ERR_BUFFER_SMALL;
		goto clean;
	}
	ExportKeyBLOB.pData = pOut;
#endif
	ExportKeyBLOB.pData= malloc(ExportKeyBLOB.length+1);//added by hyl
    if (ExportKeyBLOB.pData == NULL) {
        NSLog(@"ExportKeyBLOB.pData malloc failed\n");
        goto clean;
    }
	memset(&KeyParams, 0, sizeof(KeyParams));

	/* Wrap the UAuth Key and write it to the encryption buffer */
//	if(CAL_SUCCESS != gpCAL->CAL_ExportKey(hWrapKey, pArgs->hUauthPriv, NULL, &KeyParams, &ExportKeyBLOB)) {
//		PRINT_ERROR("CreateKeyHandle: failed to wrapp UAuthKey.");
//		res = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto clean;
//    	}

	/* TODO: 
	   Check if KeyParams.KeyID is not empty (i.e. Uauth key is stored in secure storage), return KeyID from 
	   CreateKeyHandle function to be used in Register command response instead of the hash of key handle 
	   (see TAG_KEYID tag in TAG_UAFV1_REG_ASSERTION in UAF specification).
	   This will allow to remove a key from secure storage on Deregistration.
	*/
//deleted by hyl	
#if 0
	tmpReminder = sizeof(ak_word_t);
	AK_WriteWord(pExportKeySize, &tmpReminder, (ak_word_t)ExportKeyBLOB.length); /* Update with correct size */
	pOut += (ak_dword_t)ExportKeyBLOB.length;
	remainder -=(ak_word_t)ExportKeyBLOB.length;
#endif
	/* Write the authenticatorInput. For pin authenticator, it is enrollmentID */
        /* TODO: If the authenticatorInput.length is zero, why don't we bail out? */
	if (0 != pArgs->authenticatorInput.length) {
		pOut = AK_WriteBytes(pOut, &remainder, pArgs->authenticatorInput.pData, (ak_word_t)pArgs->authenticatorInput.length);
	}
	/* Write the username and its size */
	if (pArgs->isSecondFactor == 0) {
//		pOut = AK_WriteByte(pOut, &remainder, (ak_byte_t)pArgs->pUsername->length);
///*		*(pOut++) = (ak_byte_t)pArgs->pUsername->length;*/ /* Write size of username */
//		pOut = AK_WriteBytes(pOut, &remainder, pArgs->pUsername->pData, (ak_word_t)pArgs->pUsername->length); /* Write username */
        
        
        int usernamelength = strlen(pArgs->pUsername->pData);
        pOut = AK_WriteByte(pOut, &remainder, strlen(pArgs->pUsername->pData));
        /*		*(pOut++) = (ak_byte_t)pArgs->pUsername->length;*/ /* Write size of username */
        pOut = AK_WriteBytes(pOut, &remainder, pArgs->pUsername->pData, strlen(pArgs->pUsername->pData)); /* Write username */
	}
    
	/* Determine the size of the key handle to export (without extensions))*/
	khSize  = sizeof(pArgs->versionOfKeyContainer) /* size of version for key container */
			+ (ak_word_t)pArgs->pKHAccessToken->length /* KHAccessToken */
//deleted by hyl
//			+ sizeof(ak_word_t) /* Wrapped Uauth Key Size */
//			+ (ak_word_t)ExportKeyBLOB.length /* Wrapped Uauth Key */
			+ (ak_word_t)pArgs->authenticatorInput.length; /* authenticatorInput */
	if (pArgs->isSecondFactor == 0) {
		khSize += (ak_word_t)(USERNAME_SIZE + strlen(pArgs->pUsername->pData));
//        khSize += (ak_word_t)(USERNAME_SIZE + 0x0005);
	}
	
	/* Add the extensions */
	if (NULL != pArgs->pTLVs) {
		for (i = 0; i < pArgs->pTLVs->numTags; i++) {
			/* TODO: add check for NULL ptr pArgs->pTLVs->tlvs */
			pOut = AK_WriteTlvBytes(pOut, &remainder, pArgs->pTLVs->tlvs[i].tag, pArgs->pTLVs->tlvs[i].value, pArgs->pTLVs->tlvs[i].length); 
			khSize += pArgs->pTLVs->tlvs[i].length + TLV_TL_SIZE;
		}
	}

	/*Check if the provided buffer was enough for filling with all necessary fields.*/
	if (NULL == pOut )
	{
		res = UAF_STATUS_ERR_BUFFER_SMALL;
		goto clean;
	}

    /* TODO:
       1. nWrappedKHLen variable below used only to check the length. Do we need this check before wrap or after wrap?
       2. Padding length calculation in below line (if commonly used "byte padding" scheme is implied) is wrong.
          If khSize is multiple to encryption block size, nWrappedKHLen will be equal to khSize!
		  Meanwhile padding MUST be added in ANY case (even if the input length is multiple to encryption block size).
		  The correct size for padded encrypted length calculation is:
		  nWrappedKHLen = (khSize / CAL_MAX_BLOCK_SIZE + 1) * CAL_MAX_BLOCK_SIZE;
       3. CAL_WrapObject function handles padding and IV.
          The code that calls CAL_WrapObject shouldn't make assumption what padding is used (if used)
          in CAL_WrapObject (the function may use a stream cipher which doesn't require padding at all).
		  So the length returned by CAL_WrapObject (OutBLOB.length) is the only length the code should rely on.
		  NOTE: In TEE environment if CAL_WrapObject is called by setting OutBLOB.pData to NULL, wrapped data length
		  returned in OutBLOB.length is NOT exact size of wrapped data, but the maximal size.
    */
	/* TODO:
	   nWrappedKHLen is used with the old akcrypt API. We shall check OutBLOB.length. Line 130 to 136 shall be removed	
	*/

	/*FIXED Arsen*/

	InBLOB.pData = (cal_byte_t*)pKeyHandle;
	InBLOB.length = khSize;

	OutBLOB.pData = NULL;
	OutBLOB.length = 0;
    NSLog(@"  CreateKeyHandle   WrapData\n");
	if (CAL_SUCCESS != WrapData(&InBLOB, &OutBLOB)) {
		res = UAF_CMD_STATUS_ERR_UNKNOWN;
		goto clean;
	}
NSLog(@"  end CreateKeyHandle   WrapData\n");
	pEncKH = OutBLOB.pData;
	nEncKHLen = OutBLOB.length;

    /* TODO:
       1. If we have below check: if (nEncKHLen > MAX_KEYHANDLE_SIZE),
          do we need above check: if (nWrappedKHLen + TLV_TAG_AND_LENGTH_SIZE > MAX_KEYHANDLE_SIZE)?
       2. We probaly need to allocate the buffer for key handle dynamically, because it is difficult
	      to know MAX_KEY_HANDLE_SIZE beforehand. 
		  In TEE, in addition to IV, wrapping function may add some header.
	*/
	/* TODO:
	   2. We deliberately try to avoid dynamic allocation. If malloc is needed, we shall keep the same
	      pattern to let the caller allocate the memory. MAX_KEYHANDLE_SIZE shall be large enough to
	      accommodate different key sizes.
	*/

	/* Check if the wrapped key handle exceeds the maximum length, because wrapping
	 * will add an IV to the output. Actually, we shall get the expected length of
	 * wrapped data before we call wrap, but the ak_cryptWrapData misses this function
	 */
	/* TODO:
	   The following check shall be replaced by checking against the max input size "*pSize"
	*/

	/*FIXED */

	if (nEncKHLen > *pKeyHandleLength) {
		
        NSLog(@"\nCreateKeyHandle: wrapped keyhandle is too big.");
		res = UAF_STATUS_ERR_BUFFER_SMALL;
//		goto clean;
	}

	/* Wipe the clear-text data and copy the wrapped key handle to the output */
	memset(pKeyHandle, 0, nEncKHLen);
	
	remainder = *pKeyHandleLength;

	AK_WriteBytes(pKeyHandle, &remainder, pEncKH, (ak_word_t)nEncKHLen);
	*pKeyHandleLength = (ak_word_t)nEncKHLen;
	
	//added by hyl
        Hash.length=CAL_MAX_HASH_SIZE;
        Hash.pData=malloc(Hash.length+1);
    

    if (Hash.pData == NULL) {
        NSLog(@"Hash.pData malloc failed\n");
        goto clean;
    }
    
    NSLog(@"  CreateKeyHandle  KeyID  getHashBytes\n");
//    {
////        NSData *data = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytes:[NSData dataWithBytes:&OutBLOB  length:OutBLOB.length]];
//       uint8_t *datahash =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:OutBLOB.pData];
//        
//       memcpy(Hash.pData, datahash, strlen(datahash));
//    }
    NSLog(@"  end CreateKeyHandle KeyID  getHashBytes\n");
//    if (NULL == Hash.pData) {
//        //                PRINT_ERROR("Register: failed to get KeyID.");
//        NSLog(@"Register: failed to get KeyID®.");
//        res = UAF_CMD_STATUS_ERR_UNKNOWN;
//        goto clean;
//    }

	//ExportKeyBLOB.length =32;
//        HEX_DUMP("keyID in CreateKeyHandle : ", Hash.pData, Hash.length);
//  PRINT_INFO("Register: ExportKeyBLOB len=%d.",ExportKeyBLOB.length);
//        res = Store_Write(&Hash, (cal_byte_t *)AK_SFS_FILE, &ExportKeyBLOB);
//        if(res)
//        {   
////                PRINT_ERROR("Register: Store_Write failed.");
//            NSLog(@"Register: Store_Write failed.");
//                res=UAF_CMD_STATUS_ERR_UNKNOWN;
//                goto clean;
//        }
//    memset(pKeyHandle, 0, MAX_KEYHANDLE_SIZE);
//    memcpy(pKeyHandle, Hash.pData, 32);
	 NSLog(@" finish CreateKeyHandle\n");
clean:
	/* TODO:
	   Use nnl_memset_s for wiping sensitive buffer, since compiler will probably 
       optimize away regular nnl_memset call in release builds.
	*/
	if (UAF_CMD_STATUS_OK != res)
		memset(pKeyHandle, 0, MAX_KEYHANDLE_SIZE);
	if (NULL != pEncKH)
		free(pEncKH);
	//added by hyl
        if (NULL != Hash.pData)
                free(Hash.pData);
        if (NULL != ExportKeyBLOB.pData)
                free(ExportKeyBLOB.pData);
//        if (NULL != OutBLOB.pData)
//                free(ExportKeyBLOB.pData);

	return res;
}

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
/* TODO: obviously there is an expectation on the minimum size of usernamesin.  This expectation MUST be stated here and in the related header file!
   The meaning of usernamesin, usernamesOut and pKeyHandlesOut needs to be described.  This is completely unclear to me!
   nKeyHandlesOutNum should contain the number of available "slots" in pKeyHandlesOut on input! This size needs to be verified below.
*/

cal_handle_t UnwrapKeyHandle(createKeyHandleArgs_t *pArgs,
                             cal_blob_t *pTransactionContent,
                             cal_blob_t *pKeyHandlesIn,
							 ak_byte_t nKeyHandlesInNum,
							 ak_byte_t *usernamesin,
							 cal_blob_t *usernamesOut,
							 cal_blob_t **pKeyHandlesOut,
							 ak_byte_t *nKeyHandlesOutNum,
                             ak_tlvs_t *pTags)
{
        /* TODO: Don't we need to validate the input params? */
	cal_handle_t hUAuthKey = NULL;
	ak_byte_t pWrappedKey[MAX_WRAPPED_KEY_LENGTH];
	ak_word_t nWrapKeyLen = 0;
	ak_byte_t nUsernameLen = 0;
	ak_byte_t *pDecKH = NULL;
	ak_dword_t nDecKHSize = 0;
	ak_word_t remainingLen = 0;
	//added by hyl
	ak_word_t res = 0;
	ak_byte_t i = 0;
	const ak_byte_t *pTemp = NULL;
	const ak_byte_t *pUsernamePos = NULL;

	cal_handle_t	hWrapKey = NULL;
	cal_blob_t		ImportKeyBLOB = {0};
	cal_blob_t		InBLOB = {0}; 
	cal_blob_t		OutBLOB = {0};
	//added by hyl
        cal_blob_t              wrappedkey = {0};
        cal_blob_t              Hash = {0};

	cal_key_params_t KeyParams;

	/* TODO: should check gpCAL, usernamesin as well */
	if (NULL == pArgs || NULL == pKeyHandlesIn ||
		NULL == usernamesin || NULL == usernamesOut || NULL == pKeyHandlesOut
		|| NULL == nKeyHandlesOutNum || NULL == pTags)
		return NULL;
	
	//Check if the output buffer is big enough for storing key handles.
	if (*nKeyHandlesOutNum < nKeyHandlesInNum)
	{
		*nKeyHandlesOutNum = 0;
		return NULL;
	}

	*nKeyHandlesOutNum = 0;

	/* For second factor, always use the first key handle */
	if (pArgs->isSecondFactor != 0) {
		nKeyHandlesInNum = 1;
	}

	/* Get Wrap Key */
//	if(CAL_SUCCESS != gpCAL->CAL_GetKey(CAL_KEY_WRAP, NULL, &hWrapKey))
//	{
//		PRINT_ERROR("CreateKeyHandle: failed to get the wrap key.");
//		*nKeyHandlesOutNum = 0;
//		return NULL;
//	}

	/* Set transaction text */
	memset(&KeyParams, 0, sizeof(KeyParams));
	KeyParams.Params.pData = NULL;
	KeyParams.Params.length = 0;

	if(pTransactionContent) {
		KeyParams.Params.pData = pTransactionContent->pData;
		KeyParams.Params.length = pTransactionContent->length;
	}
    
    
    
    
//    NSMutableString *hexString = [NSMutableString string];
//    for (int i=0; i < 9; i++)
//    {
//        [hexString appendFormat:@"%c", pArgs->];
//    }
    
    

    
    
    
	/* Unwrap the key handles*/
	for (i = 0; i < nKeyHandlesInNum; i++) {
    
		InBLOB.pData = (cal_byte_t*)pKeyHandlesIn[i].pData;
		InBLOB.length = pKeyHandlesIn[i].length;

		OutBLOB.pData = NULL;
		OutBLOB.length = 0;
		
		if (CAL_SUCCESS != UnwrapData(&InBLOB, &OutBLOB, 0, UVT_FORMAT_LOCAL)) {
//			PRINT_ERROR("UnwrapKeyHandle: UnwrapData failed.");
            NSLog(@"UnwrapKeyHandle: UnwrapData failed.");
			continue;
		}

		pDecKH = OutBLOB.pData;
		nDecKHSize = OutBLOB.length;
		pTemp = pDecKH;
		remainingLen = (ak_word_t)nDecKHSize;

		/* TODO: We also always expecting the version of key container (add KC version size).
		   Also use pArgs->pKHAccessToken->length instead of CAL_MAX_HASH_SIZE 
		*/
		/* Check the size of raw keyhandle: at least KHAccessToken + UAuthKey size */
		if (nDecKHSize < (pArgs->pKHAccessToken->length + sizeof(ak_word_t) + sizeof(pArgs->versionOfKeyContainer))) {
//			PRINT_ERROR("UnwrapKeyHandle: incorrect raw keyhandle length.");
            NSLog(@"UnwrapKeyHandle: incorrect raw keyhandle length. : %d", nDecKHSize);
			goto clearKH;
		}
		
		///* Verify version of key container */
		if (remainingLen < sizeof(pArgs->versionOfKeyContainer) ) {
//			PRINT_ERROR("UnwrapKeyHandle: incorrect keyhandle length.");
            NSLog(@"UnwrapKeyHandle: incorrect keyhandle length.");
			goto clearKH;
		}
//		if (0 != memcmp(pTemp, &pArgs->versionOfKeyContainer, sizeof(pArgs->versionOfKeyContainer))) {
////			PRINT_ERROR("UnwrapKeyHandle: version of key container doesn't match.");
//            NSLog(@"UnwrapKeyHandle: version of key container doesn't match.");
//			goto clearKH;
//		}
//		pTemp += sizeof(pArgs->versionOfKeyContainer);
//		remainingLen -= sizeof(pArgs->versionOfKeyContainer);

		/* TODO: 
		   1. Check we have enough space in pTemp (remainingLen) before memory comparison.
		   2. Instead of CAL_MAX_HASH_SIZE, pArgs->pKHAccessToken->length should be used. 
		*/
		/*Arsen: we already checked that nDecKHSize < (pArgs->pKHAccessToken->length + sizeof(ak_word_t) + sizeof(pArgs->versionOfKeyContainer)).*/

		/* Check if KHAccessToken matches */
//		if (0 != memcmp(pTemp, pArgs->pKHAccessToken->pData, pArgs->pKHAccessToken->length)) {
////			PRINT_ERROR("UnwrapKeyHandle: access key does not match.");
//            NSLog(@"UnwrapKeyHandle: access key does not match.");
//			goto clearKH;
//		}
		/* TODO: Instead of CAL_MAX_HASH_SIZE, pArgs->pKHAccessToken->length should be used */
		pTemp += pArgs->pKHAccessToken->length;
		remainingLen -=  (ak_word_t)pArgs->pKHAccessToken->length;

		/* Get wrapped UAuth key size and pointer to the wrapped key */
//deleted by hyl
#if 0
		pTemp = AK_GetWord(&nWrapKeyLen, pTemp, &remainingLen);
		if (nWrapKeyLen > MAX_WRAPPED_KEY_LENGTH || remainingLen < nWrapKeyLen) {
			PRINT_ERROR("UnwrapKeyHandle: wrapped key's size is too large.");
			goto clearKH;
		}
		nnl_memcpy(pWrappedKey, pTemp, nWrapKeyLen);
		pTemp += nWrapKeyLen;
		remainingLen -= nWrapKeyLen;
#endif
		/* Verify authenticatorInput (enrollmentID) */
		if (0 != pArgs->authenticatorInput.length && NULL != pArgs->authenticatorInput.pData) {
//			PRINT_INFO("UnwrapKeyHandle: authenticatorInput present.");
            NSLog(@"UnwrapKeyHandle: authenticatorInput present.");
            if (remainingLen < pArgs->authenticatorInput.length) {
//                PRINT_ERROR("\nUnwrapKeyHandle: incorrect authenticatorInput length.");
                  NSLog(@"\nUnwrapKeyHandle: incorrect authenticatorInput length.");
                goto clearKH;
            }
            if (0 != memcmp(pTemp, pArgs->authenticatorInput.pData, pArgs->authenticatorInput.length)) {
//                PRINT_ERROR("UnwrapKeyHandle: authenticatorInput data doesn't match.");
                 NSLog(@"UnwrapKeyHandle: authenticatorInput data doesn't match.");
                goto clearKH;
            }
            pTemp += pArgs->authenticatorInput.length;
            remainingLen -= (ak_word_t)pArgs->authenticatorInput.length;
        }

		/* If not second factore, check the remaining size of raw keyhandle: at least username size */
		if (pArgs->isSecondFactor == 0) {
			if (remainingLen < sizeof(ak_byte_t)) {
//				PRINT_ERROR("\nUnwrapKeyHandle: incorrect raw keyhandle length.");
                NSLog(@"\nUnwrapKeyHandle: incorrect raw keyhandle length.");
				goto clearKH;
			}
			nUsernameLen = *(pTemp++);
			remainingLen -= sizeof(ak_byte_t);

			/* Copy the decrypted username to an output buffer */
			if (nUsernameLen > MAX_USERNAME_SIZE || remainingLen < nUsernameLen) {
//				PRINT_ERROR("\nUnwrapKeyHandle: incorrect keyhandle/username length.");
                NSLog(@"\nUnwrapKeyHandle: incorrect keyhandle/username length.");
				goto clearKH;
			}
			pUsernamePos = pTemp; // mark the location of the unwrapped username and copy it later
			pTemp += nUsernameLen;
			AK_WriteBytes(usernamesin, &remainingLen, pUsernamePos, (ak_word_t)nUsernameLen);
			usernamesOut->length = nUsernameLen;
			(usernamesOut++)->pData = usernamesin;
			usernamesin += nUsernameLen;

		}

		pTags->numTags = 0;
		/* Extract extensions from key handle */
		while (remainingLen >= TLV_TL_SIZE) {

			pTemp = AK_GetWord(&pTags->tlvs[pTags->numTags].tag, pTemp, &remainingLen);
			pTemp = AK_GetWord(&pTags->tlvs[pTags->numTags].length, pTemp, &remainingLen);

			/* If the Tag we get is 0, it means it is just padding data for encryption */
			if (0 == pTags->tlvs[pTags->numTags].tag)
				break;
			if (remainingLen < pTags->tlvs[pTags->numTags].length) {
				//PRINT_ERROR("\nUnwrapKeyHandle: incorrect raw keyhandle length.");
                NSLog(@"\nUnwrapKeyHandle: incorrect raw keyhandle length.");
				goto clearKH;
			}
			pTags->tlvs[pTags->numTags].value = (ak_byte_t*) malloc(pTags->tlvs[pTags->numTags].length);
			if (NULL == pTags->tlvs[pTags->numTags].value)
			{
//				PRINT_ERROR("\nUnwrapKeyHandle: incorrect raw keyhandle length.");
                 NSLog(@"\nUnwrapKeyHandle: incorrect raw keyhandle length.");
				goto clearKH;
			}

			pTemp = AK_GetBytes(pTags->tlvs[pTags->numTags].value, pTags->tlvs[pTags->numTags].length, pTemp, &remainingLen);

			pTags->numTags++;
		}
    
		/*TODO: move lines 404-407 to after line 386. This shall happen only for first factor authenticator */
		/*FIXED Arsen*/

		(*nKeyHandlesOutNum)++;
		*pKeyHandlesOut++ = &pKeyHandlesIn[i];
clearKH:
		/* TODO: 
		   Use nnl_memset_s for wiping sensitive buffer, since compiler will probably 
		   optimize away regular nnl_memset call in release builds.
		*/
		memset(pDecKH, 0, nDecKHSize);
		free(pDecKH);
	}

	/* If only one key handle remains, unwrap the wrapped UAuth key */
	if (*nKeyHandlesOutNum == 1) {
	
		//added by hyl
        Hash.length=CAL_MAX_HASH_SIZE;
        Hash.pData=malloc(Hash.length+1);


        uint8_t digestData[256];
        size_t digestLength = sizeof(digestData);
        memcpy(digestData, InBLOB.pData, InBLOB.length);
        uint8_t *hash_temp =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:digestData length:InBLOB.length];
        memcpy(Hash.pData, hash_temp, Hash.length);
        
        if (NULL != hash_temp) {
            free(hash_temp);
            hash_temp =NULL;
            
        }
        
       if (!Hash.pData)
        {
                NSLog(@"sign: failed to get KeyID.");
                *nKeyHandlesOutNum = 0;
                hUAuthKey = NULL;
        }
        else
        {
                wrappedkey.length=MAX_WRAPPED_KEY_LENGTH;
                wrappedkey.pData=pWrappedKey;
//                        res=Store_Read(&Hash, (cal_byte_t *)AK_SFS_FILE, &wrappedkey);
               res = 0;
                if(res)
                {
//                                PRINT_ERROR("sign: failed to get wrappedkey.");
                        NSLog(@"sign: failed to get wrappedkey.");
                        *nKeyHandlesOutNum = 0;
                        hUAuthKey = NULL;
                }
                else
                {
        //            HEX_DUMP("wrappedkey after Store_Read", wrappedkey.pData, wrappedkey.length);
                    ImportKeyBLOB.length = nWrapKeyLen;
                    ImportKeyBLOB.pData = pWrappedKey;
                   
                    if (CAL_SUCCESS )
                    {
            //					PRINT_ERROR("UnwrapKeyHandle: failed to unwrap the UAuth key.");
                        NSLog(@"UnwrapKeyHandle: failed to unwrap the UAuth key.");
                        hUAuthKey = NULL;
                        *nKeyHandlesOutNum = 0;
                    }
                }
            }

	}

	memset(pWrappedKey, 0, MAX_WRAPPED_KEY_LENGTH);
	//added by hyl
    if (NULL != Hash.pData)
            free(Hash.pData);
    
    

	return hUAuthKey;
}



