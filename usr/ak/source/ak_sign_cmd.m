/* Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved. */

#include "akDefs.h"
#include "uaf_ak_tlv.h"
#include "uaf_ak_defs.h"
#include "uaf_ak_keyhandle.h"
#include "uaf_ak_authenticator.h"
#include "uaf_ak_keyhandle.h"
#include "uaf_ak_token_verifier.h"
#include "uaf_ak_util.h"
#include "uaf_ak_uvt.h"
#import "gmrz_jv_ecc_cal_ext.h"

#import "gmrz_jv_asm_db.h"

#import "gmrz_jv_asm_json_parse.h"
/**
 * Creates a UAFV1 Signing Response using provided arguments.
 *
 * @param pArgs pointer to a signResponseArgs_t structure to be exported
 * @param pUAFV1RegResponse pointer to the output sign response
 * @param pRegResponseSize pointer to where the size of the response to be stored
 *
 * @return UAF_STATUS_ERR_UNKNOWN if failed to create signature or failed to create hash
 *		   UAF_STATUS_OK if succeeded
 */
ak_result_t CreateUAFV1SignResponse(signResponseArgs_t* pArgs /*IN*/,
                                    ak_byte_t *username,
                                   ak_byte_t *pUAFV1SignResponse /*OUT*/,
                                    ak_word_t *pUAFV1SignResponseLength /*OUT*/,
                                    cal_blob_t *additionalSignedData,
                                    ak_byte_t signedDataLen,
                                    cal_blob_t *additionalUnsignedData,
                                    ak_byte_t unsignedDataLen,
                                    NSInteger method

);

/** 
 * Process sign request and output sign response
 *
 * @param pAKInfo [IN] pointer to a structure containing internal AK info
 * @param pInputArgs [IN] pointer to a structure containing the parsed AK request
 * @param pResponse [IN/OUT] A buffer where the response must be written. This buffer must be allocated by the caller.
 * @param pResponseLength [OUT] Length of the response
 */
ak_result_t Sign(authenticatorInfo_t *pAKInfo,
                 ak_dword_t  pAKInfoCount,
                 input_args_t *pInputArgs,
				 ak_byte_t *pResponse, 
				 ak_word_t *pResponseLength,NSInteger method)
 {
    authenticator_t* pAuthenticator = NULL;
    authenticatorInfo_t *pAuthnrInfo = NULL;
	signResponseArgs_t signRespArgs = {0};
    cal_handle_t hUauthKey = NULL;
    createKeyHandleArgs_t createKHArgs;
	ak_byte_t authnrVerifyOut[MAX_KEYHANLDE_EXT_SIZE];
	ak_word_t authnrVerifyOutSize = (ak_word_t)sizeof(authnrVerifyOut);
    ak_byte_t rawUviOut[CAL_MAX_HASH_SIZE];
    ak_word_t rawUviOutSize = sizeof(rawUviOut);
    ak_byte_t signedUVI_TLV[TLV_TL_SIZE + CAL_MAX_HASH_SIZE];
	ak_byte_t authnrNonce[MAX_CHALLENGE_SIZE ];
	ak_byte_t keyID[CAL_MAX_HASH_SIZE ];
	cal_blob_t DataBLOB = { 0 };
	cal_blob_t Hash = { 0 };
	cal_blob_t additionalSignedDataArray[1] = {0};
	ak_byte_t additionalSignedDataArraySize = 0;
	ak_byte_t usernames[MAX_USERNAME_SIZE * MAX_KEYHANDLE_NUM];
	ak_tlvs_t pKHTags = {0};
    ak_result_t res = UAF_CMD_STATUS_OK;

	ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;

	ak_word_t tmpLength = 0;

//     PRINT_TIME("Sign");
     NSLog(@"Sign");
	if (NULL == pAKInfo || NULL == pInputArgs || NULL == pResponse || NULL == pResponseLength)
		return UAF_STATUS_ERR_INVALID_PARAM;

	if (RESPONSE_HEADER_SIZE > *pResponseLength)
	{
//		PRINT_ERROR("GetInfo: response buffer[%u] is too small.", *pResponseLength);
        NSLog(@"GetInfo: response buffer[%u] is too small.", *pResponseLength);
		return UAF_STATUS_ERR_BUFFER_SMALL;
	}

     
     
	/* Check the authenticator ID */
	if (pInputArgs->authenticatorID >= pAKInfoCount)
	{
//		PRINT_ERROR("Sign: invalid authenticator ID.");
        NSLog(@"Sign: invalid authenticator ID.");
		res = UAF_STATUS_ERR_INVALID_PARAM;
		goto clean;
	}

	/* Get authenticator and authenticator info */
//	pAuthenticator = &pAKInfo->authenticators.items[pInputArgs->authenticatorID];
//    if (UAF_CMD_STATUS_OK != 
//		pAuthenticator->GetInfo(pInputArgs->authenticatorID, &pAuthnrInfo))
     pAuthnrInfo = pAKInfo;
     
     if (NULL == pAuthnrInfo)
	{
//		PRINT_ERROR("Sign: fail to get authenticator information.");
        NSLog(@"Sign: fail to get authenticator information.");
        res = UAF_CMD_STATUS_ERR_UNKNOWN;
		goto clean;
    }

//	if (UAF_CMD_STATUS_OK !=
//        VerifyUVT(pInputArgs, &pAuthnrInfo->aaid[0], authnrVerifyOut, &authnrVerifyOutSize, rawUviOut, &rawUviOutSize, pAuthnrInfo->containerID, pAuthnrInfo->UVTFormat))
//	{
////		PRINT_ERROR("\nSign: VerifyUVT failed.");
//        NSLog(@"\nSign: VerifyUVT failed.");
//		res = UAF_CMD_STATUS_ACCESS_DENIED;
//		goto clean;
//	}

     
     pInputArgs->finalChallenge.pData = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:pInputArgs->finalChallenge.pData length:strlen(pInputArgs->finalChallenge.pData)];
     pInputArgs->finalChallenge.length = 32;
	/* Mix server challenge to entropy pool */
	if (UAF_CMD_STATUS_OK != MixServerChallenge(pInputArgs->finalChallenge)) 
	{
//	    PRINT_ERROR("\nSign: failed to mix the server challenge.");
        NSLog(@"\nSign: failed to mix the server challenge.");
		res = UAF_CMD_STATUS_ERR_UNKNOWN;
		goto clean;
	}

	/* Create raw keyhandles */
	createKHArgs.pKHAccessToken = &pInputArgs->khAccessToken;
	createKHArgs.hUauthPriv = NULL;
	createKHArgs.isSecondFactor = (pAuthnrInfo->metadata.authenticatorType & UAF_TYPE_2NDF_AUTHNR);
//	createKHArgs.authenticatorInput.length = authnrVerifyOutSize;
//	createKHArgs.authenticatorInput.pData = authnrVerifyOut;
     createKHArgs.authenticatorInput.length = 0;
     createKHArgs.authenticatorInput.pData = nil;
    createKHArgs.pTLVs = NULL; //&pInputArgs->extensionTags;

	/*Add version of key container*/
	createKHArgs.versionOfKeyContainer = KEY_CONTAINER_VERSION;
    
	
	/* Unwrap the keyhandles */
	signRespArgs.keyHandleNum = MAX_KEYHANDLE_NUM;
     
     
     
     
     
	hUauthKey= UnwrapKeyHandle(&createKHArgs, &pInputArgs->transactionContent,
							&pInputArgs->keyHandles[0], pInputArgs->keyHandlesNum,
							usernames, &signRespArgs.usernames[0],
							&signRespArgs.pKeyHandles[0], &signRespArgs.keyHandleNum,
							&pKHTags);


	/* Fail if no matching keyhandles are found */
	if (0 == signRespArgs.keyHandleNum) 
	{
		//NSLog(@"\nSign: fail to unwrap the key handle.");
		res =  UAF_CMD_STATUS_ACCESS_DENIED;
		goto clean;
	}
	else
	/* If only one matching keyhandle is found or the authenticator is 2nd factor only */
	if (1 == signRespArgs.keyHandleNum) 
	{
		/* Verify transaction confirmation token if present */
//		if (UAF_CMD_STATUS_OK != VerifyTCT(pInputArgs)) 
//		{
////			PRINT_ERROR("Sign: fail to verify transaction confirmation token.");
//            NSLog(@"Sign: fail to verify transaction confirmation token.");
//
//			res = UAF_CMD_STATUS_ACCESS_DENIED;
//			goto clean;
//		}

		/* Check gpCAL */
//		if(NULL == gpCAL)
//		{
////			PRINT_ERROR("Register: gpCAL is NULL.");
//            NSLog(@"Register: gpCAL is NULL.");
//			res = UAF_CMD_STATUS_ERR_UNKNOWN;
//			goto clean;
//		}

		/* Generate authenticator nonce */
		DataBLOB.pData = (cal_byte_t*)authnrNonce;
		DataBLOB.length = (cal_dword_t)sizeof(authnrNonce);
        
//        pInputArgs->transactionContent.pData =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:pInputArgs->transactionContent.pData length:pInputArgs->transactionContent.length];
//        pInputArgs->transactionContent.length = 32;
//        
        int randnum_temp = [gmrz_jv_asm_json_parse getRandomNumber:1000 to:9999];
        unsigned char randnum[3] = "\0";
        randnum[0] = 65344 / 256;
        randnum[1] = 65344 % 256;
    
        
        uint8_t * test_datablock = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:randnum length:2];
        memcpy(DataBLOB.pData, test_datablock, DataBLOB.length);
		if ( 0 == strlen(DataBLOB.pData))
		{
//			PRINT_ERROR("\nSign: fail to generate authenticator nonce.");
            NSLog(@"\nSign: fail to generate authenticator nonce.");
			res = UAF_CMD_STATUS_ERR_UNKNOWN;
			goto clean;
		}

        
        if(test_datablock)
        {
            free(test_datablock);
        }
		/* Obtain KeyID */
		DataBLOB.pData = (cal_byte_t*)signRespArgs.pKeyHandles[0]->pData;
		DataBLOB.length = (cal_dword_t)signRespArgs.pKeyHandles[0]->length;

//		HEX_DUMP("keyHandle : ", DataBLOB.pData, DataBLOB.length);
		Hash.pData = (cal_byte_t*)keyID;
		Hash.length = (cal_dword_t)sizeof(keyID);
        
        
        
        uint8_t *hashcopy =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:DataBLOB.pData length:DataBLOB.length];
        
        memcpy(Hash.pData, hashcopy, Hash.length);
        

        if(NULL != hashcopy)
        {
            free(hashcopy);
            hashcopy = NULL;
        }
//		if (CAL_SUCCESS != gpCAL->CAL_HashData(&DataBLOB, &Hash))
        if ( NULL ==  Hash.pData)
		{
//			PRINT_ERROR("Sign: failed to get KeyID.");
            NSLog(@"Sign: failed to get KeyID.");
			res = UAF_CMD_STATUS_ERR_UNKNOWN;
            
			goto clean;
		}
//		HEX_DUMP("keyID : ", Hash.pData, Hash.length);
		signRespArgs.keyID.length = Hash.length;

//        pInputArgs->transactionContent.pData = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:pInputArgs->transactionContent.pData length:strlen(pInputArgs->transactionContent.pData)];
//        pInputArgs->transactionContent.length = 32;
        
		/* Create UAF Response */
		signRespArgs.pAAID						= (ak_byte_t*)&pAuthnrInfo->aaid[0];
//		signRespArgs.authenticatorVersion		= pAKInfo->extInfo.version;
		signRespArgs.authenticationMode			= (0 == pInputArgs->transactionContent.length) ?
													UAF_USER_VERIFIED : UAF_SECURE_DISPLAY;
		signRespArgs.signatureAlgAndEncoding	= pAuthnrInfo->metadata.authenticationAlg;
		signRespArgs.authenticatorNonce.length	= sizeof(authnrNonce);
		signRespArgs.authenticatorNonce.pData	= authnrNonce;
		signRespArgs.keyID.pData				= &keyID[0];
		signRespArgs.pFinalChallenge			= &pInputArgs->finalChallenge;
		signRespArgs.pTransactionText			= &pInputArgs->transactionContent;
		signRespArgs.signCounter				= 1;
//		signRespArgs.hUAuthKey					= hUauthKey;
	}
     

	/* Response format : TAG_UAFV1_SIGN_CMD_RESP || LENGTH || ERRORCODE 
	 * || UAF_SIGN_REPONSE/KEYHANDLE_USERNAME */
	ptr = pResponse + RESPONSE_HEADER_SIZE;
	remainder = *pResponseLength - RESPONSE_HEADER_SIZE;

	tmpLength = remainder;
	res = CreateUAFV1SignResponse(&signRespArgs,pInputArgs->username.pData,  ptr, &tmpLength, additionalSignedDataArray, additionalSignedDataArraySize, 0, 0,method);
    if (res != UAF_CMD_STATUS_OK) 
	{
//		PRINT_ERROR("Sign: CreateUAFV1SignResponse failed.");
        NSLog(@"Sign: CreateUAFV1SignResponse failed.");
        goto clean;
    }

	/* Skip Bytes */
	ptr = AK_SkipBytes(ptr, &remainder, tmpLength);
	tmpLength = remainder;


	*pResponseLength = (ak_word_t)(ptr - pResponse);

clean:
//	nnl_memset_s(usernames, 0, MAX_USERNAME_SIZE * MAX_KEYHANDLE_NUM);
     memset(usernames, 0, MAX_USERNAME_SIZE * MAX_KEYHANDLE_NUM);
    
    if(NULL != DataBLOB.pData)
    {
        free(DataBLOB.pData);
        DataBLOB.pData = NULL;
    }
     
//     
//     if(NULL != Hash.pData)
//     {
//         free(Hash.pData);
//         Hash.pData = NULL;
//     }
//    
     
     if(NULL != pInputArgs->finalChallenge.pData)
     {
         free(pInputArgs->finalChallenge.pData);
         pInputArgs->finalChallenge.pData = NULL;
         pInputArgs->finalChallenge.pData = 0;
     }
     

	
	if (UAF_CMD_STATUS_OK != res) 
	{
		*pResponseLength = RESPONSE_HEADER_SIZE;
	}

	{
		ak_word_t i;
		for (i = 0; i < pKHTags.numTags; i++) {
			if (pKHTags.tlvs[i].value)
			{
//				nnl_memset(pKHTags.tlvs[i].value, 0, pKHTags.tlvs[i].length);
//				nnl_free(pKHTags.tlvs[i].value);
                
                memset(pKHTags.tlvs[i].value, 0, pKHTags.tlvs[i].length);
                free(pKHTags.tlvs[i].value);
			}
		}
	}

	ptr = pResponse;
	remainder = RESPONSE_HEADER_SIZE;

	ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_SIGN_CMD_RESP);
	ptr = AK_WriteWord(ptr, &remainder, *pResponseLength - TLV_TL_SIZE);
	ptr = AK_WriteWord(ptr, &remainder, TAG_STATUS_CODE);
	ptr = AK_WriteWord(ptr, &remainder, sizeof(ak_word_t));
	AK_WriteWord(ptr, &remainder, (ak_word_t)res);

    return UAF_CMD_STATUS_OK;
}

/**
 * Creates a UAFV1 Signing Response using provided arguments.
 *
 * @param pArgs pointer to a signResponseArgs_t structure to be exported
 * @param pUAFV1RegResponse pointer to the output sign response
 * @param pRegResponseSize pointer to where the size of the response to be stored
 */
ak_result_t CreateUAFV1SignResponse(signResponseArgs_t* pArgs,
                                    ak_byte_t *username,
                                    ak_byte_t *pUAFV1SignResponse,
                                    ak_word_t *pUAFV1SignResponseLength,
                                    cal_blob_t *additionalSignedData,
                                    ak_byte_t signedDataLen,
                                    cal_blob_t *additionalUnsignedData,
                                    ak_byte_t unsignedDataLen,
                                    NSInteger method
)
{
	ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;
    ak_byte_t loopIndex = 0;

	ak_byte_t* ptrAuthenticator = NULL;
	ak_byte_t* ptrAuthentication = NULL;

	cal_blob_t Hash = { 0 };
	ak_word_t TCHashSize = 0;

	ak_byte_t *pSignData = NULL;
	ak_word_t signDataSize = 0;

	ak_word_t respSize = 0;

	cal_blob_t DataBLOB = { 0 };
	cal_blob_t Signature = { 0 };

	ak_word_t tmpRemainder = 0;

	ak_word_t unKHSize = 0;
	ak_byte_t i = 0;

	cal_result_t calResult;

	if (NULL == pArgs || NULL == pUAFV1SignResponse || NULL == pUAFV1SignResponseLength)
	{
		return UAF_STATUS_ERR_INVALID_PARAM;
	}

	ptr = pUAFV1SignResponse;
	remainder = * pUAFV1SignResponseLength;

	/* If only one key handle remains, generate auth assertion */
	if (pArgs->keyHandleNum == 1) 
	{
		ptr = AK_WriteWord(ptr, &remainder, TAG_AUTHENTICATOR_ASSERTION);
		ptrAuthenticator = ptr;
		ptr = AK_SkipBytes(ptr, &remainder, TLV_T_SIZE);

		ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_AUTH_ASSERTION);
		ptrAuthentication = ptr;
		ptr = AK_SkipBytes(ptr, &remainder, TLV_L_SIZE);
		
		/* Get the exact size of the hash */
//		if (CAL_SUCCESS != gpCAL->CAL_HashData(NULL, &Hash)) 
//		{
////			PRINT_ERROR("CreateUAFV1SignResponse: CAL_HashData failed to get the size of the hash.");
//            NSLog(@"CreateUAFV1SignResponse: CAL_HashData failed to get the size of the hash.");
//			return UAF_CMD_STATUS_ERR_UNKNOWN;
//		}

		/* Get the size of SignedData */
		/* TCHashSize is either 0 or CAL_MAX_HASH_SIZE */
        Hash.length = 32;
		TCHashSize = (0 == pArgs->pTransactionText->length) ? 0 : (ak_word_t)Hash.length;
		signDataSize = (ak_word_t) (TLV_TL_SIZE	/* SignedData Tag and Length */
			+ TLV_TL_SIZE + AAID_SIZE /* TAG_AAID */
			+ TLV_TL_SIZE + sizeof(ak_byte_t) + sizeof(ak_word_t) * 2 /* Version, Mode and Sig Alg */
			+ TLV_TL_SIZE + pArgs->authenticatorNonce.length /* Authnr Nonce */
			+ TLV_TL_SIZE + pArgs->pFinalChallenge->length /* FinalChallenge */
			+ TLV_TL_SIZE + TCHashSize /* TC Hash */
			+ TLV_TL_SIZE + pArgs->keyID.length /* Key ID */
			+ TLV_TL_SIZE + sizeof(ak_dword_t))	/* SignCounter */;
        
        /* calcuate size of additional signed data and add to signed data length.*/
        for (loopIndex =0; loopIndex < signedDataLen; loopIndex++) {
            signDataSize += additionalSignedData[loopIndex].length;
        }

		respSize = signDataSize;
		pSignData = ptr;

		ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_SIGNEDDATA);
		ptr = AK_WriteWord(ptr, &remainder, signDataSize - TLV_TL_SIZE);

		/* Write TAG_AAID */
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_AAID, pArgs->pAAID, AAID_SIZE);
		
//		PRINT_INFO("authenticatorVersion for SIGN command: %04x", pArgs->authenticatorVersion);
        
	
		/* Write TAG_ASSERTION_INFO */
		ptr = AK_WriteWord(ptr, &remainder, TAG_ASSERTION_INFO);
		ptr = AK_WriteWord(ptr, &remainder, sizeof(ak_byte_t) + sizeof(ak_word_t) * 2);
		ptr = AK_WriteWord(ptr, &remainder, pArgs->authenticatorVersion); //Authnr Version
		ptr = AK_WriteBytes(ptr, &remainder, (ak_byte_t*)&pArgs->authenticationMode, sizeof(ak_byte_t)); //Authnr Mode
		ptr = AK_WriteWord(ptr, &remainder, pArgs->signatureAlgAndEncoding); // Signature Alg

		/* Write TAG_AUTHENTICATOR_NONCE */
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_AUTHENTICATOR_NONCE, 
			 pArgs->authenticatorNonce.pData, (ak_word_t)pArgs->authenticatorNonce.length);
		/* Write FinalChallenge */
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_FINAL_CHALLENGE, 
			pArgs->pFinalChallenge->pData, (ak_word_t)pArgs->pFinalChallenge->length);
		/* Write TAG_TRANSACTION_CONTENT_HASH */
		ptr = AK_WriteWord(ptr, &remainder, TAG_TRANSACTION_CONTENT_HASH);
		ptr = AK_WriteWord(ptr, &remainder, TCHashSize);
		if (TCHashSize > 0) 
		{ 
			/* Calculate the hash of TC and write to the output */
			DataBLOB.pData = (cal_byte_t*)pArgs->pTransactionText->pData;
			DataBLOB.length = (cal_dword_t)pArgs->pTransactionText->length;
			Hash.pData = (cal_byte_t*)ptr;
			Hash.length = (cal_dword_t)TCHashSize;

			ptr = AK_SkipBytes(ptr, &remainder, TCHashSize);
			if (NULL == ptr)
			{
//				PRINT_ERROR("GetInfo: response buffer[%u] is too small.", *pUAFV1SignResponseLength);
                 NSLog(@"GetInfo: response buffer[%u] is too small.", *pUAFV1SignResponseLength);
				return UAF_STATUS_ERR_BUFFER_SMALL;
			}

            
            uint8_t *hashcopy =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:DataBLOB.pData length:DataBLOB.length];
            
            memcpy(Hash.pData, hashcopy, 32);
            
            if ( NULL ==  Hash.pData)
			{
                 NSLog(@"CreateUAFV1SignResponse: failed to calculate TCHash.");
				return UAF_CMD_STATUS_ERR_UNKNOWN;
			}
            
            
            if ( NULL !=  hashcopy)
            {
                free(hashcopy);
                hashcopy = NULL;
            }
		}

        
        uint8_t * tcdata = DataBLOB.pData;
        
		/* Write TAG_KeyID */
		ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_KEYID, 
			pArgs->keyID.pData, (ak_word_t)pArgs->keyID.length);

        
        /* Additional signed data */
        if (signedDataLen > 0 && additionalSignedData != 0) {
            for(loopIndex = 0; loopIndex < signedDataLen ; loopIndex++) {
                ptr = AK_WriteBytes(ptr, &remainder, additionalSignedData[loopIndex].pData, additionalSignedData[loopIndex].length);
            }
        }
		/* Write TAG_COUNTERS */
		ptr = AK_WriteWord(ptr, &remainder, TAG_COUNTERS);
		ptr = AK_WriteWord(ptr, &remainder, sizeof(ak_dword_t));
	//	ptr = AK_WriteDWord(ptr, &remainder, pArgs->signCounter); // SignCounter
        
        NSString *dataIn = nil;
        if ([gmrz_jv_asm_db gmrz_jv_asm_DB_Query:@"signCounter" counterIn:@"signCounter" DB_dataIn:&dataIn] == errSecItemNotFound) {
            [gmrz_jv_asm_db gmrz_jv_asm_DB_Add:@"signCounter" counterIn:@"signCounter" DB_dataIn:@"2"];
        }
        NSString * signCounter = nil;
        NSInteger  state =  [gmrz_jv_asm_db gmrz_jv_asm_DB_Query:@"signCounter" counterIn:@"signCounter" DB_dataIn:&signCounter];
        int sign = 0;
        if (state == 0) {
            sign = [signCounter intValue];
        }
        ptr = AK_WriteDWord(ptr, &remainder, sign); // SignCounter
        
        [gmrz_jv_asm_db gmrz_jv_asm_DB_Delete:@"signCounter" counterIn:@"signCounter"];
        
        
        sign++;
        [gmrz_jv_asm_db gmrz_jv_asm_DB_Add:@"signCounter" counterIn:@"signCounter" DB_dataIn:[NSString stringWithFormat:@"%d",sign]];

        
		/* Calculate SignData signature size */
        Signature.length = 64;


		/* Write the signature size */
		ptr = AK_WriteWord(ptr, &remainder, TAG_SIGNATURE);
		ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)Signature.length);

		/* Calculate KRD signature and write it to the output */
		DataBLOB.pData = (cal_byte_t*)pSignData;
		DataBLOB.length = (cal_dword_t)signDataSize;
		Signature.pData = (cal_byte_t*)ptr;

		ptr = AK_SkipBytes(ptr, &remainder, (ak_word_t)Signature.length);
		if (NULL == ptr)
		{
//			PRINT_ERROR("GetInfo: response buffer[%u] is too small.", *pUAFV1SignResponseLength);
            NSLog(@"GetInfo: response buffer[%u] is too small.", *pUAFV1SignResponseLength);
			return UAF_STATUS_ERR_BUFFER_SMALL;
		}

        uint8_t signature[512];
        size_t signatureLength = sizeof(signature);
        uint8_t digestData[512];
        size_t digestLength = sizeof(digestData);
        memcpy(digestData, DataBLOB.pData, DataBLOB.length);

        
        uint8_t *hash =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:digestData length:DataBLOB.length];
        
//		calResult = gpCAL->CAL_Sign(pArgs->hUAuthKey, &DataBLOB, &Signature);
//		if (CAL_SUCCESS != calResult)
        
        
        NSMutableString *hexString = [NSMutableString string];
        for (int i=0; i < 9; i++)
        {
            [hexString appendFormat:@"%c", pArgs->pAAID[i]];
        }
        
        
        
        calResult = [[gmrz_jv_ecc_cal_ext sharedManager] useKeyAsyncSign:nil pubId:nil trancationtext:tcdata serviceId:hexString
                                                               accountId:[NSString stringWithCString:username encoding:NSUTF8StringEncoding] digestData:hash digestLength:32 signature:signature signatureLength:&signatureLength method:method methods:@"auth"];
        
        if (hash != NULL) {
            free(hash);
            hash = NULL;
        }
        if (calResult == -128 || calResult==-2)
        {
            //		PRINT_ERROR("CreateUAFV1RegResponse: failed to get signature.");
            NSLog(@"CreateUAFV1RegResponse: failed to get signature.");
            return CAL_ERR_CANCELED;
        }
        if (calResult == -3)
        {
            //		PRINT_ERROR("CreateUAFV1RegResponse: failed to get signature.");
            NSLog(@"CreateUAFV1RegResponse: failed to get signature.");
            return CAL_ERR_USE_PASSWORD_PANEL;
        }
        else if (CAL_SUCCESS != calResult &&calResult != -128)
        {
            //		PRINT_ERROR("CreateUAFV1RegResponse: failed to get signature.");
            NSLog(@"CreateUAFV1RegResponse: failed to get signature.");
            return UAF_CMD_STATUS_ERR_UNKNOWN;
        }
        
        char rawstr[65] = "\0";
        memset(rawstr, 0x0, sizeof(rawstr));
        char length = *(signature + 3);
        char *temp_ptr = NULL;
        
        temp_ptr = signature + 4;
        if (length > 32) {
            temp_ptr = temp_ptr + (length - 32);
        }
        
        memcpy(rawstr, temp_ptr, 32);
        temp_ptr = temp_ptr + 32;
        length = *(temp_ptr + 1);
        temp_ptr += 2;
        if (length > 32) {
            temp_ptr = temp_ptr + (length - 32);
        }
        
        memcpy(rawstr + 32, temp_ptr, 32);
        
        memcpy(Signature.pData, rawstr, 64);
       
		/* Check ptr before updating tag sizes */
		if (NULL == ptr)
		{
//			PRINT_ERROR("GetInfo: response buffer[%u] is too small.", *pUAFV1SignResponseLength);
            NSLog(@"GetInfo: response buffer[%u] is too small.", *pUAFV1SignResponseLength);
			return UAF_STATUS_ERR_BUFFER_SMALL;
		}

		respSize += (ak_word_t)Signature.length + TLV_TL_SIZE;

		/* Write the size of TAG_UAFV1_AUTH_ASSERTION */
		tmpRemainder = sizeof(ak_word_t);	
		AK_WriteWord(ptrAuthentication, &tmpRemainder, respSize);

		/* Write the size of TAG_AUTHENTICATOR_ASSERTION */
		respSize += TLV_TL_SIZE;		
		tmpRemainder = sizeof(ak_word_t);
		AK_WriteWord(ptrAuthenticator, &tmpRemainder, respSize);

		respSize += TLV_TL_SIZE;
	}
	/* If more than one key handle present, send the TAG_USERNAME_AND_KEYHANDLE */
	else 
	{
		for (i = 0; i < pArgs->keyHandleNum; i++) 
		{
			unKHSize = (ak_word_t)(TLV_TL_SIZE * 2 + 
				pArgs->usernames[i].length + pArgs->pKeyHandles[i]->length);
			ptr = AK_WriteWord(ptr, &remainder, TAG_USERNAME_AND_KEYHANDLE);
			ptr = AK_WriteWord(ptr, &remainder, unKHSize);
			respSize += TLV_TL_SIZE;
			
			/* Write TAG_USERNAME */
			ptr = AK_WriteWord(ptr, &remainder, TAG_USERNAME);
			ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)pArgs->usernames[i].length);
			ptr = AK_WriteBytes(ptr, &remainder, pArgs->usernames[i].pData, (ak_word_t)pArgs->usernames[i].length);

			/* Write TAG_KEYHANDLE */
			ptr = AK_WriteWord(ptr, &remainder, TAG_KEYHANDLE);
			ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)pArgs->pKeyHandles[i]->length);
			ptr = AK_WriteBytes(ptr, &remainder, pArgs->pKeyHandles[i]->pData, (ak_word_t)pArgs->pKeyHandles[i]->length);

			respSize += unKHSize;
		}
	}

	/* Get the size of the command response*/
	*pUAFV1SignResponseLength = respSize;

	return UAF_CMD_STATUS_OK;
}
