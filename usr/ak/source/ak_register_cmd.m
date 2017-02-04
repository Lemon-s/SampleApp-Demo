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
#import <UIKit/UIKit.h>
#import "gmrz_jv_util_func.h"


static NSString *privatekeyid = @"prib19";
static NSString *publickeyid = @"pubb19";
static int osVer_get  = 0;

#define SystemVersion [[UIDevice currentDevice] systemVersion].floatValue

ak_result_t getPubKeyBytes(cal_pubkey_blob_t *pubKey, 
						   ak_byte_t *buffer, 
						   ak_dword_t bufferLen, 
						   ak_dword_t *pubKeyLen);

/**ÏÏÏ
 * Creates a UAFV1 Registration Response using provided arguments.
 *
 * @param pArgs pointer to a regResponseArgs_t structure to be exported
 * @param pUAFV1RegResponse pointer to the output reg response
 * @param pRegResponseSize pointer to where the size of the response to be stored
 *Ï
 * @return UAF_STATUS_ERR_UNKNOWN if failed to create signature
 *		   UAF_STATUS_OK if succeeded
 */
ak_result_t CreateUAFV1RegResponse(regResponseArgs_t* pArgs /*IN*/,
                                   ak_byte_t *username,/*IN*/
                                   ak_byte_t *pUAFV1RegResponse /*OUT*/,
                                   ak_word_t *pRegResponseSize /*OUT*/,
                                   cal_blob_t *additionalSignedData,
                                   ak_byte_t signedDataLen,
                                   cal_blob_t *additionalUnsignedData,
                                   ak_byte_t unsignedDataLen,
                                   NSInteger method
);

/** 
 * Process registration request and output registration response
 *
 * @param pAKInfo [IN] pointer to a structure containing internal AK info
 * @param pInputArgs [IN] pointer to a structure containing the parsed AK request
 * @param pResponse [IN/OUT] A buffer where the response must be written. This buffer must be allocated by the caller.
 * @param pResponseLength [IN/OUT] Length of the response
 */
ak_result_t Register( authenticatorInfo_t *pAKInfo,
                        ak_dword_t  pAKInfoCount,
					   input_args_t *pInputArgs,
					   ak_byte_t *pResponse, 
					   ak_word_t *pResponseLength,
                     NSInteger method)
{
	ak_result_t result = UAF_CMD_STATUS_OK;

	ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;

	ak_word_t tmpLength = 0;

	authenticator_t*		pAuthenticator = NULL;
	authenticatorInfo_t*	pAuthnrInfo = NULL;
    ak_byte_t authnrVerifyOut[MAX_KEYHANLDE_EXT_SIZE];
//    ak_word_t authnrVerifyOutSize = (ak_word_t)sizeof(authnrVerifyOut);
//    ak_byte_t rawUviOut[CAL_MAX_HASH_SIZE];
//    ak_word_t rawUviOutSize = 0;
//    ak_byte_t signedUVI_TLV[TLV_TL_SIZE + CAL_MAX_HASH_SIZE];

	cal_handle_t hAttKey	= NULL;
	cal_handle_t hUauthKey	= NULL;
    ak_byte_t * publickey_ios9 = NULL;
    
    
	cal_pubkey_blob_t authPubKey = {0};

	ak_byte_t pubKeyBuffer[MAX_PUBLIC_KEY_SIZE];
	ak_dword_t pubKeySize = 0;

	createKeyHandleArgs_t createKHArgs = {0};

	ak_byte_t keyHandle[MAX_KEYHANDLE_SIZE];
	ak_word_t khSize = MAX_KEYHANDLE_SIZE;

	ak_byte_t keyID[CAL_MAX_HASH_SIZE];

	cal_blob_t DataBLOB = { 0 };
	cal_blob_t Hash		= { 0 };
    cal_blob_t additionalSignedDataArray[1] = {0};
    ak_byte_t additionalSignedDataArraySize = 0;

	regResponseArgs_t regRespArgs = {0};

//	PRINT_INFO("Register called.");

	if (NULL == pAKInfo || NULL == pInputArgs || NULL == pResponse || NULL == pResponseLength)
		return UAF_STATUS_ERR_INVALID_PARAM;
    
    NSLog(@"%d\n", *pResponseLength);
	if (RESPONSE_HEADER_SIZE > *pResponseLength)
	{
		NSLog(@"GetInfo: response buffer[%u] is too small.", *pResponseLength);
		return UAF_STATUS_ERR_BUFFER_SMALL;
	}

	/* Check the authenticator ID */
//	if (pInputArgs->authenticatorID >= pAKInfo->authenticators.num)
    if (pInputArgs->authenticatorID >= pAKInfoCount)
    
	{
//		PRINT_ERROR("Register: invalid authenticator ID.");
        NSLog(@"%s", "Register: invalid authenticator ID.");
		result = UAF_STATUS_ERR_INVALID_PARAM;
        goto finalize;
	}

//	PRINT_INFO("Register: authenticatorIndex: %d, authenticatorNum: %d", pInputArgs->authenticatorID, pAKInfo->authenticators.num);
	/* Get authenticator and its information */
//	pAuthenticator = &pAKInfo->authenticators.items[pInputArgs->authenticatorID];
    
    
    pAuthnrInfo = pAKInfo;
//	if (UAF_CMD_STATUS_OK !=
//		pAuthenticator->GetInfo(pInputArgs->authenticatorID, &pAuthnrInfo))
    
    if(NULL == pAuthnrInfo)
	{

        NSLog(@"%s", "Register: invalid authenticator ID.");
		result = UAF_CMD_STATUS_ERR_UNKNOWN;
		goto finalize;
	}

	/* Check if the attestation type is supported */
	if (pInputArgs->attestationType != pAuthnrInfo->attestationType) 
	{
		NSLog(@"Register: attestation type not supported.");
		result = UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED;
		goto finalize;
	}

    
    //ios could not got some obj like uvi ,so uvt did not verify at here
	/* Verify UVT */
//	if (UAF_CMD_STATUS_OK !=
//		VerifyUVT(pInputArgs, &pAuthnrInfo->aaid[0], authnrVerifyOut, &authnrVerifyOutSize, rawUviOut, &rawUviOutSize, pAuthnrInfo->containerID, pAuthnrInfo->UVTFormat))
//	{
////		PRINT_ERROR("Register: VerifyUVT failed.");
//        NSLog(@"%s", "Register: VerifyUVT failed.");
//		result = UAF_CMD_STATUS_ACCESS_DENIED;
////		goto finalize;
//        return NULL;
//	}

	/* Mix server challenge to entropy pool */
    
    pInputArgs->finalChallenge.pData = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:pInputArgs->finalChallenge.pData length:strlen(pInputArgs->finalChallenge.pData)];
    pInputArgs->finalChallenge.length = 32;
	if (UAF_CMD_STATUS_OK != MixServerChallenge(pInputArgs->finalChallenge)) {
//		PRINT_ERROR("Register: failed to mix the server challenge.");
        
        NSLog(@"%s", "Register: failed to mix the server challenge.");
		result = UAF_CMD_STATUS_ERR_UNKNOWN;
		goto finalize;
	}

	/* Check gpCAL */
 
    {
//        osVer_get = SystemVersion;
        NSString * priID;
        NSString * pubID;
        NSMutableString *hexString = [NSMutableString string];
        for (int i=0; i < 9; i++)
        {
            [hexString appendFormat:@"%c", pAKInfo->aaid[i]];
        }
        
       priID =  [gmrz_jv_util_func asmDB_data_id:hexString counterid:[[NSBundle mainBundle] bundleIdentifier] username:[NSString stringWithCString:pInputArgs->username.pData encoding:NSUTF8StringEncoding] ext:@"pri"];
        pubID =  [gmrz_jv_util_func asmDB_data_id:hexString counterid:[[NSBundle mainBundle] bundleIdentifier] username:[NSString stringWithCString:pInputArgs->username.pData encoding:NSUTF8StringEncoding] ext:@"pub"];
//    

        //??????????
        //增加判断 是否已经生成密钥对  如果已经生成那么删除原有的密钥对 重新生成（尚未增加）
        //??????????
        
        
        if (SystemVersion >= 9.0) {
            if (CAL_SUCCESS != [[gmrz_jv_ecc_cal_ext sharedManager] generateKeyAsync_ios9:priID pubId:publickeyid publickeybyte:&publickey_ios9]) {
                //        PRINT_ERROR("Register: CAL_GenKey failed.");
                NSLog(@"%s", "Register: CAL_GenKey failed.");
                result = UAF_CMD_STATUS_ERR_UNKNOWN;
                goto finalize;
            }
        }
        else if(SystemVersion <= 8.4 && SystemVersion >= 8.0)
        {
            
            if (CAL_SUCCESS != [[gmrz_jv_ecc_cal_ext sharedManager] generateKeyAsync:priID pubId:pubID serviceId:hexString accountId:[NSString stringWithCString:pInputArgs->username.pData encoding:NSUTF8StringEncoding]]) {
                //        PRINT_ERROR("Register: CAL_GenKey failed.");
                NSLog(@"%s", "Register: CAL_GenKey failed.");
                result = UAF_CMD_STATUS_ERR_UNKNOWN;
                goto finalize;
            }
        }
    
    }
   
    
    
    
    
    if(TAG_ATTESTATION_BASIC_FULL == pAuthnrInfo->attestationType)
    {
        /* Get Attestation Key */
        //		if (CAL_SUCCESS != gpCAL->CAL_GetAttestationKey(NULL, NULL, &hAttKey))
        //		{
        //			PRINT_ERROR("Register: CAL_GetAttestationKey failed.");
        //			result = UAF_CMD_STATUS_ERR_UNKNOWN;
        //			goto finalize;
        //		}
    }
    //	else if(TAG_ATTESTATION_BASIC_SURROGATE == pAuthnrInfo->attestationType)
    else if(TAG_ATTESTATION_BASIC_SURROGATE == pAuthnrInfo->attestationType)
    {
        /* For surrogate attestation generated Uauth key is used.*/
//
        
        //
        NSMutableString *hexString = [NSMutableString string];
        for (int i=0; i < 9; i++)
        {
            [hexString appendFormat:@"%c", pAKInfo->aaid[i]];
        }

        NSString * priID =  [gmrz_jv_util_func asmDB_data_id:hexString counterid:[[NSBundle mainBundle] bundleIdentifier] username:[NSString stringWithCString:pInputArgs->username.pData encoding:NSUTF8StringEncoding] ext:@"pri"];
        NSString *pubID =  [gmrz_jv_util_func asmDB_data_id:hexString counterid:[[NSBundle mainBundle] bundleIdentifier] username:[NSString stringWithCString:pInputArgs->username.pData encoding:NSUTF8StringEncoding] ext:@"pub"];
        if (SystemVersion <= 8.4  && SystemVersion >= 8.0) {
            hUauthKey = (unsigned char *)[[[gmrz_jv_ecc_cal_ext sharedManager] setPublicData:priID pubId:pubID] bytes];

            hAttKey = hUauthKey;
        }
        else
        {
             hAttKey = publickey_ios9;
        }
    }


	/* Convert the Uauth public key to raw bytes and copy it to a buffer */
    memset(pubKeyBuffer, 0x0, sizeof(pubKeyBuffer));
    memcpy(pubKeyBuffer, hAttKey,65);
    
    pubKeySize = 65;
	/* Create raw key handles */
	createKHArgs.pKHAccessToken = &pInputArgs->khAccessToken;
	createKHArgs.hUauthPriv = hAttKey;
	createKHArgs.isSecondFactor = (pAuthnrInfo->metadata.authenticatorType & UAF_TYPE_2NDF_AUTHNR);
	createKHArgs.pUsername = &pInputArgs->username;
	createKHArgs.authenticatorInput.length = 0;
	createKHArgs.authenticatorInput.pData = NULL;
	createKHArgs.pTLVs = NULL; //&pInputArgs->extensionTags;

	/* Add version of key container*/
	createKHArgs.versionOfKeyContainer = KEY_CONTAINER_VERSION;

	/* Create key handle to be exported*/
//	nnl_memset(keyHandle, 0, MAX_KEYHANDLE_SIZE);
    memset(keyHandle, 0, MAX_KEYHANDLE_SIZE);
    NSLog(@"CreateKeyHandle  .\n");
	result = CreateKeyHandle(&createKHArgs, &keyHandle[0], &khSize);
    NSLog(@"end CreateKeyHandle  .\n");
	if (UAF_CMD_STATUS_OK != result) {
//		PRINT_ERROR("Register: failed to create key handle.");
         NSLog(@"%s", "Register: failed to create key handle.");
		goto finalize;
	}

	/* Generate KeyID */
    
//    [NSData dataWithBytes:keyHandle length:khSize];
    memset(keyHandle + khSize, 0x0, sizeof(keyHandle) - khSize);
	DataBLOB.pData = (cal_byte_t*)keyHandle;
	DataBLOB.length = (cal_dword_t)khSize;
	Hash.pData = (cal_byte_t*)keyID;
	Hash.length = (cal_dword_t)sizeof(keyID);
    
   
    
    

    NSLog(@" Register create keyid getHashBytes .\n");
//    unsigned char * hashcopy =  [[[gmrz_jv_ecc_cal_ext sharedManager] getHashBytes: [NSData dataWithBytes:keyHandle length:khSize]] bytes];
    
    uint8_t *hashcopy =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:keyHandle length:khSize];
    if (!hashcopy) {
       
        NSLog(@"%s", "Register: failed to get create keyid getHashBytes.");
        result = UAF_CMD_STATUS_ERR_UNKNOWN;
        goto finalize;
    }
    memcpy(Hash.pData, hashcopy,Hash.length);
    NSLog(@"end Register create keyid getHashBytes .\n");
//	if (CAL_SUCCESS != gpCAL->CAL_HashData(&DataBLOB, &Hash)) {
////		PRINT_ERROR("Register: failed to get KeyID.");
//          NSLog(@"%s", "Register: failed to get KeyID.");
//		result = UAF_CMD_STATUS_ERR_UNKNOWN;
//		goto finalize;
//	}
    
    
    
    
    //store username keyid keyhandle and ****
    {
        NSMutableString *hexString = [NSMutableString string];
        for (int i=0; i < 9; i++)
        {
            [hexString appendFormat:@"%c", pAKInfo->aaid[i]];
        }
        
        
        NSString * serviceID = nil;
        serviceID = [@""  stringByAppendingString:hexString];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
        
        NSString *priId =[serviceID stringByAppendingString:[[NSString alloc] initWithUTF8String:pInputArgs->username.pData]];
        
        //check keyhandle first
        NSString  *ItemOut = nil;
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
        

        NSString *keyinfolist= nil;
        
        
        uint8_t *keyhandle = (uint8_t *)malloc(512);
        
        gmrz_base64_encode_ext(DataBLOB.pData, keyhandle, DataBLOB.length);
        
//        uint8_t *keyhandle = gmrz_base64_encode(DataBLOB.pData, DataBLOB.length);
        
        uint8_t *keyid = (uint8_t *)malloc(128);
        
        gmrz_base64_encode_ext(hashcopy, keyid, 32);
        
        
       
        
//        uint8_t *keyid = gmrz_base64_encode(hashcopy, 32);
        
        NSString * nskeyid = [gmrz_jv_util_func base64urlconv:keyid];
        
        NSString *idefientprivatekey = [[NSString alloc] initWithUTF8String:pInputArgs->username.pData];
       
        
        if (ItemOut == nil) {
            
            [gmrz_jv_util_func KeychainItem_add:[[NSString alloc] initWithUTF8String:pInputArgs->username.pData]
             
                                      keyhandle:[NSString stringWithFormat:@"%s" ,keyhandle]
                                          keyid:nskeyid
                                            UVS:@""
                                      serviceId:hexString
                                      accountId:[[NSString alloc] initWithUTF8String:pInputArgs->username.pData]
                                          priId:idefientprivatekey
                                 userlistJsonIn:nil userlistJsonOut:&keyinfolist];
            
            
        }
        else
        {
            [gmrz_jv_util_func KeychainItem_add:[[NSString alloc] initWithUTF8String:pInputArgs->username.pData]
             
                                      keyhandle:[NSString stringWithFormat:@"%s" ,keyhandle]
                                          keyid:nskeyid
                                            UVS:@""
                                      serviceId:hexString
                                      accountId:[[NSString alloc] initWithUTF8String:pInputArgs->username.pData]
                                          priId:idefientprivatekey
                                 userlistJsonIn:ItemOut userlistJsonOut:&keyinfolist];
        }
            
            
            
        [gmrz_jv_util_func db_items_delete:serviceID FuncItemIndex:0];
        [gmrz_jv_util_func db_items_add:serviceID Data2Json:keyinfolist];
        if (NULL != keyhandle)
        {
            free(keyhandle);
            keyhandle = NULL;
        }
        
        if (NULL != keyid)
        {
            free(keyid);
            keyid = NULL;
        }
        
   
        
        
    }
    
    
    
    
    
    

	/* Create UAF Response */
	regRespArgs.pAAID						= (ak_byte_t*)&pAuthnrInfo->aaid[0];
//	regRespArgs.authenticatorVersion		= pAKInfo->extInfo.version;
	regRespArgs.authenticationMode			= UAF_USER_VERIFIED;
    
//    if (CAL_ALG_ECDSA == authPubKey.pPubKey->algid) {
    if (CAL_ALG_ECDSA == CAL_ALG_ECDSA) {
        regRespArgs.publicKeyAlgAndEncoding		= UAF_ALG_KEY_ECC_X962_RAW;
    }
    else if (CAL_ALG_RSA == authPubKey.pPubKey->algid)
    {
        regRespArgs.publicKeyAlgAndEncoding		= UAF_ALG_KEY_RSA_2048_PSS_RAW;
    }
	else if (CAL_ALG_SM2 == authPubKey.pPubKey->algid)
	{
		regRespArgs.publicKeyAlgAndEncoding		= UAF_ALG_KEY_ECC_X962_RAW;
	}
	

    
	regRespArgs.attestationType				= pAuthnrInfo->attestationType;
//    regRespArgs.signatureAlgAndEncoding		= pAuthnrInfo->metadata.authenticationAlg;
	regRespArgs.pFinalChallenge				= &pInputArgs->finalChallenge;
	regRespArgs.keyID.pData					= &keyID[0];
	regRespArgs.keyID.length				= Hash.length;
//	regRespArgs.regCounter					= ++pInputArgs->pConfig->regCounter;
//	regRespArgs.signCounter					= ++pInputArgs->pConfig->signCounter;
    	regRespArgs.regCounter					= 1;
    	regRespArgs.signCounter					= 1;
	regRespArgs.uauthPub.length				= pubKeySize;
	regRespArgs.uauthPub.pData				= pubKeyBuffer;
//	regRespArgs.pAttestationCertificate		= (cal_cblob_t *)pAuthnrInfo->certificate;
	regRespArgs.keyHandle.length			= khSize;
	regRespArgs.keyHandle.pData				= &keyHandle[0];
	regRespArgs.hAttestationKey				= hAttKey;

//    if (rawUviOutSize != 0) { // UVI data is optional
////        PRINT_INFO("Including UVI data in KRD");
//         NSLog(@"%s", "Including UVI data in KRD");
//        result = GenerateUviTlv(keyID, sizeof(keyID), rawUviOut, rawUviOutSize, signedUVI_TLV, sizeof(signedUVI_TLV));
//        if (result != UAF_CMD_STATUS_OK) {
////            PRINT_ERROR("Register: generating UVI TLV failed.");
//             NSLog(@"%s", "Register: generating UVI TLV failed.");
//            goto finalize;
//        }
//    
//        additionalSignedDataArray[additionalSignedDataArraySize].pData = signedUVI_TLV;
//        additionalSignedDataArray[additionalSignedDataArraySize].length = sizeof(signedUVI_TLV);
//        additionalSignedDataArraySize++;
//    }
	/* Response format : TAG_UAFV1_REGISTER_CMD_RESP || LENGTH || TAG_STATUS_CODE || UAF_REG_REPONSE */
	ptr = pResponse + RESPONSE_HEADER_SIZE;
	remainder = *pResponseLength - RESPONSE_HEADER_SIZE;

	tmpLength = remainder;
	result = CreateUAFV1RegResponse(&regRespArgs, pInputArgs->username.pData, ptr, &tmpLength, additionalSignedDataArray, additionalSignedDataArraySize, 0, 0,method);
	if (result != UAF_CMD_STATUS_OK) 
	{
//		PRINT_ERROR("Register: CreateUAFV1RegResponse failed.");
        NSLog(@"%s", "Register: CreateUAFV1RegResponse failed.");
		goto finalize;
	}

	/* Skip Bytes */
	ptr = AK_SkipBytes(ptr, &remainder, tmpLength);

	/* Export the AK Configuration */
//	tmpLength = remainder;
//	result = ExportConfig(pInputArgs->pConfig, ptr, &tmpLength);
//	if (result != UAF_CMD_STATUS_OK)
//	{
////		PRINT_ERROR("Register: ExportConfig failed.");
//        NSLog(@"%s", "Register: ExportConfig failed.");
//		goto finalize;
//	}

//	ptr = AK_SkipBytes(ptr, &remainder, tmpLength);
    
	*pResponseLength = (ak_word_t)(ptr - pResponse);
//	PRINT_INFO("Register has succcessfully finished.");
    NSLog(@"%s","Register has succcessfully finished.");
    
    
finalize:
	if (NULL != authPubKey.pPubKey) 
	{
		free(authPubKey.pPubKey);
	}
    
    if (NULL !=  pInputArgs->finalChallenge.pData)
    {
        free( pInputArgs->finalChallenge.pData);
        pInputArgs->finalChallenge.pData = NULL;
    }
    
    if (NULL != hashcopy)
    {
        free(hashcopy);
    }
    

	if (UAF_CMD_STATUS_OK != result) 
	{
		*pResponseLength = RESPONSE_HEADER_SIZE;
	}

	ptr = pResponse;
	remainder = RESPONSE_HEADER_SIZE;

	ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_REGISTER_CMD_RESP);
	ptr = AK_WriteWord(ptr, &remainder, *pResponseLength - TLV_TL_SIZE);
	ptr = AK_WriteWord(ptr, &remainder, TAG_STATUS_CODE);
	ptr = AK_WriteWord(ptr, &remainder, sizeof(ak_word_t));
	AK_WriteWord(ptr, &remainder, (ak_word_t)result);

	return UAF_CMD_STATUS_OK;
}



/**
 * Creates a UAFV1 Registration Response using provided arguments.
 *
 * @param pArgs pointer to a regResponseArgs_t structure to be exported
 * @param pUAFV1RegResponse pointer to the output reg response
 * @param pRegResponseSize pointer to where the size of the response to be stored
 */
ak_result_t CreateUAFV1RegResponse(regResponseArgs_t* pArgs,
                                   ak_byte_t *username,
                                   ak_byte_t *pUAFV1RegResponse,
                                   ak_word_t *pUAFV1RegResponseLength,
                                   cal_blob_t *additionalSignedData,
                                   ak_byte_t signedDataLen,
                                   cal_blob_t *additionalUnsignedData,
                                   ak_byte_t unsignedDataLen,
                                   NSInteger method
                                   )
{
	ak_byte_t* ptr = NULL;
	ak_word_t remainder = 0;

	ak_word_t tmpRemainder = 0;

	ak_byte_t* ptrAuthenticator = NULL;
	ak_byte_t* ptrReg = NULL;

	ak_byte_t* pKRD = NULL;

	ak_word_t krdLength = 0;
	ak_word_t respLength = 0;

	cal_blob_t Signature	= { 0 };
	cal_blob_t DataBLOB		= { 0 };

    int loopIndex = 0;

	cal_result_t calResult;

//    PRINT_TIME("CreateUAFV1RegResponse");
    NSLog(@"%s", "CreateUAFV1RegResponse\n");

	if (NULL == pArgs || NULL == pUAFV1RegResponse || NULL == pUAFV1RegResponseLength)
		return UAF_STATUS_ERR_INVALID_PARAM;

	ptr = pUAFV1RegResponse;
	remainder =  *pUAFV1RegResponseLength;

	/* Write Authenticator assertion Tag */
	ptr = AK_WriteWord(ptr, &remainder, TAG_AUTHENTICATOR_ASSERTION);
	ptrAuthenticator = ptr;
	ptr = AK_SkipBytes(ptr, &remainder, TLV_L_SIZE);

	/* Write registration assertion Tag */
	ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_REG_ASSERTION);
	ptrReg = ptr;
	ptr = AK_SkipBytes(ptr, &remainder, TLV_L_SIZE);

	/* Calculate the size of KRD */
    krdLength = TLV_TL_SIZE				/* KRD Tag and Length */
			+ TLV_TL_SIZE + AAID_SIZE	/* AAID */ 
			+ TLV_TL_SIZE				/* Assertion Info Tag and Length*/
			+ sizeof(ak_byte_t) + sizeof(ak_word_t) * 3 /* version, mode, sigAlg, key format */
			+ TLV_TL_SIZE + (ak_word_t)pArgs->pFinalChallenge->length	/* FinalChallenge */
			+ TLV_TL_SIZE + (ak_word_t)pArgs->keyID.length				/* KeyID */
			+ TLV_TL_SIZE + sizeof(ak_dword_t) * 2						/* Counters */
			+ TLV_TL_SIZE + (ak_word_t)pArgs->uauthPub.length			/* Public Key */;
    /* calcuate size of additional signed data and add to krd length.*/
    for (loopIndex =0; loopIndex < signedDataLen; loopIndex++) {
        krdLength += additionalSignedData[loopIndex].length;
    }
	respLength = krdLength;
    pKRD = ptr;

	/* Write KRD Tag and Length */
	ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_KRD);
	ptr = AK_WriteWord(ptr, &remainder, krdLength - TLV_TL_SIZE);
	
	/* Write TAG_AAID */
	ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_AAID, pArgs->pAAID, AAID_SIZE);

//	PRINT_INFO("authenticatorVersion for REGISTER command: %04x", pArgs->authenticatorVersion);
    
	/* Write TAG_ASSERTION_INFO */
    
    pArgs->signatureAlgAndEncoding = 1;
	ptr = AK_WriteWord(ptr, &remainder, TAG_ASSERTION_INFO);
	ptr = AK_WriteWord(ptr, &remainder, sizeof(ak_byte_t) + sizeof(ak_word_t) * 3);
	ptr = AK_WriteWord(ptr, &remainder, pArgs->authenticatorVersion); //Authnr Version
	ptr = AK_WriteBytes(ptr, &remainder, (ak_byte_t*)&pArgs->authenticationMode, sizeof(ak_byte_t));
	ptr = AK_WriteWord(ptr, &remainder, pArgs->signatureAlgAndEncoding); // Signature Alg
	ptr = AK_WriteWord(ptr, &remainder, pArgs->publicKeyAlgAndEncoding); // Public key format

	/* Write FinalChallenge */
//	ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_FINAL_CHALLENGE, 
//		pArgs->pFinalChallenge->pData, (ak_word_t)pArgs->pFinalChallenge->length);
        ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_FINAL_CHALLENGE,
                           pArgs->pFinalChallenge->pData, (ak_word_t)pArgs->pFinalChallenge->length);

	/* Write TAG_KeyID */
	ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_KEYID, 
		pArgs->keyID.pData, (ak_word_t)pArgs->keyID.length);

	/* Write TAG_COUNTERS */
	ptr = AK_WriteWord(ptr, &remainder, TAG_COUNTERS);
	ptr = AK_WriteWord(ptr, &remainder, sizeof(ak_dword_t) * 2);
	ptr = AK_WriteDWord(ptr, &remainder, pArgs->signCounter); // SignCounter
	ptr = AK_WriteDWord(ptr, &remainder, pArgs->regCounter); // RegCounter

	/* Write TAG_PUB_KEY */
	ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_PUB_KEY, 
		pArgs->uauthPub.pData , (ak_word_t)(pArgs->uauthPub.length));

    /* Additional signed data */
    if (signedDataLen > 0 && additionalSignedData != 0) {
        for(loopIndex = 0; loopIndex < signedDataLen ; loopIndex++) {
            ptr = AK_WriteBytes(ptr, &remainder, additionalSignedData[loopIndex].pData, additionalSignedData[loopIndex].length);
        }
    }

	/* Check CAL global pointer */
    Signature.length = 64;
	if(TAG_ATTESTATION_BASIC_FULL == pArgs->attestationType)
	{
		/* Write TAG_ATTESTATION_BASIC_FULL */
		ptr = AK_WriteWord(ptr, &remainder, TAG_ATTESTATION_BASIC_FULL);
		ptr = AK_WriteWord(ptr, &remainder, 
			(ak_word_t)(TLV_TL_SIZE*2 + Signature.length + pArgs->pAttestationCertificate->length));
	}
	else if(TAG_ATTESTATION_BASIC_SURROGATE == pArgs->attestationType)
//    else if(TAG_ATTESTATION_BASIC_SURROGATE == 0x3E08)
	{
		/* Write TAG_ATTESTATION_BASIC_SURROGATE */
		ptr = AK_WriteWord(ptr, &remainder, TAG_ATTESTATION_BASIC_SURROGATE);
		ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)(TLV_TL_SIZE + Signature.length));
	}
	else
	{
//		PRINT_ERROR("CreateUAFV1RegResponse: attestation type is not supported.");
        NSLog(@"%s", "CreateUAFV1RegResponse: attestation type is not supported.");
        return UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED;
	}
    
    
    /* Write TAG_ATTESTATION_TYPE */
//    ptr = AK_WriteWord(ptr, &remainder, TAG_ATTESTATION_TYPE);
//    ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)Signature.length + 4);
//    
////    unsigned char temp[3] = "\0";
////    temp[0] =pArgs->attestationType / 256;
////    temp[1] =pArgs->attestationType % 256;
////    ptr = AK_WriteBytes(ptr, &remainder, temp, (ak_word_t)sizeof(unsigned short));
    
    

	/* Write TAG_SIGNATURE */
	ptr = AK_WriteWord(ptr, &remainder, TAG_SIGNATURE);
	ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)Signature.length);

	/* Calculate KRD signature and write it to the output */
	DataBLOB.pData = (cal_byte_t*)pKRD;
	DataBLOB.length = (cal_dword_t)krdLength;
	Signature.pData = (cal_byte_t*)ptr;

	ptr = AK_SkipBytes(ptr, &remainder, (ak_word_t)Signature.length);
	if (NULL == ptr)
	{
//		PRINT_ERROR("CreateUAFV1RegResponse: response buffer[%u] is too small.", *pUAFV1RegResponseLength);
        NSLog(@"CreateUAFV1RegResponse: response buffer[%u] is too small.%ld", *pUAFV1RegResponseLength);
		return UAF_STATUS_ERR_BUFFER_SMALL;
	}

//	calResult = gpCAL->CAL_Sign(pArgs->hAttestationKey, &DataBLOB, &Signature);
    
     NSLog(@"%s", " before CreateUAFV1RegResponse_getHashBytes\n");
    uint8_t signature[1024];
    memset(signature, 0x0, sizeof(signature));
    size_t signatureLength = sizeof(signature);
    uint8_t digestData[256];
    memset(digestData, 0x0, sizeof(digestData));
    size_t digestLength = sizeof(digestData);
    memcpy(digestData, DataBLOB.pData, DataBLOB.length);
    

    
    
   uint8_t *hash =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:digestData length:DataBLOB.length];
    
//    uint8_t *hash =  [[gmrz_jv_ecc_cal_ext sharedManager] getSHA1Bytesext:digestData length:DataBLOB.length];
//     uint8_t *hash =  [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:"thisis" length:6];
    
    NSLog(@"%s", " after CreateUAFV1RegResponse_getHashBytes\n");

    

    NSMutableString *hexString = [NSMutableString string];
    for (int i=0; i < 9; i++)
    {
        [hexString appendFormat:@"%c", pArgs->pAAID[i]];
    }

    
    
    calResult = [[gmrz_jv_ecc_cal_ext sharedManager] useKeyAsyncSign:privatekeyid pubId:publickeyid trancationtext:NULL serviceId:hexString
                                                           accountId:[NSString stringWithCString:username encoding:NSUTF8StringEncoding] digestData:hash digestLength:32 signature:signature signatureLength:&signatureLength method:method methods:@"reg"];
    
    free(hash);
    if (calResult == -128)
    {
        //		PRINT_ERROR("CreateUAFV1RegResponse: failed to get signature.");
        NSLog(@"CreateUAFV1RegResponse: failed to get signature.");
        return CAL_ERR_CANCELED;
    }else if (CAL_SUCCESS != calResult &&calResult != 128)
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
    
    
//    if (CAL_SUCCESS != [[gmrz_jv_ecc_cal_ext sharedManager] useKeyAsyncVerify:@"123" pubId:@"234"  digestData:hash digestLength:32 signature:signature signatureLength:signatureLength])
//    {
//        
//        NSLog(@"CreateUAFV1RegResponse: failed to get signature.");
//        return calResult == CAL_ERR_CANCELED ? UAF_CMD_STATUS_USER_CANCELLED : UAF_CMD_STATUS_ERR_UNKNOWN;
//    }
    
//    unsigned char test[65];
//    memset(test, 0x0, 65);
//    memcpy(test + 32, signature, 32);
//    memcpy(test, signature + 32, 32);
//    
    memcpy(Signature.pData, rawstr, 64);

	if(TAG_ATTESTATION_BASIC_FULL == pArgs->attestationType)
	{
		/* Write TAG_ATTESTATION_CERT */
		ptr = AK_WriteWord(ptr, &remainder, TAG_ATTESTATION_CERT);
		ptr = AK_WriteWord(ptr, &remainder, (ak_word_t)pArgs->pAttestationCertificate->length);
		ptr = AK_WriteBytes(ptr, &remainder, pArgs->pAttestationCertificate->pData, (ak_word_t)pArgs->pAttestationCertificate->length);
	}

	// Check ptr before updating tag sizes
	if (NULL == ptr)
	{
//		PRINT_ERROR("CreateUAFV1RegResponse: response buffer[%u] is too small.", *pUAFV1RegResponseLength);
        NSLog(@"CreateUAFV1RegResponse: response buffer[%u] is too small.");
		return UAF_STATUS_ERR_BUFFER_SMALL;
	}

	/* Calculate the size of TAG_UAFV1_REG_ASSERTION */
	respLength += (ak_word_t)(TLV_TL_SIZE * 2 + Signature.length);
	if(TAG_ATTESTATION_BASIC_FULL == pArgs->attestationType)
	{
		/* For TAG_ATTESTATION_BASIC_FULL add TAG_ATTESTATION_CERT TLV size */
		respLength += (ak_word_t)(TLV_TL_SIZE + (ak_word_t)pArgs->pAttestationCertificate->length);
	}
	tmpRemainder = sizeof(ak_word_t);
	AK_WriteWord(ptrReg, &tmpRemainder, respLength);

	/* Write the size of TAG_AUTHENTICATOR_ASSERTION */
	respLength += TLV_TL_SIZE;
	tmpRemainder = sizeof(ak_word_t);
	AK_WriteWord(ptrAuthenticator, &tmpRemainder, respLength);
	
	/* Append the key handle */
//	AK_WriteTlvBytes(ptr, &remainder, TAG_KEYHANDLE, (ak_byte_t *)pArgs->keyHandle.pData, (ak_word_t)pArgs->keyHandle.length);
//	respLength += TLV_TL_SIZE + (ak_word_t)pArgs->keyHandle.length;

	if (NULL == ptr)
	{
//		PRINT_ERROR("CreateUAFV1RegResponse: response buffer[%u] is too small.", *pUAFV1RegResponseLength);
        
        NSLog(@"CreateUAFV1RegResponse: response buffer[%u] is too small. %d", *pUAFV1RegResponseLength);
		return UAF_STATUS_ERR_BUFFER_SMALL;
	}

	/* Get the size of the command response*/
	*pUAFV1RegResponseLength = TLV_TL_SIZE + respLength;
    
//    PRINT_TIME("CreateUAFV1RegResponse finishing");
    NSLog(@"CreateUAFV1RegResponse finishing\n");
    return UAF_CMD_STATUS_OK;
}



ak_dword_t freeGetInfoData(authenticatorInfo_t **pList, int list_count)
{
    if (!pList) {
        NSLog(@"plist is null");
        return -1;
    }
    
    
    for (int index = 0; index < list_count; index++) {
        free(pList[index]);
//        (*pList + index) = NULL;
    }
   
    *pList = NULL;
    return 0;
}

