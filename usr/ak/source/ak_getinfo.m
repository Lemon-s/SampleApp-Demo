//
//  ak_getinfo.m
//  TestAkcmd
//
//  Created by Lyndon on 16/6/9.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "akDefs.h"

#include "uaf_ak_defs.h"
#include "gmrz_ak_authenticator.h"
#include "uaf_ak_tlv.h"


#define BLURT printf ("This is line %d of file %s (function %s)\n",\
__LINE__, __FILE__, __func__)


/**
 * Process getInfo request and output getInfo response
 *
 * @param pAKInfo [IN]				pointer to a structure containing internal AK info
 *
 */
ak_result_t AuthenticatorInfoInit(authenticatorInfo_t** pAKInfo, ak_result_t * count)
{
    
    
    //authenticatorInfo index 0
    
    
    pAKInfo[*count] = (authenticatorInfo_t *)malloc(sizeof(authenticatorInfo_t));
    //init aaid
    memcpy((ak_byte_t *)(*pAKInfo[*count]).aaid, "4e4e#4005", AAID_SIZE);
    
    //init metadata
    (*pAKInfo[*count]).metadata.authenticatorType = UAF_TYPE_BASIC_AUTHNR;
    (*pAKInfo[*count]).metadata.maxKeyHandle = 0x01;
    (*pAKInfo[*count]).metadata.userVerification = USER_VERIFY_PRESENCE;
    (*pAKInfo[*count]).metadata.keyProtection = KEY_PROTECTION_HARDWARE;
    (*pAKInfo[*count]).metadata.matcherProtection = MATCHER_PROTECTION_TEE;
    (*pAKInfo[*count]).metadata.tcDisplay = TC_DISPLAY_ANY;
    (*pAKInfo[*count]).metadata.authenticationAlg = UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW;

    //init scheme
    memcpy((ak_byte_t *)(*pAKInfo[*count]).scheme, "UAFV1TLV", ASSERTION_SCHEME_SIZE);
    (*pAKInfo[*count]).attestationType = TAG_ATTESTATION_BASIC_SURROGATE;
    
    (*count)++;
    
    
    
    //authenticatorInfo index 1
    
    pAKInfo[*count] = (authenticatorInfo_t *)malloc(sizeof(authenticatorInfo_t));
    //init aaid
    memcpy((ak_byte_t *)(*pAKInfo[*count]).aaid, "4e4e#400a", AAID_SIZE);
    
    //init metadata
    (*pAKInfo[*count]).metadata.authenticatorType = UAF_TYPE_BASIC_AUTHNR;
    (*pAKInfo[*count]).metadata.maxKeyHandle = 0x01;
    (*pAKInfo[*count]).metadata.userVerification = USER_VERIFY_PRESENCE;
    (*pAKInfo[*count]).metadata.keyProtection = KEY_PROTECTION_SECURE_ELEMENT;
    (*pAKInfo[*count]).metadata.matcherProtection = MATCHER_PROTECTION_ON_CHIP;
    (*pAKInfo[*count]).metadata.tcDisplay = TC_DISPLAY_ANY;
    (*pAKInfo[*count]).metadata.authenticationAlg = UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW;
    
    //init scheme
    memcpy((ak_byte_t *)(*pAKInfo[*count]).scheme, "UAFV1TLV", sizeof(ASSERTION_SCHEME_SIZE));
    (*pAKInfo[*count]).attestationType = TAG_ATTESTATION_BASIC_SURROGATE;
    
    (*count)++;
    
    
    //authenticatorInfo index 2
    pAKInfo[*count] = (authenticatorInfo_t *)malloc(sizeof(authenticatorInfo_t));
    //init aaid
    memcpy((ak_byte_t *)(*pAKInfo[*count]).aaid, "4e4e#400b", AAID_SIZE);
    
    //init metadata
    (*pAKInfo[*count]).metadata.authenticatorType = UAF_TYPE_BASIC_AUTHNR;
    (*pAKInfo[*count]).metadata.maxKeyHandle = 0x01;
    (*pAKInfo[*count]).metadata.userVerification = USER_VERIFY_PRESENCE;
    (*pAKInfo[*count]).metadata.keyProtection = KEY_PROTECTION_SECURE_ELEMENT;
    (*pAKInfo[*count]).metadata.matcherProtection = MATCHER_PROTECTION_ON_CHIP;
    (*pAKInfo[*count]).metadata.tcDisplay = TC_DISPLAY_ANY;
    (*pAKInfo[*count]).metadata.authenticationAlg = UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW;
    
    //init scheme
    memcpy((ak_byte_t *)(*pAKInfo[*count]).scheme, "UAFV1TLV", sizeof(ASSERTION_SCHEME_SIZE));
    (*pAKInfo[*count]).attestationType = TAG_ATTESTATION_BASIC_SURROGATE;
    
    (*count)++;
    
    
    //authenticatorInfo index 3
    pAKInfo[*count] = (authenticatorInfo_t *)malloc(sizeof(authenticatorInfo_t));
    //init aaid
    memcpy((ak_byte_t *)(*pAKInfo[*count]).aaid, "4e4e#4009", AAID_SIZE);
    
    //init metadata
    (*pAKInfo[*count]).metadata.authenticatorType = UAF_TYPE_BASIC_AUTHNR;
    (*pAKInfo[*count]).metadata.maxKeyHandle = 0x01;
    (*pAKInfo[*count]).metadata.userVerification = USER_VERIFY_PRESENCE;
    (*pAKInfo[*count]).metadata.keyProtection = KEY_PROTECTION_SECURE_ELEMENT;
    (*pAKInfo[*count]).metadata.matcherProtection = MATCHER_PROTECTION_ON_CHIP;
    (*pAKInfo[*count]).metadata.tcDisplay = TC_DISPLAY_ANY;
    (*pAKInfo[*count]).metadata.authenticationAlg = UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW;
    
    //init scheme
    memcpy((ak_byte_t *)(*pAKInfo[*count]).scheme, "UAFV1TLV", sizeof(ASSERTION_SCHEME_SIZE));
    (*pAKInfo[*count]).attestationType = TAG_ATTESTATION_BASIC_SURROGATE;
    
    (*count)++;
    
    return UAF_CMD_STATUS_OK;
}




/**
 * Process getInfo request and output getInfo response
 *
 * @param pAKInfo [IN]				pointer to a structure containing internal AK info
 * @param pInputArgs [IN]			pointer to a structure containing the parsed AK request
 * @param pResponse [IN/OUT]		A buffer where the response must be written.
 *									This buffer must be allocated by the caller.
 * @param pResponseLength [IN/OUT]	Length of the response
 */
ak_result_t GetInfoExt(authenticatorInfo_t *pAKInfo[32], input_args_t* pInputArgs,
                    ak_byte_t* pResponse, ak_word_t* pResponseLength)
{
    ak_result_t result = UAF_CMD_STATUS_OK;
    ak_result_t count = 0;
    authenticatorInfo_t *authinfo[MAX_AUTHENTICATORS_NUM] = {0};
    
    ak_byte_t* ptr = NULL;
    ak_word_t remainder = 0;
    
    ak_word_t index = 0;
    ak_word_t infoLength = 0;
    ak_word_t metadataLength = 0;
   // PRINT_TIME("GetInfo");
    printf ("This is line %d of file %s (function %s) operation: %s\n", __LINE__, __FILE__, __func__, "GetInfo");
    
    if (NULL == pAKInfo || NULL == pInputArgs || NULL == pResponse || NULL == pResponseLength)
        return UAF_STATUS_ERR_INVALID_PARAM;
    
    if (*pResponseLength < RESPONSE_HEADER_SIZE)
    {
        //PRINT_ERROR("GetInfo: response buffer[%u] is too small.", *pResponseLength);
        printf ("This is line %d of file %s (function %s) operation: GetInfo: response buffer[%u] is too small.\n", __LINE__, __FILE__, __func__, *pResponseLength);
        return UAF_STATUS_ERR_BUFFER_SMALL;
    }
    
    // Calculate the value length of TAG_AUTHENTICATOR_METADATA
    metadataLength = sizeof(ak_word_t)  // AuthenticatorType
    + sizeof(ak_byte_t)  // MaxKeyHandles
    + sizeof(ak_dword_t) // UserVerification
    + sizeof(ak_word_t)  // KeyProtection
    + sizeof(ak_word_t)  // MatcherProtection
    + sizeof(ak_word_t)  // TransactionConfirmationDisplay
    + sizeof(ak_word_t); // AuthenticationAlg
    
    // Calculate the value length of TAG_AUTHENTICATOR_INFO
    infoLength = TLV_TL_SIZE + sizeof(ak_byte_t)		// TAG_AUTHENTICATOR_INDEX
    + TLV_TL_SIZE + AAID_SIZE				// TAG_AAID
    + TLV_TL_SIZE + metadataLength			// TAG_AUTHENTICATOR_METADATA
    + TLV_TL_SIZE + ASSERTION_SCHEME_SIZE	// TAG_ASSERTION_SCHEME
    + TLV_TL_SIZE + sizeof(ak_word_t);		// TAG_ATTESTATION_TYPE
    
    // Skip header for now
    ptr = pResponse + RESPONSE_HEADER_SIZE;
    remainder = *pResponseLength - RESPONSE_HEADER_SIZE;
    
    // TAG_API_VERSION
    ptr = AK_WriteTlvByte(ptr, &remainder, TAG_API_VERSION, 1);
    
    
    
    result = AuthenticatorInfoInit(&authinfo, &count);
    
    if (result == 0) {
        for (int i = 0; i < count; i++) {
            pAKInfo[i]  = authinfo[i];
        }
    }
    
    
   // for (index = 0; index < pAKInfo->authenticators.num; index++)
    for (index = 0; index < count; index++)
    {
        authenticatorInfo_t* pInfo = NULL;
//        result = pAKInfo->authenticators.items[index].GetInfo(index, &pInfo);
        pInfo = authinfo[index];
        if (UAF_CMD_STATUS_OK != result)
        {
           // PRINT_ERROR("GetInfo: failed GetInfo of authenticators[%u].", index);
            printf ("This is line %d of file %s (function %s) operation: GetInfo: failed GetInfo of authenticators[%u].\n", __LINE__, __FILE__, __func__, index);
            result = UAF_CMD_STATUS_ERR_UNKNOWN;
            goto finalize;
        }
        
        // TAG_AUTHENTICATOR_INFO
        ptr = AK_WriteWord(ptr, &remainder, TAG_AUTHENTICATOR_INFO);
        ptr = AK_WriteWord(ptr, &remainder, infoLength);
        
        // TAG_AUTHENTICATOR_INDEX
        ptr = AK_WriteTlvByte(ptr, &remainder, TAG_AUTHENTICATOR_INDEX, (ak_byte_t)index);
        
        // TAG_AAID
        ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_AAID, pInfo->aaid, AAID_SIZE);
        
        // TAG_AUTHENTICATOR_METADATA
        ptr = AK_WriteWord(ptr, &remainder, TAG_AUTHENTICATOR_METADATA);
        ptr = AK_WriteWord(ptr, &remainder, metadataLength);
        // We write metadata members one by one because some members (userVerification and authenticationAlg)
        // are larger than one byte. We don't assume the byte order of the platform, so we use WriteDword/Writeword
        // to take care of the underlying byte order
        ptr = AK_WriteWord(ptr, &remainder, pInfo->metadata.authenticatorType);		// AuthenticatorType
        ptr = AK_WriteByte(ptr, &remainder, pInfo->metadata.maxKeyHandle);			// MaxKeyHandle
        ptr = AK_WriteDWord(ptr, &remainder, pInfo->metadata.userVerification);		// UserVerification
        ptr = AK_WriteWord(ptr, &remainder, pInfo->metadata.keyProtection);			// KeyProtection
        ptr = AK_WriteWord(ptr, &remainder, pInfo->metadata.matcherProtection);		// MatcherProtection
        ptr = AK_WriteWord(ptr, &remainder, pInfo->metadata.tcDisplay);				// TransactionConfirmationDisplay
        ptr = AK_WriteWord(ptr, &remainder, pInfo->metadata.authenticationAlg);		// AuthenticationAlg
        
        // TAG_ASSERTION_SCHEME
        ptr = AK_WriteTlvBytes(ptr, &remainder, TAG_ASSERTION_SCHEME, pInfo->scheme, ASSERTION_SCHEME_SIZE);
        
        // TAG_ATTESTATION_TYPE
        ptr = AK_WriteTlvWord(ptr, &remainder, TAG_ATTESTATION_TYPE, pInfo->attestationType);
        
        if (NULL == ptr)
        {
//            PRINT_ERROR("GetInfo: response buffer[%u] is too small.", *pResponseLength);
            printf ("This is line %d of file %s (function %s) operation: GetInfo: response buffer[%u] is too small.\n", __LINE__, __FILE__, __func__, *pResponseLength);
            result = UAF_STATUS_ERR_BUFFER_SMALL;
            goto finalize;
        }
    }
//    PRINT_TIME("GetInfo done");
    printf ("This is line %d of file %s (function %s) operation: %s: \n", __LINE__, __FILE__, __func__, "GetInfo done");
    
finalize:
    *pResponseLength = (UAF_CMD_STATUS_OK == result) ? (ak_word_t)(ptr - pResponse) : RESPONSE_HEADER_SIZE;
    
    ptr = pResponse;
    remainder = *pResponseLength;
    
    ptr = AK_WriteWord(ptr, &remainder, TAG_UAFV1_GETINFO_CMD_RESP);
    ptr = AK_WriteWord(ptr, &remainder, *pResponseLength - TLV_TL_SIZE);
    AK_WriteTlvWord(ptr, &remainder, TAG_STATUS_CODE, (ak_word_t)result);
    
//    PRINT_INFO("GetInfo: result=0x%X ResponseLength=%u", result, *pResponseLength);
    
    
    printf ("This is line %d of file %s (function %s) operation: GetInfo: result=0x%X ResponseLength=%u: \n", __LINE__, __FILE__, __func__, result, *pResponseLength);
    return UAF_CMD_STATUS_OK;
}
