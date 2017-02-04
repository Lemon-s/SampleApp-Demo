//
//  ak_util.c
//  TestAkcmd
//
//  Created by Lyndon on 16/6/28.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "uaf_ak_defs.h"
#include "uaf_ak_util.h"
#include "uaf_ak_tlv.h"
#include "gmrz_jv_ecc_cal_ext.h"


ak_result_t WrapData(const cal_blob_t* pIn, cal_blob_t* pOut)
{
    ak_result_t result = UAF_CMD_STATUS_OK;
    
    cal_handle_t wrapKey = NULL;
    cal_blob_t out = {0};
    
    
    
    
    if (NULL == pIn || NULL == pOut)
        return UAF_STATUS_ERR_INVALID_PARAM;
//    if (NULL == gpCAL)
//        return UAF_STATUS_ERR_NOTINITIALIZED;
    
//    HEX_DUMP("WrapData: Hex dump of plain data.", pIn->pData, pIn->length);
    
    // Get the wrapping key
//    if (CAL_SUCCESS != gpCAL->CAL_GetKey(CAL_KEY_WRAP, NULL, &wrapKey))
//    {
////        PRINT_ERROR("WrapData: failed to get wrapping key.");
//        printf("WrapData: failed to get wrapping key.\n");
//        return UAF_CMD_STATUS_ERR_UNKNOWN;
//    }
    
    
//    if (CAL_SUCCESS != [getSym generateSymmetricKey])
//    {
//        //        PRINT_ERROR("WrapData: failed to get wrapping key.");
//        printf("WrapData: failed to get wrapping key.\n");
//        return UAF_CMD_STATUS_ERR_UNKNOWN;
//    }
//    
  
    
    if (NULL == pOut->pData)
    {
        // Get the wrapped data size
//        if (CAL_SUCCESS != gpCAL->CAL_WrapObject(wrapKey, pIn, &out))
//        {
////            PRINT_ERROR("WrapData: failed to get wrapped object size.");
//            printf("WrapData: failed to get wrapped object size.\n");
//            result = UAF_CMD_STATUS_ERR_UNKNOWN;
//            goto cleanup;
//        }
        
            //  Wrap motify by yaozhu replace here to AES 256
        //Symmetric key use
        

//        NSData *source = [NSData dataWithBytes:pIn->pData length:pIn->length];
//        
//        NSString *symmertickey =  @SYMMETRIC_KEY;
//        NSData * encrypt = [getSym aes256_encrypt:symmertickey SourceData:source];
        
        uint8_t * pOutBuffer = NULL;
        UInt16 pOutBufferLength = 0;
        size_t status = [[gmrz_jv_ecc_cal_ext sharedManager] aes256_encrypt_ext:pIn->pData SourceDataLength:pIn->length dstData:&pOutBuffer dstDataLength:&pOutBufferLength];
        
        // Allocate a memory
        out.pData = pOutBuffer;
        out.length = pOutBufferLength;
        if (NULL == out.pData)
        {
//            PRINT_ERROR("WrapData: failed to allocate memory.");
            printf("WrapData: failed to get wrapping key.\n");
            result = UAF_CMD_STATUS_ERR_UNKNOWN;
           goto cleanup;
            
        }
        
   
        pOut->length = out.length;
        pOut->pData = out.pData;
    }
    else
    {
        
        uint8_t * pOutBuffer = NULL;
        UInt16 pOutBufferLength = 0;
        size_t status = [[gmrz_jv_ecc_cal_ext sharedManager] aes256_encrypt_ext:pIn->pData SourceDataLength:pIn->length dstData:&pOutBuffer dstDataLength:&pOutBufferLength];
        if (status != CAL_SUCCESS) {
            goto cleanup;
        }

            memcpy(pOut->pData, pOutBuffer, pOutBufferLength);
            pOut->length = pOutBufferLength;
        
    }
//    // Wrap
//    if (CAL_SUCCESS != gpCAL->CAL_WrapObject(wrapKey, pIn, pOut))
//    {
////        PRINT_ERROR("WrapData: failed to wrap object.");
//         printf("WrapData: failed to wrap object\n");
//        result = UAF_CMD_STATUS_ERR_UNKNOWN;
//        goto cleanup;
//    }
    //  Wrap motify by yaozhu replace here to AES 256
    
//    HEX_DUMP("WrapData: Hex dump of wrapped data.", pOut->pData, pOut->length);
    
cleanup:
//    gpCAL->CAL_CloseHandle(wrapKey);
    if (UAF_CMD_STATUS_OK != result)
    {
        if (NULL != out.pData)
        {
            memset(out.pData, 0, out.length);
            free(out.pData);
            
        }
    }
    
    return result;
}



ak_result_t UnwrapData(const cal_blob_t* pIn, cal_blob_t* pOut, cal_blob_t* containerID, ak_byte_t uvtFormat)
{
    ak_result_t result = UAF_CMD_STATUS_OK;
    
    cal_handle_t wrapKey = NULL;
    cal_blob_t out = {0};
    cal_bind_info_t BindInfo = { 0 };
    
//    PRINT_TIME("UnwrapData");
    printf("\nUnwrapData");
    if (NULL == pIn || NULL == pOut)
        return UAF_STATUS_ERR_INVALID_PARAM;
//    if (NULL == gpCAL)
//        return UAF_STATUS_ERR_NOTINITIALIZED;
    
//    HEX_DUMP("UnwrapData: Hex dump of wrapped data.", pIn->pData, pIn->length);
    
    // Get the wrapping key
//    if (uvtFormat == UVT_FORMAT_OTHER_TA) {
////        PRINT_INFO("UnwrapData for OTHER");
//        printf("\nUnwrapData for OTHER");
//        BindInfo.version = CAL_BIND_INFO_VERSION;
////        BindInfo.AppID = *containerID;
//        BindInfo.BindTarget = CAL_BIND_APPLICATION;
//        if (CAL_SUCCESS != gpCAL->CAL_GetKey(CAL_KEY_WRAP, &BindInfo, &wrapKey))
//        {
//            PRINT_ERROR("UnwrapData: failed to get wrapping key.");
//            result = UAF_CMD_STATUS_ERR_UNKNOWN;
//            goto cleanup;
//        }
//    } else if (uvtFormat == UVT_FORMAT_LOCAL){
//        PRINT_INFO("UnwrapData for LOCAL");
//        if (CAL_SUCCESS != gpCAL->CAL_GetKey(CAL_KEY_WRAP, NULL, &wrapKey))
//        {
//            PRINT_ERROR("UnwrapData: failed to get wrapping key.");
//            result = UAF_CMD_STATUS_ERR_UNKNOWN;
//            goto cleanup;
//        }
//    } else {
//        PRINT_ERROR("UnwrapData: Unsupported UVTFormat.");
//        result = UAF_STATUS_ERR_INVALID_PARAM;
//        goto cleanup;
//        
//    }
    
    if (NULL == pOut->pData)
    {
        // Get the unwrapped data size
        
        uint8_t * pOutBuffer = NULL;
        UInt16 pOutBufferLength = 0;
        size_t status = [[gmrz_jv_ecc_cal_ext sharedManager] aes256_decrypt_ext:pIn->pData SourceDataLength:pIn->length dstData:&pOutBuffer dstDataLength:&pOutBufferLength];
        out.pData = pOutBuffer;
        out.length = pOutBufferLength;
        
        
        if (NULL == out.pData)
        {
            //            PRINT_ERROR("WrapData: failed to allocate memory.");
            printf("\nUnwrapData: failed to get unwrapped object size.");
            result = UAF_CMD_STATUS_ERR_UNKNOWN;
            goto cleanup;
            
        }
        // Allocate a memory
//        out.pData = (cal_byte_t*)malloc(out.length);
//        if (NULL == out.pData)
//        {
////            PRINT_ERROR("UnwrapData: failed to allocate memory.");
//            printf("UnwrapData: failed to allocate memory.");
//            result = UAF_CMD_STATUS_ERR_UNKNOWN;
//            goto cleanup;
//        }
        
        pOut->length = out.length;
        pOut->pData = out.pData;
    }
    else
    {
        uint8_t * pOutBuffer = NULL;
        UInt16 pOutBufferLength = 0;
        size_t status = [[gmrz_jv_ecc_cal_ext sharedManager] aes256_decrypt_ext:pIn->pData SourceDataLength:pIn->length dstData:&pOutBuffer dstDataLength:&pOutBufferLength];
        if (status != CAL_SUCCESS) {
            printf("UnwrapData: failed to unwrap object.");
            result = UAF_CMD_STATUS_ERR_UNKNOWN;
            goto cleanup;
        }
        
        memcpy(pOut->pData, pOutBuffer, pOutBufferLength);
        pOut->length = pOutBufferLength;

    }

    
//    HEX_DUMP("UnwrapData: Hex dump of unwrapped data.", pOut->pData, pOut->length);
    
cleanup:
//    gpCAL->CAL_CloseHandle(wrapKey);
    if (UAF_CMD_STATUS_OK != result)
    {
        if (NULL != out.pData)
        {
            memset(out.pData, 0, out.length);
            free(out.pData);
            pOut->pData = NULL;
        }
    }
    printf("\n UnwrapData finishing");
//    PRINT_TIME("UnwrapData finishing");
    
    return result;
}





int CompareBlobs(const ak_byte_t* buffer1, ak_word_t length1, const ak_byte_t* buffer2, ak_word_t length2)
{
    if (NULL == buffer1 && NULL == buffer2)
        return 0;
    
    if (NULL == buffer1)
        return -1;
    
    if (NULL == buffer2)
        return 1;
    
    if (length1 < length2)
        return -1;
    
    if (length1 > length2)
        return 1;
    
    return memcmp(buffer1, buffer2, length1);
}