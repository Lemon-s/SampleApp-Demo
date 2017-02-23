//
//  ak_getinfo.h
//  TestAkcmd
//
//  Created by Lyndon on 16/6/9.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#ifndef ak_getinfo_h
#define ak_getinfo_h

#include "uaf_ak_tlv.h"

ak_result_t AuthenticatorInfoInit(authenticatorInfo_t** pAKInfo,
                                  ak_word_t * count);



//ak_result_t GetInfo(authenticatorInfo_t *pAKInfo,
//                    input_args_t *pInputArgs,
//                    ak_byte_t *pResponse,
//                    ak_word_t *pResponseLength);


ak_result_t GetInfoExt(authenticatorInfo_t *pAKInfo[32],
                    input_args_t *pInputArgs,
                    ak_byte_t *pResponse,
                    ak_word_t *pResponseLength);
#endif /* ak_getinfo_h */
