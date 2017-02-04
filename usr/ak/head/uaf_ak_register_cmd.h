/* Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved. */

#ifndef uaf_ak_uaf_ak_register_cmd_h
#define uaf_ak_uaf_ak_register_cmd_h

/**
 * @param pAKInfo [IN] pointer to a structure containing internal AK info
 * @param pInputArgs [IN] pointer to a structure containing the parsed AK request
 * @param pResponse [IN/OUT] A buffer where the response must be written. This buffer must be allocated by the caller.
 * @param pResponseLength [OUT] Length of the response [Rolf: [IN/OUT] size of pResponse oin input, length of written data on
 output
 *
 * @return UAF_STATUS_OK if no errors occurred.
 */

/** TODO: HIGHLY RECOMMENDED: pResponseLength SHOULD be set to available length input!
 This *pResponseLength on input needs to be verified in each of the functions below
 Note: don't assume that only friendly ASMs will call our AK!  Even on rooted phones when called by ASM malware, the AK MUST work properly!
 */

ak_result_t Register( authenticatorInfo_t *pAKInfo,
                     ak_dword_t  pAKInfoCount,
                     input_args_t *pInputArgs,
                     ak_byte_t *pResponse,
                     ak_word_t *pResponseLength,
                     NSInteger method);



ak_dword_t freeGetInfoData(authenticatorInfo_t **pList, int list_count);
#endif
