/**
 * Copyright (C) 2014-2015, Nok Nok Labs, Inc. All rights reserved.
 *
 * @file:			uaf_ak_token_verifier.h
 ***************************************************************************************
 * Functions to verify various types of token, including User Verification Token (UVT)
 * and Transaction Confirmation Token (TCT)
 * Version:			0.1
 */
#ifndef UAF_AK_TOKEN_VERIFIER_H
#define UAF_AK_TOKEN_VERIFIER_H

#include "uaf_ak_defs.h"
#include "uaf_ak_tlv.h"


/*
 * Verify the transaction confirmation token during secure transaction
 * @param pInfo[IN] pointer to the input
 */
ak_result_t VerifyTCT(input_args_t *pInfo);

#endif