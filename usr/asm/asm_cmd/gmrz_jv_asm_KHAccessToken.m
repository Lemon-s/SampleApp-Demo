//
//  gmrz_jv_asm_KHAccessToken.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/2.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_jv_asm_KHAccessToken.h"

#import "gmrz_jv_asm_json_parse.h"
#import "gmrz_jv_ecc_cal_ext.h"

@implementation gmrz_jv_asm_KHAccessToken


+(NSInteger) getKHAccessToken:(uint8_t **) KHAccessData  jsonin:(NSString *)jsonin
{
    NSDictionary *dicout ;
    
    int status = [gmrz_jv_asm_json_parse getHAccessTokenFillItem:jsonin dicOut:&dicout];
    
    if (status != 0) {
        return status;
    }
  
    
    //appid
    NSString *HKAccess =  [dicout valueForKeyPath:@"args.appID"];
    //ponsonal id
    HKAccess = [ HKAccess stringByAppendingString:[dicout valueForKeyPath:@"args.username"]];
    //asmtoken
    int asmtoken = [gmrz_jv_asm_json_parse getRandomNumber:1000 to:9999];
    //asmtokehash = (hash256)asmtoken
    uint8_t ramdstr[512] ;
    memset(ramdstr, 0x0, sizeof(ramdstr));
    unsigned long randrom = arc4random() % (0xEEEEEEEE + 1); //真随机数
    ramdstr[0] = randrom / 256 * 256 * 256;
    ramdstr[1] = randrom / 256 * 256;
    ramdstr[2] = randrom / 256;
    ramdstr[3] = randrom % 256;
    
    
    
    
    uint8_t * asmtokenhash = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:ramdstr length:4];
    
    
    
    //callerID
    HKAccess = [ HKAccess stringByAppendingString:[self getBundleId]];
    
    memset(ramdstr, 0x0, sizeof(ramdstr));
    memcpy(ramdstr, asmtokenhash, 32);
    if (asmtokenhash) {
        free(asmtokenhash);
    }
    
    
    if (HKAccess.length + 32  >= 511) {
         memcpy(ramdstr + 32 , [HKAccess UTF8String],511 - 32);
    }
    else
        memcpy(ramdstr + 32 , [HKAccess UTF8String], HKAccess.length);

    
    uint8_t * temp_KHAccessData = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:ramdstr length:(2 + HKAccess.length)];
   
    * KHAccessData = temp_KHAccessData;
    if (!(* KHAccessData)) {
        return  KHACCESSTOKEN_CAL_FAILED;
    }
    
    NSInteger temp_outlength = 32;
    

    return KHACCESSTOKEN_CAL_SUCCESS;
}


+(NSString *) getBundleId
{
    return [[NSBundle mainBundle] bundleIdentifier];
}


@end
