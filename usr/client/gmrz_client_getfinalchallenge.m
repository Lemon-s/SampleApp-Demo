//
//  gmrz_client_getfinalchallenge.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/5.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_client_getfinalchallenge.h"
#import "gmrz_json_pkg.h"
#import "gmrz_jv_util_func.h"
#import "gmrz_jv_ecc_cal_ext.h"

@implementation gmrz_client_getfinalchallenge

+(NSInteger) getFanilchallage:(NSString *)appID
                    challenge:(NSString *)challenge
                finalchallage:(NSString ** ) finalchallage
{
    NSString *tempfinalchallage = nil;
    [gmrz_json_pkg gmrz_pkg_json_finalchallage:appID challenge:challenge finalchallage:&tempfinalchallage];
    
    
//     *finalchallage = [[gmrz_jv_ecc_cal_ext sharedManager] getHashBytesext:[tempfinalchallage UTF8String]];
    *finalchallage = [[gmrz_jv_util_func textFromBase64StringExt:tempfinalchallage] copy];
    
    return 0;
}


@end
