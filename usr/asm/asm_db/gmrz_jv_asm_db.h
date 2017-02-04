//
//  gmrz_jv_asm_db.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/10.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface gmrz_jv_asm_db : NSObject

+ (OSStatus)gmrz_jv_asm_DBin:(NSString *)serviceId
                   counterIn:(NSString *)counterIn
                   DB_dataIn:(NSString *)DB_dataIn;


+ (OSStatus)gmrz_jv_asm_DB_Query:(NSString *)serviceId
                       counterIn:(NSString *)counterIn
                       DB_dataIn:(NSString **)DB_dataIn;

+ (OSStatus)gmrz_jv_asm_DB_Delete:(NSString *)serviceId
                        counterIn:(NSString *)counterIn;

+ (void)gmrz_jv_addSignCounter:(NSString *)SignCounter;
+ (NSString *)gmrz_jv_suchSignCounter:(NSString *)SignCounter;
+ (void)gmrz_jv_changeSignCounter:(NSString *)SignCounter;
@end
