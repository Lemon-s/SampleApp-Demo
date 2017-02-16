//
//  gmrz_jv_asm_KHAccessToken.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/2.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>


#define KHACCESSTOKEN_CAL_SUCCESS 0
#define KHACCESSTOKEN_CAL_FAILED -1040

@interface gmrz_jv_asm_KHAccessToken : NSObject


+(NSInteger) getKHAccessToken:(unsigned char **) KHAccessData  jsonin:(NSString *)jsonin;


@end
