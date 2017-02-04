//
//  gmrz_jv_asm_json_parse.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/3.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>



#define PARSEJSONDATA_SUCCESS 0
#define PARSEJSONDATA_FAILD -1020

@interface gmrz_jv_asm_json_parse : NSObject

+(NSInteger )getHAccessTokenFillItem:(NSString *)JsonPullin dicOut:(NSDictionary **)dicOut;
+(int)getRandomNumber:(int)from to:(int)to;
@end
