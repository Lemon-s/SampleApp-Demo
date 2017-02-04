//
//  gmrz_jv_asm_json_parse.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/3.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_jv_asm_json_parse.h"

@implementation gmrz_jv_asm_json_parse


+(NSInteger )getHAccessTokenFillItem:(NSString *)JsonPullin dicOut:(NSDictionary **)dicOut

{
   
    

    
    if (JsonPullin == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSData *jsonData = [JsonPullin dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers
                                                          error:&err];
    *dicOut = [dic mutableCopy];
    

    if(err) {
        NSLog(@"json解析失败：%@",err);
        return PARSEJSONDATA_FAILD;
    }

    return PARSEJSONDATA_SUCCESS;
}



+(int)getRandomNumber:(int)from to:(int)to;
{
    return (int)(from + (arc4random() % (to - from + 1)));
}


@end
