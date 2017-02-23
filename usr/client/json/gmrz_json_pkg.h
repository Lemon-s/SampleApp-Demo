//
//  gmrz_json_pkg.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/5.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>



@interface gmrz_json_pkg : NSObject

//+(NSInteger )gmrz_parse_json:(NSString *)JsonPullin dicOut:(NSDictionary **)dicOut;

+(NSInteger )gmrz_pkg_json_finalchallage:(NSString *)appID
                               challenge:(NSString *)challenge
                           finalchallage:(NSString ** ) finalchallage;
+(NSInteger )gmrz_pkg_json_client2asm:(NSString *)JsonPullin Jsonout:(NSString **)JsonOut dicOut:(NSMutableDictionary **)dicOut;

+(NSInteger )gmrz_pkg_authjson_client2asm:(NSString *)JsonPullin username:(NSString *)username Jsonout:(NSString **)JsonOut dicOut:(NSMutableDictionary **)dicOut;
@end
