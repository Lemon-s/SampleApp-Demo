//
//  gmrz_client_getfinalchallenge.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/5.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface gmrz_client_getfinalchallenge : NSObject

+(NSInteger) getFanilchallage:(NSString *)appID
                    challenge:(NSString *)challenge
                finalchallage:(NSString ** ) finalchallage;

@end
