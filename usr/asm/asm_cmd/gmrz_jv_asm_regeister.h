//
//  gmrz_jv_asm_regeister.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/3.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface gmrz_jv_asm_regeister : NSObject


@property (nonatomic, copy) NSString *appID;
@property (nonatomic, copy) NSString *userName;
@property (nonatomic, copy) NSString *finalChallenge;
@property (nonatomic, assign) unsigned short attestationType;


@end
