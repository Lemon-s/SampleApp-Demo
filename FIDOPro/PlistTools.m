//
//  PlistTools.m
//  FIDOPro
//
//  Created by 张宁 on 16/8/2.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "PlistTools.h"

@implementation PlistTools
+ (NSString *)readPlist:(NSString *)key {
    
    NSString *plistPath = [[NSBundle mainBundle]pathForResource:@"urlinfo" ofType:@"plist"];
    NSMutableDictionary *dict = [[NSMutableDictionary alloc]initWithContentsOfFile:plistPath];
    NSMutableDictionary *url = [dict valueForKey:@"url"];
    NSString * str = [url objectForKey:key];
    
    return str;
    
}
@end
