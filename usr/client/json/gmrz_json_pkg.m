//
//  gmrz_json_pkg.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/5.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_json_pkg.h"
#import "gmrz_client_getfinalchallenge.h"
#import "uaf_ak_defs.h"

#define PARSEJSONDATA_SUCCESS 0
#define PARSEJSONDATA_FAILD -1020



@implementation gmrz_json_pkg


//+(NSInteger )gmrz_parse_json:(NSString *)JsonPullin dicOut:(NSDictionary **)dicOut
//{
//
//    if (JsonPullin == nil) {
//        return PARSEJSONDATA_FAILD;
//    }
//    
//    NSData *jsonData = [JsonPullin dataUsingEncoding:NSUTF8StringEncoding];
//    NSError *err;
//    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
//                                                        options:NSJSONReadingMutableContainers
//                                                          error:&err];
//    *dicOut = [dic copy];
//  
//    if(err) {
//        NSLog(@"json解析失败：%@",err);
//        return PARSEJSONDATA_FAILD;
//    }
//    
//    return PARSEJSONDATA_SUCCESS;
//}


+(NSInteger )gmrz_pkg_json_finalchallage:(NSString *)appID
                               challenge:(NSString *)challenge
                           finalchallage:(NSString ** ) finalchallage
{
    
    NSError *err;
    
    NSString *faceID = [@"ios:bundle-id:" stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
    
    NSMutableDictionary* AsmData = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* channelBinding = [[NSMutableDictionary alloc] init];
    
    [AsmData   setObject:appID     forKey:@"appID"];
    [AsmData   setObject:challenge forKey:@"challenge"];
    [AsmData   setObject:channelBinding       forKey:@"channelBinding"];
    [AsmData   setObject:faceID  forKey:@"facetID"];

    
    
    NSData * jsonData = [NSJSONSerialization dataWithJSONObject:AsmData
                                                       options:(NSJSONWritingOptions)NSJSONWritingPrettyPrinted
                                                         error:&err];
    NSString* jsonNSStringBody =  [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];

    
    *finalchallage = [jsonNSStringBody copy];
    
    return PARSEJSONDATA_SUCCESS;
}




+(NSInteger )gmrz_pkg_authjson_client2asm:(NSString *)JsonPullin username:(NSString *)username Jsonout:(NSString **)JsonOut dicOut:(NSMutableDictionary **)dicOut
{
    
    
    NSInteger status;
    NSString *finalchallage;
    
    if (JsonPullin == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSData *jsonData = [JsonPullin dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                   options:NSJSONReadingMutableContainers
                                                     error:&err];
    if (arr == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    
    NSDictionary * dic = [arr objectAtIndex:0];
 
    
    NSString *appID = [dic valueForKeyPath:@"header.appID"];
    if (appID == nil ||[appID isEqual:[NSNull null]] || [appID isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSString *keyhandleusername = [username copy];
    if (username == nil ||[username isEqual:[NSNull null]] || [username isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSMutableDictionary *upv = [dic valueForKeyPath:@"header.upv"];
    if (upv == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSString *challenge= [dic valueForKey:@"challenge"];
    if (challenge == nil ||[challenge isEqual:[NSNull null]] || [challenge isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSString *requestType = [dic valueForKeyPath:@"header.op"];
    if (requestType == nil ||[requestType isEqual:[NSNull null]] || [requestType isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSArray *transactionArray = [dic valueForKeyPath:@"transaction"];
    NSString *transaction;
    if(transactionArray)
        transaction = [transactionArray[0] valueForKeyPath:@"content"];
    else
        transaction = @"";
    
    NSMutableDictionary *json2asm = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *asmVersion = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *args = [[NSMutableDictionary alloc]init];
    
    [args setObject:appID forKey:@"appID"];
    status = [gmrz_client_getfinalchallenge getFanilchallage:appID challenge:challenge finalchallage:&finalchallage];
    [args setObject:keyhandleusername forKey:@"username"];
    [args setObject:finalchallage forKey:@"finalChallenge"];
    [args setValue:@15880 forKey:@"attestationType"];
    [args setValue:transaction forKey:@"transcation"];
    
    
    [asmVersion setObject:upv forKey:@"asmVersion"];
    
    
    [json2asm setObject:args forKey:@"args"];
    [json2asm setObject:asmVersion forKey:@"asmVersion"];
    [json2asm setObject:@"1" forKey:@"authenticatorIndex"];
    [json2asm setObject:asmVersion forKey:@"asmVersion"];
    [json2asm setObject:requestType forKey:@"requestType"];
    
    *dicOut = [json2asm copy];
    
    
    //pkg NSMutableDictionary out
    NSMutableDictionary *jsonSerial = [[NSMutableDictionary alloc]init];
    [jsonSerial setObject:args forKey:@"args"];
    [jsonSerial setValue:@"0" forKey:@"authenticatorIndex"];
    [jsonSerial setObject:upv forKey:@"asmVersion"];
    [jsonSerial setObject:requestType forKey:@"requestType"];
    
    jsonData = [NSJSONSerialization dataWithJSONObject:jsonSerial options:NSJSONWritingPrettyPrinted error:&err];
    NSString * result = [[NSString alloc] initWithData:jsonData  encoding:NSUTF8StringEncoding];
    
    
    *JsonOut = [result copy];

    if(err) {
        NSLog(@"json解析失败：%@",err);
        return PARSEJSONDATA_FAILD;
    }

    
    return PARSEJSONDATA_SUCCESS;
}




+(NSInteger )gmrz_pkg_json_client2asm:(NSString *)JsonPullin Jsonout:(NSString **)JsonOut dicOut:(NSMutableDictionary **)dicOut
{
    NSInteger status;
    NSString *finalchallage;
    NSError *err;
    
    if (JsonPullin == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSData *jsonData = [JsonPullin dataUsingEncoding:NSUTF8StringEncoding];
   
    NSMutableArray *arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                   options:NSJSONReadingMutableContainers
                                                     error:&err];
    if(arr == nil)
        return PARSEJSONDATA_FAILD;
    NSDictionary * dic = [arr objectAtIndex:0];
    
    
    NSString *appID = [dic valueForKeyPath:@"header.appID"];
    if (appID == nil ||[appID isEqual:[NSNull null]] || [appID isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSString *username = [dic valueForKeyPath:@"username"];
    if (username == nil ||[username isEqual:[NSNull null]] || [username isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSMutableDictionary *upv = [dic valueForKeyPath:@"header.upv"];
    if (upv == nil) {
        return PARSEJSONDATA_FAILD;
    }
    NSString *challenge= [dic valueForKey:@"challenge"];
    if (challenge == nil ||[challenge isEqual:[NSNull null]] || [challenge isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    NSString *requestType = [dic valueForKeyPath:@"header.op"];
    if (requestType == nil ||[requestType isEqual:[NSNull null]] || [requestType isEqualToString:@""]) {
        return PARSEJSONDATA_FAILD;
    }
    
    NSMutableDictionary *json2asm = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *asmVersion = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *args = [[NSMutableDictionary alloc]init];
    
    [args setObject:appID forKey:@"appID"];
    [args setObject:username forKey:@"username"];
     status = [gmrz_client_getfinalchallenge getFanilchallage:appID challenge:challenge finalchallage:&finalchallage];
    [args setObject:finalchallage forKey:@"finalChallenge"];
    [args setValue:[NSNumber numberWithLong:TAG_ATTESTATION_BASIC_SURROGATE] forKey:@"attestationType"];

    
    [asmVersion setObject:upv forKey:@"asmVersion"];
    
 
    [json2asm setObject:args forKey:@"args"];
    [json2asm setObject:asmVersion forKey:@"asmVersion"];
    [json2asm setObject:@"0" forKey:@"authenticatorIndex"];
    [json2asm setObject:asmVersion forKey:@"asmVersion"];
    [json2asm setObject:requestType forKey:@"requestType"];
    
    *dicOut = [json2asm copy];
    
    
    //pkg NSMutableDictionary out
    NSMutableDictionary *jsonSerial = [[NSMutableDictionary alloc]init];
    [jsonSerial setObject:args forKey:@"args"];
    [jsonSerial setValue:@"0" forKey:@"authenticatorIndex"];
    [jsonSerial setObject:upv forKey:@"asmVersion"];
    [jsonSerial setObject:requestType forKey:@"requestType"];

    jsonData = [NSJSONSerialization dataWithJSONObject:jsonSerial options:NSJSONWritingPrettyPrinted error:&err];
    NSString * result = [[NSString alloc] initWithData:jsonData  encoding:NSUTF8StringEncoding];
    
    
    *JsonOut = [result mutableCopy];

    if(err) {
        NSLog(@"json解析失败：%@",err);
        return PARSEJSONDATA_FAILD;
    }
    
    
    
    
    
    return PARSEJSONDATA_SUCCESS;
}


@end
