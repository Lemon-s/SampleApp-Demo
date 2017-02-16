//
//  gmrz_client_interface.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/5.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_client_interface.h"

#include "uaf_ak_defs.h"
#include "gmrz_ak_authenticator.h"
#include "ak_getinfo.h"
#include "uaf_ak_defs.h"
#import "uaf_ak_tlv.h"
#include "uaf_ak_register_cmd.h"
//#include "gmrz_jv_ecc_cal.h" //no use any more
#include "gmrz_jv_ecc_cal_ext.h"
#include "gmrz_jv_asm_json_parse.h"
#include "gmrz_jv_asm_KHAccessToken.h"
#include "gmrz_jv_util_func.h"
#include "gmrz_json_pkg.h"
#import "gmrz_client_getfinalchallenge.h"
#include "uaf_ak_sign_cmd.h"
#include "authticatorlistshow.h"
#include "modelAlert.h"


@import LocalAuthentication;
#define UAF_REQUEST    @"uafRequest"
#define SystemVersion [[UIDevice currentDevice] systemVersion].floatValue
#define MALLOC_SIZE 512 * 2
//static authenticator_t gAuthenticators[MAX_AUTHENTICATORS_NUM] = {0};
//static ak_internal_info_t gAKInfo = {{gAuthenticators, 0}, {1,0x0100 }};
enum FidoStatus{
    SUCCESS = 0,
    FAILURE,
    CANCELED,
    NO_MATCH,
    NOT_INSTALLED,
    NOT_COMPATIBLE,
    APP_NOT_FOUND,
    TRANSACTION_ERROR,
    WAIT_USER_ACTION,
    INSECURE_TRANSPORT,
    PROTOCOL_ERROR,
    TOUIDINVALID

};

#if TARGET_OS_SIMULATOR
static BOOL isSimulator = YES;
#else
static BOOL isSimulator = NO;
#endif



@implementation gmrz_client_interface




+(OSStatus)process:(NSString *)FidoIn DoFido:(op)DoFido Methods:(methods)Method FidoOut:(NSString **)FidoOut
{
    
    //添加此方法，可以传入全部待 解析的数据  还可以传入
    NSString *response = [gmrz_client_interface responseToJsonParsingHeader:FidoIn];

    
    
    OSStatus status = SUCCESS;
    
    if (response == nil || [response isEqualToString:@""]) {
        status = PROTOCOL_ERROR;
        return status;
    }
    
    //check if running on Simulator
    if (isSimulator)
    {
        status = FAILURE;
        return status;
    }
    
    //check if touch id is available

  
    BOOL touchidavaliable = [gmrz_jv_util_func checkiftouchidisavaliable];
    if (!touchidavaliable) {
        
        __block BOOL _istruebtn = NO;
        dispatch_async(dispatch_get_main_queue(), ^{
            
            
//            [[NSOperationQueue mainQueue] addOperationWithBlock:^ {
                UIAlertController * alert =   [UIAlertController
                                               alertControllerWithTitle:NSLocalizedString(@"Touch ID Not Enabled", nil)
                                               message:NSLocalizedString(@"Enable Touch ID and passcode in iOS Settings and try again", nil)
                                               preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction* ok = [UIAlertAction
                                     actionWithTitle:NSLocalizedString(@"OK", nil)
                                     style:UIAlertActionStyleDefault
                                     handler:^(UIAlertAction * action)
                                     {
                                         
                                         _istruebtn = YES;
                                         [alert dismissViewControllerAnimated:YES completion:nil];
                                         
                                     }];
                [alert addAction:ok];
                
                UIWindow *window = [UIApplication sharedApplication].keyWindow;
                UIViewController *rootViewController = window.rootViewController;
                
                [rootViewController presentViewController:alert animated:YES completion:nil];
                
//            }];
            
            
        });
        
        while (!_istruebtn) {
            sleep(1);
        };
        _istruebtn = NO;
        *FidoOut = nil;
        status = FAILURE;
        return status;
    }
    
    if (DoFido== 0) //reg
    {

    /*
     *解析从client下发到asm的报文
     *
     *返回字典格式的初始数据  dic 为head 解析
     *返回字符串格式重新拼装数据  client_args 为 args
     *
     */
        int statuscode = SUCCESS;
        *FidoOut = [self regfunctionext:response method:Method statuscode:&statuscode];
        status  = statuscode;
    }
    else if(DoFido== 1) //auth
    {
        
        //检测用户列表
        NSArray *policylist;
        NSString *username;
        NSString *aaid;
        NSString *keyid;
        int statuscode = 0;
        
        status = [self checkifaccepted:&policylist Fidoin:response];
        
        if (status != 0)
        {
            NSLog(@"have a policylist list!");
            
            for (int index = 0; index < policylist.count; index++) {
                if (policylist.count > 0 && ([[policylist[index] valueForKeyPath:@"aaid"][0] isKindOfClass:[NSNull class]] || [policylist[index] valueForKeyPath:@"aaid"][0] == nil)) {
                    NSLog(@"messge format error!");
                    statuscode = PROTOCOL_ERROR;
                    return statuscode;
                }
                
            }
            
            
            status =  [self checkifmutiuser:policylist username:&username aaid:&aaid keyid:&keyid];
        }else
        {
            statuscode = NO_MATCH;
        }
        
        if (status == 1){
         //当只有一个用户符合
            *FidoOut = [[self authfunctionext:response username:username aaid:aaid keyid:keyid statuscode:&statuscode method:Method] copy];
            NSLog(@"just one username match");
        }else if (status > 1){
            //当多个用户符合
            *FidoOut = [[self authfunction:response aaid:aaid keyid:keyid statuscode:&statuscode method:Method] copy];
            NSLog(@"call back usernme list");
            
        }else
        {
            statuscode = NO_MATCH;
        }


        return statuscode;
    }
    else if(DoFido == 2) //rereg
    {
        status = 0;
        NSArray *authticatorlist = nil;
        status = [self checkifderegjsoninvalid:response authticatorlist:&authticatorlist];
        if (status == 0 && authticatorlist != NULL) {
            //delete keypair and asmdb
             status = [self deleteKeypair:[authticatorlist[0] valueForKeyPath:@"aaid"][0] username:nil serviceid:nil keyid:[authticatorlist[0] valueForKeyPath:@"keyID"][0]];
           }
        else
            status = 3;
        return status;
        
    }
    else if(DoFido == 3) //chec kpolicy
    {
        NSArray *policylist;
        int statuscode = 0;
        //检测是否有disallow  如果有的话为注册的checkPOLICY 如果没有 为认证的checkPOLICY
        NSArray *disallowlist = nil;
        status = [self checkifdisallow:&disallowlist Fidoin:response];
        
        //检测数据协议
        NSString *op = [self changeToobtain:response];
        
        if(disallowlist != nil || [op isEqualToString:@"Reg"]){
            for(int i = 0; i < disallowlist.count; i++)
            {
                NSString * serviceID = [@""  stringByAppendingString:[disallowlist[i] valueForKeyPath:@"aaid"][0]];
                serviceID = [serviceID stringByAppendingString:@"#"];
                serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
                
                //                [disallowlist[i] valueForKeyPath:@"aaid"][0]
                NSString *ItemOut = nil;
                [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
                
                NSError *err;
                NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
                NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                          options:NSJSONReadingMutableContainers
                                                                            error:&err];
                
                
                NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
                for (int j = 0; j < arr.count ; j++) {
                    if ([[arr[j] valueForKeyPath:@"keyid"] isEqualToString:[disallowlist[i] valueForKeyPath:@"keyIDs"][0]]) {
                        statuscode = NO_MATCH;
                        
                    }else{
                        statuscode = SUCCESS;
                    }
                }
            }
            status = statuscode;
            
            
        }
        else{
            
            
            status = [self checkifaccepted:&policylist Fidoin:response];
            
            if (status != 1 || policylist == nil) {
                return PROTOCOL_ERROR;
            }
            
            
            
            for(int i = 0; i < policylist.count; i++)
            {
                
                if ([[policylist[i] valueForKeyPath:@"aaid"][0][0] isEqualToString:@"4e4e#400a"]
                    || [[policylist[i] valueForKeyPath:@"aaid"][0][0] isEqualToString:@"4e4e#400b"]) {
                    NSString * serviceID = [@""  stringByAppendingString:[policylist[i] valueForKeyPath:@"aaid"][0][0]];
                    serviceID = [serviceID stringByAppendingString:@"#"];
                    serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
                    NSString *ItemOut = nil;
                    [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
                    
                    if (ItemOut == nil) {
                        continue;
                    }
                    NSLog(@"kc all --%@", ItemOut);
                    NSLog(@"keyIDs %@", [policylist[i] valueForKeyPath:@"keyIDs"][0]);
                    if (![[policylist[i] valueForKeyPath:@"keyIDs"][0] isEqual:[NSNull null]]) {
                        NSError *err;
                        NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
                        NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                                  options:NSJSONReadingMutableContainers
                                                                                    error:&err];
                        
                        
                        NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
                        for (int j = 0; j < arr.count ; j++) {
            
                            NSLog(@"kc loop --%@", [arr[j] valueForKeyPath:@"keyid"]);
                            NSString *tempKeyid = [arr[j] valueForKeyPath:@"keyid"];
                            NSString *tempKeypolicylist = [policylist[i] valueForKeyPath:@"keyIDs"][0][0];
//                            if ([[arr[j] valueForKeyPath:@"keyid"] isEqualToString:[policylist[i] valueForKeyPath:@"keyIDs"][0][0]]) {
                             if ([tempKeyid isEqualToString:tempKeypolicylist]) {
                                statuscode = SUCCESS;
                                  NSLog(@"already get key --%@", [arr[j] valueForKeyPath:@"keyid"]);
                                 return statuscode;
                            }
   
                        }
                        
                        
                    }else{
                        
                        if (ItemOut != nil) {
                            statuscode = SUCCESS;
                            return statuscode;
                        }
                        else
                            statuscode = NO_MATCH;
                    }
                    
                }
                else{
                    statuscode =  NO_MATCH;
                }
            }
            
        }
        
        return statuscode;
    }

    return status;
}



+(NSString *)changeToobtain:(NSString *)FidoIn{
    
    NSData *jsonData = [FidoIn dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                   options:NSJSONReadingMutableContainers
                                                     error:&err];
    if (!err) {
        
        NSString *op = arr[0][@"header"][@"op"];
        return op;
        
    }else{
        
        return nil;
        
    }
}


+(NSString *)responseToJsonParsingHeader:(NSString *)FidoIn {
    
    
    NSError *error = nil;
    if (FidoIn == nil) {
        return nil;
    }
    
    NSMutableString* response = [[NSMutableString alloc] init];
    //parse out the json data
    NSDictionary* json = [NSJSONSerialization
                          JSONObjectWithData: [FidoIn dataUsingEncoding:NSUTF8StringEncoding] //1
                          
                          options:kNilOptions
                          error:&error];
    //    if(nil != json && nil == error){
    response = [json valueForKeyPath:UAF_REQUEST];
    if (![response isKindOfClass:[NSString class]]) {
        return nil;
    }
    return response;
    
}



+(OSStatus)Checkifreg:(NSArray *)disallowlist
{
    OSStatus status = 0;
    //
    //status = 0 可以注册
    //status = 6  不可以注册
    //status = 2  4e4e#400a不可以注册
    //status = 4  4e4e#400b不可以注册
    //
    //400a 为低位 400b为高位
    unsigned char regid[3] = "\0";
    memset(regid, 0, 3);
    
    
    
    for (int i = 0 ; i < disallowlist.count; i++) {
        NSString * serviceID = [@""  stringByAppendingString:[disallowlist[i] valueForKeyPath:@"aaid"][0]];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
        //
        //check keyhandle first
        NSString *ItemOut = nil;
        //        [gmrz_jv_util_func db_items_delete:serviceID FuncItemIndex:0];
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
        
        
        if (ItemOut == nil) {
            status = 0;
            continue;
        }
        NSError *err;
        NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                  options:NSJSONReadingMutableContainers
                                                                    error:&err];
        
        
        NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
        
        for (int j = 0; j < arr.count; j++) {
            
            NSString *keyIDs = [disallowlist[i] valueForKeyPath:@"keyIDs"][0];
            NSString *keyid = [arr[j] valueForKeyPath:@"keyid"];

            if ([ keyid isEqualToString:keyIDs ]) {
                if([[disallowlist[i] valueForKeyPath:@"aaid"][0] isEqualToString:@"4e4e#400a"])
                    regid[0] = 1;
                else if ([[disallowlist[i] valueForKeyPath:@"aaid"][0] isEqualToString:@"4e4e#400b"])
                    regid[1] = 1;
            }
            
        }
        
        
    }
    status =  regid[0] * 2 + regid[1] * 4;
    return status;
}


+(OSStatus)checkifdisallow:(NSArray **)disallowlist Fidoin:(NSString *)Fidoin
{
    OSStatus status = 0;
    
    if (Fidoin == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    
    NSData *jsonData = [Fidoin dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                   options:NSJSONReadingMutableContainers
                                                     error:&err];
    NSDictionary * dic = [arr objectAtIndex:0];
    
    NSMutableArray *_disallowlist = [dic valueForKeyPath:@"policy.disallowed"];
    
    if (_disallowlist == nil && _disallowlist == NULL){
        return SUCCESS;
    }

    *disallowlist = [_disallowlist copy];
    return FAILURE;
}

//check if get auth keyid
+(OSStatus)checkifaccepted:(NSArray **)policylist Fidoin:(NSString *)Fidoin
{
    OSStatus status = 0;
    
    if (Fidoin == nil) {
        return PARSEJSONDATA_FAILD;
    }
    
    
    NSData *jsonData = [Fidoin dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                   options:NSJSONReadingMutableContainers
                                                     error:&err];
    
    if (arr == nil) {
        return PROTOCOL_ERROR;
    }
    NSDictionary * dic = [arr objectAtIndex:0];
    
    NSMutableArray *_policylist = [dic valueForKeyPath:@"policy.accepted"];
    
    if (_policylist == nil && _policylist == NULL){
        return 0;
    }

    *policylist = [_policylist copy];
    status = 1;
    
    return status;
}





//check if get auth keyid
+(OSStatus)checkifmutiuser:(NSArray *)policylist username:(NSString **)username aaid:(NSString **)aaid keyid:(NSString **)keyid
{
    OSStatus status = 0;
    int username_count = 0;
    int username_index = 0;
    int aaid_index = 0;
    NSString *username_temp = nil;
    int i= 0,  j = 0;
    NSMutableArray *arrlist;
    NSArray *arr ;
    
    for (i = 0 ; i < policylist.count; i++) {
        j = 0;

        NSString * serviceID = [@""  stringByAppendingString:[policylist[i] valueForKeyPath:@"aaid"][0][0]];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
        //
        //check keyhandle first
        NSString *ItemOut = nil;
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
        
        if(ItemOut == nil)
            continue;
        
        NSError *err;
        NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                  options:NSJSONReadingMutableContainers
                                                                    error:&err];
        
        
        arr = [jsonparse valueForKey:@"info_list"];

        if ([policylist[i] valueForKeyPath:@"keyIDs"][0] == nil || [policylist[i] valueForKeyPath:@"keyIDs"][0] == NULL || [[policylist[i] valueForKeyPath:@"keyIDs"][0] isEqual:[NSNull null]] || [arr count] == 0)
        {
            *username = nil;
            status = 2;
            
            return status;
        }

        
        for (j = 0; j < arr.count; j++) {
            if ([[arr[j] valueForKeyPath:@"keyid"] isEqualToString:[policylist[i] valueForKeyPath:@"keyIDs"][0][0]]) {
                if (username_temp == nil) {
                    username_temp = [arr[j] valueForKeyPath:@"username"];
                    username_index = j;
                    username_count ++;
                    aaid_index = i;
                    arrlist = [arr mutableCopy];
                }
                else if([username_temp isEqualToString:[arr[j] valueForKeyPath:@"username"] ])
                    break;
                
            }
            
        }
    }
    if (username_count > 1) {
        *username = nil;
        status = 2;
    }
    else if(username_count == 1)
    {
        *username = [[arrlist[username_index] valueForKeyPath:@"username"] copy];
  
        *aaid = [[policylist[aaid_index] valueForKeyPath:@"aaid"][0][0] copy];
        *keyid = [[policylist[aaid_index] valueForKeyPath:@"keyIDs"][0][0] copy];
        status = 1;
    }
    else
        status = 0;
    return status;
}

//check if get  keyid represent
+(OSStatus)checkifderegjsoninvalid:(NSString *)FidoIn authticatorlist:(NSArray **)authticatorlist
{
    OSStatus status = 0;
    NSError *err;
    NSData *jsonData = [FidoIn dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    

    
    NSArray * arr = [jsonparse valueForKeyPath:@"authenticators"];
    if (arr[0] == nil ||arr[0]  == NULL||[arr[0]isEqual:[NSNull null]]) {
        return NO_MATCH;
    }
    if ([arr[0] valueForKeyPath:@"keyID"][0] == nil ||
        [arr[0] valueForKeyPath:@"keyID"][0] == NULL ||
        [[arr[0] valueForKeyPath:@"keyID"][0] isEqual:[NSNull null]]){
        
        status = 1;
        *authticatorlist = nil;
        return status;
    }
    else{
        * authticatorlist = [arr copy];
    }
    
    return status;
}


//check if get  keyid represent
+(OSStatus)checkifderegjsoninvalid:(NSArray **)authticatorlist asmdbItem:(NSString *)asmdbItem
{
    OSStatus status = 0;
    NSError *err;
    NSData *jsonData = [asmdbItem dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    
    
    return status;
}




+(NSString *)Deregfunction:(NSString *)FidoIn statuscode:(int *)statuscode
{
    NSString *result;
    
    
    
    return result;
}


+(NSString *)regfunctionext:(NSString *)FidoIn method:(NSInteger)method statuscode:(int *)statuscode
{
    NSString *result;
    unsigned char *pResponse;
    unsigned short pResponseLength = MALLOC_SIZE;
    input_args_t args = {0};
    int responselength = 0;
    OSStatus status = SUCCESS;
    
    
    NSString *client_args;
    NSMutableDictionary *dic;
    status = [gmrz_json_pkg gmrz_pkg_json_client2asm:FidoIn Jsonout:&client_args dicOut:&dic];
    if (status != SUCCESS) {
        *statuscode = PROTOCOL_ERROR;
        return @"{}";
    }
    
    if (client_args == nil) {
        NSLog(@"gmrz_pkg_json_client2asm failed");
        *statuscode = FAILURE;
        return @"{}";
    }
    
    unsigned char checkmatadata[3];
    memset(checkmatadata, 0, sizeof(checkmatadata));
    NSMutableArray *policylist;
    status = [self checkifaccepted:&policylist Fidoin:FidoIn];

    if (policylist.count <= 0 || policylist ==nil) {
        *statuscode = PROTOCOL_ERROR;
         return @"{}";
    }
    
    for (int i = 0; i < policylist.count; i++) {
        if (![[policylist[i] valueForKeyPath:@"aaid"][0] isKindOfClass:[NSNull class] ]&&
            [[policylist[i] valueForKeyPath:@"aaid"][0][0] isEqualToString:@"4e4e#400a"]) {
            checkmatadata[0] = 1;
        }
        else if (![[policylist[i] valueForKeyPath:@"aaid"][0] isKindOfClass:[NSNull class] ]&&[[policylist[i] valueForKeyPath:@"aaid"][0][0] isEqualToString:@"4e4e#400b"])
            checkmatadata[1] = 1;
    }
    
    int checkmatadatamode = checkmatadata[0] * 2 + checkmatadata[1] * 4;
    if (checkmatadatamode ==  0) {
        NSLog(@"have no enable authticator!");
        *statuscode = NO_MATCH;
        return @"{}";
    }
    else if(checkmatadatamode == 2)
    {
        NSLog(@"you can reg 4e4e#400a");
    }
    else if(checkmatadatamode == 4)
    {
        NSLog(@"you can reg 4e4e#400b");
    }
    else if(checkmatadatamode == 6)
    {
        NSLog(@"you have not reg");
    }

    
    
    
    NSArray *disallowlist;
    status = [self checkifdisallow:&disallowlist Fidoin:FidoIn];
    
    if (status != 0)
    {
        NSLog(@"have a disallow list!");
        NSString *test = [disallowlist[0] valueForKeyPath:@"aaid"][0];
        for (int index = 0; index < disallowlist.count; index++) {
            if (disallowlist.count > 0 && ([[disallowlist[index] valueForKeyPath:@"aaid"][0] isKindOfClass:[NSNull class]] || [disallowlist[index] valueForKeyPath:@"aaid"][0] == nil)) {
                NSLog(@"messge format error!");
                *statuscode = PROTOCOL_ERROR;
                return @"{}";
            }

        }
        
        status =  [self Checkifreg:disallowlist];
        
    }
    
    if(status == 6)
    {
        
        NSLog(@"have no enable authticator!");
        *statuscode = NO_MATCH;
        return @"{}";
    }

    //ios 8.0 end
    
    //
    pResponse = (unsigned char *)malloc(pResponseLength);
    if (pResponse == NULL) {
        printf("pResponse  malloc failed\n");
    }
    authenticatorInfo_t *gAKInfoExt[32] = {0};
    
    //get info
    int  getInfoStatus = GetInfoExt(&gAKInfoExt, &args, pResponse, &pResponseLength);
   
    
    
    memset(pResponse, 0x0, MALLOC_SIZE);
    
    
    //解析asm接收到的json数据 返回字符串格式；
    NSDictionary *dicRegeister =nil;
    [gmrz_jv_asm_json_parse getHAccessTokenFillItem:client_args dicOut:&dicRegeister];

    NSString *_temp_client_args = [client_args mutableCopy];
    if (_temp_client_args == nil) {
         NSLog(@"_temp_client_args is nil");
        *statuscode = FAILURE;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        
        return @"{}";

    }
    //生成KHAccess TOKEN
    //返回的为sha256值  生成的值为 asmtoken/appid/username/bundle id/
    unsigned char * KHAccessin = NULL;
    if (_temp_client_args == nil) {
        NSLog(@"getKHAccessToken is nil");
        *statuscode = FAILURE;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        
        return @"{}";
    }
    getInfoStatus  = [gmrz_jv_asm_KHAccessToken getKHAccessToken:&KHAccessin jsonin:_temp_client_args];
    if (getInfoStatus != 0) {
        NSLog(@"getKHAccessToken is nil");
        *statuscode = FAILURE;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        
        return @"{}";
    }
    args.khAccessToken.pData = KHAccessin;
    args.khAccessToken.length = 32;
    
    args.authenticatorID = 1;
    args.operationType = 0x3601;
    args.authenticatorID = (ak_byte_t)[[dicRegeister valueForKey:@"authenticatorIndex"] intValue];
    if((status == 2 && checkmatadatamode == 4 )|| (status == 2 && checkmatadatamode == 6))
    {
        args.authenticatorID = 2;
        NSLog(@"you can reg 4e4e#400b");
    }
    else if((status == 4 && checkmatadatamode == 2)|| (status == 4 && checkmatadatamode == 6))
    {
         args.authenticatorID = 1;
        NSLog(@"you can reg 4e4e#400a");
    }
    else if((status == 0 && checkmatadatamode == 2)|| (status == 0 && checkmatadatamode == 6))
    {
        args.authenticatorID = 1;
        NSLog(@"you can reg 4e4e#400a");
    }
    else if((status == 0 && checkmatadatamode == 4)|| (status == 0 && checkmatadatamode == 6))
    {
        args.authenticatorID = 2;
        NSLog(@"you can reg 4e4e#400a");
    }
    else
    {
        
        NSLog(@"have no enable authticator!");
        *statuscode = NO_MATCH;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        
        return @"{}";

    }
    

    
    
    args.finalChallenge.pData = (uint8_t *)[[dicRegeister valueForKeyPath:@"args.finalChallenge"] UTF8String];
    
    args.username.pData =  (ak_byte_t *)[[dicRegeister valueForKeyPath:@"args.username"] UTF8String];
    args.attestationType = (ak_word_t)[dicRegeister valueForKeyPath:@"args.attestationType"];
    args.attestationType = 15880;
    
    memset(pResponse, 0x0, MALLOC_SIZE);
    pResponseLength = MALLOC_SIZE;
    //get info operation end
    int resultRegister = Register(gAKInfoExt[args.authenticatorID], 4, &args, pResponse, &pResponseLength,method);
    
    if(KHAccessin)
        free(KHAccessin);
    

    unsigned char *temp = NULL;
    //get reg/auth status code
    *statuscode = *(pResponse + 8) + *(pResponse + 9) * 256 ;
    if (*statuscode != SUCCESS) {
        NSMutableString *hexString = [NSMutableString string];
        for (int i=0; i < 9; i++)
        {
            [hexString appendFormat:@"%c", gAKInfoExt[args.authenticatorID]->aaid[i]];
        }
        
        
        NSString * serviceID = nil;
        serviceID = [@""  stringByAppendingString:hexString];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
        
        //check keyhandle first
        NSString  *ItemOut = nil;
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
        NSString  *DelItemOut = nil;
        [gmrz_jv_util_func KeychainItem_Delkey:[dicRegeister valueForKeyPath:@"args.username"] jsonIn:ItemOut userlistJsonOut:&DelItemOut];
        
        [gmrz_jv_util_func db_items_delete:serviceID FuncItemIndex:0];
        if (DelItemOut != NULL) {
            [gmrz_jv_util_func db_items_add:serviceID Data2Json:DelItemOut];
        }
        
    }
    
    
    if (*statuscode != SUCCESS && *statuscode != 13) {
       
        *statuscode = FAILURE;
  
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        return @"{}";
    }
    else if(*statuscode == 13)
    {
        *statuscode = CANCELED;
        
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        return @"{}";
    }
    
    //get reg/auth assertions
    
    temp = pResponse + 14;
    
    
    //get assertions by url_base64
//    char * uint_assertions =  gmrz_base64_encode(temp, pResponseLength -14);
    
    uint8_t *uint_assertions = (uint8_t *)malloc(1024);
    
    gmrz_base64_encode_ext(temp, uint_assertions, pResponseLength -14);
    
    
    NSString * assertion = [gmrz_jv_util_func base64urlconv:uint_assertions];
    
    if (uint_assertions) {
        free(uint_assertions);
    }
    
    //get assertions by url_base64
    NSData *jsonData = [FidoIn dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                   options:NSJSONReadingMutableContainers
                                                     error:&err];
    
    
    NSDictionary * dic_temp = [arr objectAtIndex:0];
    NSMutableDictionary *registerJsonRsponse = [[NSMutableDictionary alloc]init];
    
    //拼接assertions
    NSMutableDictionary * assertions = [[NSMutableDictionary alloc]init];
    [assertions setObject:assertion forKey:@"assertion"];
    [assertions setObject:@"UAFV1TLV" forKey:@"assertionScheme"];
    
    NSArray *assertionArray = [[NSArray alloc] initWithObjects:assertions, nil];
    [registerJsonRsponse setObject:assertionArray forKey:@"assertions"];
    [registerJsonRsponse setObject:dic_temp[@"header"] forKey:@"header"];
    [registerJsonRsponse setObject:[dicRegeister valueForKeyPath:@"args.finalChallenge"] forKey:@"fcParams"];
    NSArray *registerJsonRsponserr =[[NSArray alloc] initWithObjects:registerJsonRsponse, nil];
    
    
    NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:registerJsonRsponserr options:NSJSONWritingPrettyPrinted error:&err];
    NSString *finalResponse = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];

    
    
    result = [finalResponse copy];
    free(pResponse);
    
    freeGetInfoData(&gAKInfoExt, 4);
    
    
    return result;
}

//if more than one users then process this
+(NSString *)authfunctionext:(NSString *)FidoIn
                    username:(NSString *)usernme
                        aaid:(NSString *)aaid
                       keyid:(NSString *)keyid
                  statuscode:(int *)statuscode method:(NSInteger)method
{
    
    unsigned char *pResponse;
    unsigned short pResponseLength = MALLOC_SIZE;
    input_args_t args = {0};
    int responselength = 0;
    NSString *result ;
    
    NSMutableString *client_args;
    NSMutableDictionary *dic;
    *statuscode = 0;
    
    
    NSString * serviceID = aaid;
    serviceID = [serviceID stringByAppendingString:@"#"];
    serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
    
    if ( SystemVersion >= 9.0) {
         *statuscode = [gmrz_jv_util_func checkifUVSchange:serviceID];
        
        if (*statuscode == 2) {
            
            *statuscode = TOUIDINVALID;
            NSLog(@"passcode not set!");
            return @"{}";
        }
        else if(*statuscode == 0)
        {
            NSLog(@"UVS has changed!");
            [self deleteKeypair:aaid username:usernme serviceid:serviceID keyid:keyid];
            *statuscode = NO_MATCH;
            return @"{}";
        }

    }
    

    //
    //check keyhandle first
    NSString *ItemOut = nil;
    [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
    if (ItemOut == nil) {
        *statuscode = FAILURE;
        return @"{}";
    }
    NSError *err;
    NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    
    
    NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];

    *statuscode = [gmrz_json_pkg gmrz_pkg_authjson_client2asm:FidoIn username:usernme Jsonout:&client_args dicOut:&dic];
    
    if (*statuscode != 0) {
        *statuscode = PROTOCOL_ERROR;
        return @"{}";
    }
     //ios 8.0 end
    
    //
    pResponse = (unsigned char *)malloc(pResponseLength);
    if (pResponse == NULL) {
        printf("pResponse  malloc failed\n");
    }
    

    jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
    jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    
    arr = [jsonparse valueForKey:@"info_list"];
    args.keyHandlesNum = 0;
    
    
    for(int i = 0; i <  arr.count; i++){
        if ([[arr[i] valueForKeyPath:@"username"] isEqualToString:usernme]) {
            
            args.keyHandles[args.keyHandlesNum].pData = (uint8_t *)malloc(512);
            memset(args.keyHandles[args.keyHandlesNum].pData, 0x0, 512);
            
            //    int resultlen = base64_decode(testbasestr, mallocrec);
            args.keyHandles[args.keyHandlesNum].length = gmrz_base64_decode_ext([[arr[i] valueForKeyPath:@"keyhandle"] UTF8String],  args.keyHandles[args.keyHandlesNum].pData);
            
//            
//            args.keyHandles[args.keyHandlesNum].pData = gmrz_base64_decode([[arr[i] valueForKeyPath:@"keyhandle"] UTF8String] , [[arr[i] valueForKeyPath:@"keyhandle"] length]);
//            args.keyHandles[args.keyHandlesNum].length = 48;
//            args.keyHandles[args.keyHandlesNum].length = 128 ;
            args.keyHandlesNum++;
        }
    }
    
    authenticatorInfo_t *gAKInfoExt[32] = {0};
    int  getInfoStatus = GetInfoExt(gAKInfoExt, &args, pResponse, &pResponseLength);
 
    
    NSDictionary *dicRegeister =nil;
    [gmrz_jv_asm_json_parse getHAccessTokenFillItem:client_args dicOut:&dicRegeister];
    
    
    unsigned char * KHAccessin = NULL;
    [gmrz_jv_asm_KHAccessToken getKHAccessToken:&KHAccessin jsonin:client_args];
    args.khAccessToken.pData = KHAccessin;
    args.khAccessToken.length = 32;
    
    
    
    
    args.operationType = 0x3603;
    args.authenticatorID = (ak_byte_t)[[dicRegeister valueForKey:@"authenticatorIndex"] intValue];
    
    if ([aaid isEqualToString:@"4e4e#400a" ]) {
        args.authenticatorID = 1;
    }
    else if ([aaid isEqualToString:@"4e4e#400b" ]) {
            args.authenticatorID = 2;
        }
    
    args.finalChallenge.pData = (uint8_t *)[[dicRegeister valueForKeyPath:@"args.finalChallenge"] UTF8String];
    
    args.username.pData =  (ak_byte_t *)[[dicRegeister valueForKeyPath:@"args.username"] UTF8String];
    args.attestationType = 15880;
    
    if ([dicRegeister valueForKeyPath:@"args.transcation"] == nil) {
        *statuscode = FAILURE;
        free(pResponse);
        freeGetInfoData(&gAKInfoExt, 4);
        return @"{}";
    }
    
    
    
     NSString * arg_transcation = [gmrz_jv_util_func convbase64url:[[dicRegeister valueForKeyPath:@"args.transcation"] UTF8String]];
    
    if (arg_transcation == nil) {
        *statuscode = FAILURE;
        free(pResponse);
        freeGetInfoData(&gAKInfoExt, 4);
        return @"{}";
    }
    
    
    
    
    
    
//    args.transactionContent.pData = (uint8_t *)malloc(512);
//    memset(args.transactionContent.pData, 0x0, 512);
//    
//    args.transactionContent.length = gmrz_base64_decode_ext([arg_transcation UTF8String],  args.transactionContent.pData);
    
//    args.transactionContent.length = gmrz_base64_decode_ext("WW91IGFyZSBhdXRob3JpemluZyBhIHRyYW5zYWN0aW9uIG9mICQxMDA",  args.transactionContent.pData);
    
    args.transactionContent.pData = gmrz_base64_decode([arg_transcation UTF8String], [arg_transcation length]);
    args.transactionContent.length = strlen(args.transactionContent.pData );
    
    
    memset(pResponse, 0x0, MALLOC_SIZE);
    pResponseLength = MALLOC_SIZE;
    //get info operation end
    int resultSign = Sign(gAKInfoExt[args.authenticatorID], 4, &args, pResponse, &pResponseLength,method);
    
    if(KHAccessin)
        free(KHAccessin);
    
    if( args.transactionContent.pData)
        free( args.transactionContent.pData);

    
    unsigned char *temp = NULL;
    temp = pResponse + 14;
    
    
    *statuscode = *(pResponse + 8)  + *(pResponse + 9) * 256;
    
    
    if (*statuscode != SUCCESS && *statuscode != 13 && *statuscode != 14) {
        *statuscode = FAILURE;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);

        return @"{}";
    }
    else if(*statuscode == 13)
    {
        *statuscode = CANCELED;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        return @"{}";
    }
    else if(*statuscode == 14)
    {
        *statuscode = WAIT_USER_ACTION;
        free(pResponse);
        
        freeGetInfoData(&gAKInfoExt, 4);
        return @"{}";
    }

    if (* statuscode == SUCCESS) {
        
//       char * uint_assertions =  gmrz_base64_encode(temp, pResponseLength -14);
        uint8_t *uint_assertions = (uint8_t *)malloc(1024);
        
        gmrz_base64_encode_ext(temp, uint_assertions, pResponseLength -14);
        
        //    NSString * assertion = [[NSString alloc ] initWithCString:uint_assertions encoding:NSUTF8StringEncoding];
        NSString * assertion = [gmrz_jv_util_func base64urlconv:uint_assertions];
        
        if (uint_assertions) {
            free(uint_assertions);
        }
        
        
        jsonData = [FidoIn dataUsingEncoding:NSUTF8StringEncoding];
        
        arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                              options:NSJSONReadingMutableContainers
                                                error:&err];
        
        
        NSDictionary * dic_temp = [arr objectAtIndex:0];
        NSMutableDictionary *registerJsonRsponse = [[NSMutableDictionary alloc]init];
        
        //拼接assertions
        NSMutableDictionary * assertions = [[NSMutableDictionary alloc]init];
        [assertions setObject:assertion forKey:@"assertion"];
        [assertions setObject:@"UAFV1TLV" forKey:@"assertionScheme"];
        
        NSArray *assertionArray = [[NSArray alloc] initWithObjects:assertions, nil];
        [registerJsonRsponse setObject:assertionArray forKey:@"assertions"];
        [registerJsonRsponse setObject:dic_temp[@"header"] forKey:@"header"];
        [registerJsonRsponse setObject:[dicRegeister valueForKeyPath:@"args.finalChallenge"] forKey:@"fcParams"];
        NSArray *registerJsonRsponserr =[[NSArray alloc] initWithObjects:registerJsonRsponse, nil];
        
        
        NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:registerJsonRsponserr options:NSJSONWritingPrettyPrinted error:&err];
        NSString *finalResponse = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
  
        
        
        //            *FidoOut = [finalResponse mutableCopy];
        
        //            *FidoOut = [*FidoOut stringByAppendingString:finalResponse];
        responselength = [finalResponse length];
        free(pResponse);
        freeGetInfoData(&gAKInfoExt, 4);
        
        result = [[NSString alloc] initWithString:finalResponse];
    }
    else
    {
        responselength = 10;
        free(pResponse);
        freeGetInfoData(&gAKInfoExt, 4);
        result = @"{}";
    }
    
    return result;

}

//if only one user then process this
+(NSString *)authfunction:(NSString *)FidoIn
                     aaid:(NSString *)aaid
                    keyid:(NSString *)keyid
               statuscode:(int *)statuscode method:(NSInteger)method
{
    
    NSString * serviceID = nil;
    
    NSString *username = @"";
    __block NSString *result = nil;
    
    unsigned char *pResponse;
    unsigned short pResponseLength = MALLOC_SIZE;
    input_args_t args = {0};
    int responselength = 0;
    
    
    NSString *client_args;
    NSMutableDictionary *dic;
    
    
    
    
     NSArray *policylist;
    [self checkifaccepted:&policylist Fidoin:FidoIn];
    NSString *keyidlist = nil;
    __block NSString *ItemOut = nil;
    
    unsigned char aaidlist[3];
    memset(aaidlist, 0, sizeof(aaidlist));
    
    
     NSArray *authticatorlist = [NSArray arrayWithObjects:@"4e4e#400a",@"4e4e#400b", nil];
    for (int i = 0; i < 2; i++) {
        serviceID = [@""  stringByAppendingString:authticatorlist[i]];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
        
        
        ItemOut = nil;
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];

        
      if (ItemOut != nil)
          aaidlist[i] = 1;
       
    }
    __block NSString * choose_result = nil;
    if (aaidlist[0] + aaidlist[1] == 2) {
        
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"this printf in main thread.");
            NSArray *array = [NSArray arrayWithObjects:@"4e4e#400a",@"4e4e#400b", nil];
            authticatorlistshow *als =[[authticatorlistshow alloc] initWithFrame:CGRectMake(0, 0, [[UIScreen mainScreen] bounds].size.width, [[UIScreen mainScreen] bounds].size.height) andDataSource:array];
            [als getSelectValue:^(NSString *selectdata) {
                choose_result = selectdata;
            }];
        });
       
        while (choose_result == nil) {
             sleep(1);
        }
        
  
    }
    else if(aaidlist[0] == 1)
        choose_result = @"4e4e#400a";
    else if(aaidlist[1] == 1)
        choose_result = @"4e4e#400b";
    
    
    NSMutableArray * pickerArray = [[NSMutableArray alloc] init];
    for (int i = 0; i < policylist.count; i++) {
        
        serviceID = [@""  stringByAppendingString:choose_result];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];

        //
        //check keyhandle first
        ItemOut = nil;
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
        
        if(ItemOut == nil)
            continue;
        
        NSError *err;
        NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                  options:NSJSONReadingMutableContainers
                                                                    error:&err];

        
        NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];

        for (int i = 0; i < arr.count; i ++) {
            [pickerArray addObject:[arr[i] valueForKeyPath:@"username"]];
        }
        break;
        
    }

    if (pickerArray.count == 1) {
        int  errorcode = 0;
        result = [self authfunctionext:FidoIn username:pickerArray[0] aaid:choose_result keyid:nil statuscode:&errorcode method:method];
        *statuscode = errorcode;
    }
    else{
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"user list show");
            authticatorlistshow *als =[[authticatorlistshow alloc] initWithFrame:CGRectMake(0, 0, [[UIScreen mainScreen] bounds].size.width, [[UIScreen mainScreen] bounds].size.height) andDataSource:pickerArray ];
            [als getSelectValue:^(NSString *selectdata) {
                
                result = [selectdata copy];
            }];
            
        });
        
        while (result == NULL || result == nil || [ result isKindOfClass:[NSNull class]]) {
            sleep(1);
        }
        
        
        
        
        
        
        
        
        
        if (SystemVersion >= 9.0) {
            *statuscode = [gmrz_jv_util_func checkifUVSchange:serviceID];
            
            if (*statuscode == 2) {
                
                *statuscode = TOUIDINVALID;
                NSLog(@"passcode not set!");
                //                return @"{}";
            }
            else if(*statuscode == 0)
            {
                NSLog(@"UVS has changed!");
                int delstatus = [self deleteKeypair:choose_result username:result serviceid:serviceID keyid:keyid];
                responselength = 10;
                *statuscode = NO_MATCH;
                //                return @"{}";
            }
            
        }
        
        if(*statuscode !=NO_MATCH)
        {
            
            
            [gmrz_json_pkg gmrz_pkg_authjson_client2asm:FidoIn username:result Jsonout:&client_args dicOut:&dic];
       
            //ios 8.0 end
            
            //
            pResponse = (unsigned char *)malloc(pResponseLength);
            if (pResponse == NULL) {
                printf("pResponse  malloc failed\n");
            }
            
            NSError *err;
            NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                      options:NSJSONReadingMutableContainers
                                                                        error:&err];
            
            NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
            args.keyHandlesNum = 0;
            
            
            for(int i = 0; i <  arr.count; i++){
                if ([[arr[i] valueForKeyPath:@"username"] isEqualToString:result]) {
                    
                     args.keyHandles[args.keyHandlesNum].pData = (unsigned char *)malloc(512);
                    memset( args.keyHandles[args.keyHandlesNum].pData, 0x0, 512);
                    
                    //    int resultlen = base64_decode(testbasestr, mallocrec);
                    args.keyHandles[args.keyHandlesNum].length = gmrz_base64_decode_ext([[arr[i] valueForKeyPath:@"keyhandle"] UTF8String],  args.keyHandles[args.keyHandlesNum].pData);
                    
                    
                    
//                    args.keyHandles[args.keyHandlesNum].pData = gmrz_base64_decode([[arr[i] valueForKeyPath:@"keyhandle"] UTF8String] , [[arr[i] valueForKeyPath:@"keyhandle"] length]);
//                    //            args.keyHandles[args.keyHandlesNum].length = 48;
//                    args.keyHandles[args.keyHandlesNum].length = strlen(args.keyHandles[args.keyHandlesNum].pData) ;
                    args.keyHandlesNum++;
                }
                
            }
            
            authenticatorInfo_t *gAKInfoExt[32] = {0};
            int  getInfoStatus = GetInfoExt(gAKInfoExt, &args, pResponse, &pResponseLength);
   
            
            NSDictionary *dicRegeister =nil;
            [gmrz_jv_asm_json_parse getHAccessTokenFillItem:client_args dicOut:&dicRegeister];
            
            
            unsigned char * KHAccessin = NULL;
            [gmrz_jv_asm_KHAccessToken getKHAccessToken:&KHAccessin jsonin:client_args];
            args.khAccessToken.pData = KHAccessin;
            args.khAccessToken.length = 32;
            
            
            
            
            args.operationType = 0x3603;
            if ([choose_result isEqualToString:@"4e4e#400a"]) {
                args.authenticatorID = 1;
            }
            if ([choose_result isEqualToString:@"4e4e#400b"]) {
                args.authenticatorID = 2;
            }
            
            
            args.finalChallenge.pData = (uint8_t *)[[dicRegeister valueForKeyPath:@"args.finalChallenge"] UTF8String];
            
            args.username.pData =  (ak_byte_t *)[[dicRegeister valueForKeyPath:@"args.username"] UTF8String];
            args.attestationType = 15880;
            
            
            
            
            
            
            
            if ([dicRegeister valueForKeyPath:@"args.transcation"] == nil) {
                *statuscode = FAILURE;
                free(pResponse);
                freeGetInfoData(&gAKInfoExt, 4);
                return @"{}";
            }
            
            
            
            
            NSString * arg_transcation = [gmrz_jv_util_func convbase64url:[[dicRegeister valueForKeyPath:@"args.transcation"] UTF8String]];
            
            if (arg_transcation == nil) {
                *statuscode = FAILURE;
                free(pResponse);
                freeGetInfoData(&gAKInfoExt, 4);
                return @"{}";
            }

            
             args.transactionContent.pData = (unsigned char *)malloc(512);
            memset(  args.transactionContent.pData, 0x0, 512);
            
            //    int resultlen = base64_decode(testbasestr, mallocrec);
             args.transactionContent.length = gmrz_base64_decode_ext([arg_transcation UTF8String],  args.transactionContent.pData);
            
            
//            args.transactionContent.pData = gmrz_base64_decode([arg_transcation UTF8String], [arg_transcation length]);
//            args.transactionContent.length = strlen(args.transactionContent.pData );
            
            
            memset(pResponse, 0x0, MALLOC_SIZE);
            pResponseLength = MALLOC_SIZE;
            //get info operation end
            int resultSign = Sign(gAKInfoExt[args.authenticatorID], 4, &args, pResponse, &pResponseLength,method);
            
            if(KHAccessin)
                free(KHAccessin);
    
            
            
            unsigned char *temp = NULL;
            temp = pResponse + 14;
            
            *statuscode = *(pResponse + 8) + *(pResponse + 9) * 256 ;
            
            
            
            if (*statuscode != SUCCESS && *statuscode != 13 && *statuscode != 14) {
                *statuscode = FAILURE;
                free(pResponse);
                
                freeGetInfoData(&gAKInfoExt, 4);
                
                return @"{}";
            }
            else if(*statuscode == 13)
            {
                *statuscode = CANCELED;
                free(pResponse);
                
                freeGetInfoData(&gAKInfoExt, 4);
                return @"{}";
            }
            else if(*statuscode == 14)
            {
                *statuscode = WAIT_USER_ACTION;
                free(pResponse);
                
                freeGetInfoData(&gAKInfoExt, 4);
                return @"{}";
            }
            
            if (* statuscode == SUCCESS) {
                
//                char * uint_assertions =  gmrz_base64_encode(temp, pResponseLength -14);
                uint8_t *uint_assertions = (uint8_t *)malloc(1024);
                
                gmrz_base64_encode_ext(temp, uint_assertions, pResponseLength -14);
                
                NSString * assertion = [gmrz_jv_util_func base64urlconv:uint_assertions];
                
                if (uint_assertions) {
                    free(uint_assertions);
                }
                
                if (args.transactionContent.pData) {
                    free(args.transactionContent.pData);
                }

                
                
                
                jsonData = [FidoIn dataUsingEncoding:NSUTF8StringEncoding];
                arr = [NSJSONSerialization JSONObjectWithData:jsonData
                                                      options:NSJSONReadingMutableContainers
                                                        error:&err];
                
                
                NSDictionary * dic_temp = [arr objectAtIndex:0];
                NSMutableDictionary *registerJsonRsponse = [[NSMutableDictionary alloc]init];
                
                //拼接assertions
                NSMutableDictionary * assertions = [[NSMutableDictionary alloc]init];
                [assertions setObject:assertion forKey:@"assertion"];
                [assertions setObject:@"UAFV1TLV" forKey:@"assertionScheme"];
                
                NSArray *assertionArray = [[NSArray alloc] initWithObjects:assertions, nil];
                [registerJsonRsponse setObject:assertionArray forKey:@"assertions"];
                [registerJsonRsponse setObject:dic_temp[@"header"] forKey:@"header"];
                [registerJsonRsponse setObject:[dicRegeister valueForKeyPath:@"args.finalChallenge"] forKey:@"fcParams"];
                NSArray *registerJsonRsponserr =[[NSArray alloc] initWithObjects:registerJsonRsponse, nil];
                
                
                NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:registerJsonRsponserr options:NSJSONWritingPrettyPrinted error:&err];
                NSString *finalResponse = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];

                
                //            *FidoOut = [finalResponse mutableCopy];
                
                //            *FidoOut = [*FidoOut stringByAppendingString:finalResponse];
                responselength = [finalResponse length];
                free(pResponse);
                
                
                freeGetInfoData(&gAKInfoExt, 4);
                
                result = [[NSString alloc] initWithString:finalResponse];
            }
            
        }

        
    }

    return result;
}


+(OSStatus)deleteKeypair:(NSString *)aaid
                username:(NSString *)username
               serviceid:(NSString *)serviceid
                   keyid:(NSString *)keyid
{
    OSStatus status = 0;
    
    
        //delete keypair
    
        NSString * serviceID = [@""  stringByAppendingString:aaid];
        serviceID = [serviceID stringByAppendingString:@"#"];
        serviceID =  [serviceID stringByAppendingString:[[NSBundle mainBundle] bundleIdentifier]];
        NSString *ItemOut = nil;
        [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
    
        if (ItemOut == nil) {
            status = 3;
        }
        else
        {
            NSError *err;
            NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                      options:NSJSONReadingMutableContainers
                                                                        error:&err];
            
            NSString *priId;
            NSString *pubID;
            NSString *serviceId;
            NSString *accountId;
            int match_result = 0;
            NSMutableArray * arr = [jsonparse valueForKey:@"info_list"];
            
            int match_object= 0;
            if (keyid != NULL) {
                for (int i = 0; i < arr.count; i++) {
                    if ([[arr[i] valueForKeyPath:@"keyid"] isEqualToString:keyid]) {
                      
                        priId = [[arr[i] valueForKeyPath:@"privatekeyinfo.priId"] copy];
                        serviceId = [[arr[i] valueForKeyPath:@"privatekeyinfo.serviceId"] copy];
                        accountId = [[arr[i] valueForKeyPath:@"privatekeyinfo.accountId"] copy];
                        match_object = i;
                    }
                }
            }
            else if(username != NULL)
            {
                for (int i = 0; i < arr.count; i++) {
                    if ([[arr[i] valueForKeyPath:@"username"] isEqualToString:username]) {
                       
                        priId = [[arr[i] valueForKeyPath:@"privatekeyinfo.priId"] copy];
                        serviceId = [[arr[i] valueForKeyPath:@"privatekeyinfo.serviceId"] copy];
                        accountId = [[arr[i] valueForKeyPath:@"privatekeyinfo.accountId"] copy];
                        match_object = i;
                    }
                }

            }
           
            if (SystemVersion >= 9) {
                
                if (serviceId == nil) {
                    status = 3;
                    return  status;
                }
                priId =  [gmrz_jv_util_func asmDB_data_id:serviceId counterid:[[NSBundle mainBundle] bundleIdentifier] username:accountId ext:@"pri"];
                match_result = [[gmrz_jv_ecc_cal_ext sharedManager] deleteKeyAsync_ios9:priId pubId:nil];
            }
            else{
                priId =  [gmrz_jv_util_func asmDB_data_id:aaid counterid:[[NSBundle mainBundle] bundleIdentifier] username:[arr[match_object] valueForKeyPath:@"username"] ext:@"pri"];
                pubID =  [gmrz_jv_util_func asmDB_data_id:aaid counterid:[[NSBundle mainBundle] bundleIdentifier] username:[arr[match_object] valueForKeyPath:@"username"] ext:@"pub"];
                match_result =  [[gmrz_jv_ecc_cal_ext sharedManager] deleteKeyAsync:priId pubId:pubID serviceId:serviceId accountId:accountId];
            }
            if (match_result == 0) {
                if (match_object < 0) {
                    status = 3;
                    return  status;
                }
                [arr removeObject:arr[match_object]];
                [gmrz_jv_util_func db_items_delete:serviceID FuncItemIndex:0];
                if (arr.count > 0) {
                    NSMutableDictionary *userListDic = [[NSMutableDictionary alloc] init];
                    [userListDic setObject:arr forKey:@"info_list"];
                    
                    NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:userListDic options:NSJSONWritingPrettyPrinted error:&err];
                    NSString * userlist = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
                    [gmrz_jv_util_func db_items_add:serviceID Data2Json:userlist];
                    ItemOut = nil;
                    [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
                }
               
            }
            
            status = 0;
            
        }
        //delete asmdb
        
 
    return status;
}





@end
