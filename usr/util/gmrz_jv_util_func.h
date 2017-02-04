//
//  gmrz_jv_util_func.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/4.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface gmrz_jv_util_func : NSObject


+(NSString *)DecodeBase64ToNSStr:(NSString *)Base64Str;
+(NSString *)EncodeNSStrToBase64:(NSString *)PlainText;




+ (NSString *)textFromBase64String:(NSString *)base64;
+ (NSString *)textFromBase64StringExt:(NSString *)base64;


char * gmrz_base64_encode_ext( const unsigned char * bindata, char * base64, int binlength);
int gmrz_base64_decode_ext( const unsigned char * base64, unsigned char * bindata );

char *gmrz_base64_encode(const unsigned char* data, int data_len);
char *gmrz_base64_decode(const unsigned char* data, int data_len);


+ (NSString *)base64urlconv:(uint8_t *)base64;
+ (NSString *)convbase64url:(uint8_t *)base64;



+ (OSStatus)userlistadd:(NSString *)username userlistJsonIn:(NSString *)userlistJsonIn userlistJsonOut:(NSString **)userlistJsonOut;

int strTobcd(unsigned char *dest, const char *src ,int srclen);




+ (OSStatus)KeychainItem_add:(NSString *)username
                   keyhandle:(NSString *)keyhandle
                       keyid:(NSString *)keyid
                         UVS:(NSString *)UVS
                   serviceId:(NSString *)serviceId
                   accountId:(NSString *)accountId
                       priId:(NSString *)priId
              userlistJsonIn:(NSString *)userlistJsonIn
             userlistJsonOut:(NSString **)userlistJsonOut;


+ (OSStatus)KeychainItem_Getkey:(NSString *)username
                         jsonIn:(NSString *)jsonIn
                         dicOut:(NSDictionary **)dicOut;



+ (OSStatus)KeychainItem_Delkey:(NSString *)username
                         jsonIn:(NSString *)jsonIn
                userlistJsonOut:(NSString **)userlistJsonOut;


+(OSStatus)db_items_add:(NSString *)ServiveId Data2Json:(NSString *)Data2Json;
+(OSStatus)db_items_match:(NSString *)ServiveId
                 Itemjson:(NSString **)Itemjson;

+(OSStatus)db_items_delete:(NSString *)ServiveId FuncItemIndex:(int *)FuncItemIndex;



+(NSInteger)getIOSversion;


+(NSString *)asmDB_data_id:(NSString *)serviceID
                 counterid:(NSString *)counterid
                  username:(NSString *)username
                       ext:(NSString *)ext;

+ (BOOL)canEvaluatePolicy:(NSString **)UVS;
+(OSStatus)checkifUVSchange:(NSString *)serviceID;
+ (BOOL)checkiftouchidisavaliable;
+ (BOOL)checkiftouchidlocked;



@end
