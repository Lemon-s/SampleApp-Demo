//
//  gmrz_jv_ecc_cal_ext.h
//  TestAkcmd
//
//  Created by Lyndon on 16/6/30.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>





#define  GENKEYPAIR_FAILED  -1001
#define  SECITEMADD_FAILED  -1002
#define  SECITEMCOPYMATCHING_FAILED -1003
#define  SECITEMDELETE_FAILED -1004
#define  SECKEYRAWSIGN_FAILED -1005
#define  SECITEMDELETE_FAILED -1006

#define WARPKYEHANLE_SUCCESS 0
#define WARPKYEHANLE_FAILD -1060


@interface gmrz_jv_ecc_cal_ext : NSObject
{
    NSData * symmetricTag;
    NSData * symmetricKeyRef;
}

//AES algorithm
@property (nonatomic, strong) NSData * symmetricTag;
@property (nonatomic, strong) NSData * symmetricKeyRef;
@property (nonatomic, strong) NSCondition *mConditionLock;

+(gmrz_jv_ecc_cal_ext *)sharedManager;



//new keypair generator

-(OSStatus)generateKeyAsync :(NSString *)priId
                       pubId:(NSString *)pubId
                   serviceId:(NSString *)serviceId
                   accountId:(NSString *)accountId;


-(OSStatus)generateKeyAsync_ios9 :(NSString *)priId pubId:(NSString *)pubId publickeybyte:(UInt8 **)publickeybyte;




-(OSStatus)setPrivatecRef:(NSString *)priId
                    pubId:(NSString *)pubId
                serviceId:(NSString *)serviceId
                accountId:(NSString *)accountId
           trancationtext:(uint8_t *)trancationtext
               privateKey:(SecKeyRef *)privateKey;



-(OSStatus)setPrivatecbyte:(NSString *)priId
                    pubId:(NSString *)pubId
                serviceId:(NSString *)serviceId
                accountId:(NSString *)accountId
               privateKey:(SecKeyRef *)privateKey;


-(OSStatus)setPrivatecRef_ios9:(NSString *)priId pubId:(NSString *)pubId trancationtext:(uint8_t *)trancationtext method:(NSInteger)method privateKey:(SecKeyRef *)privateKey methods :(NSString *)methods;


-(OSStatus)setPrivatecRef_ios10:(NSString *)priId pubId:(NSString *)pubId trancationtext:(uint8_t *)trancationtext method:(NSInteger)method privateKey:(SecKeyRef *)privateKey methods :(NSString *)methods;

-(OSStatus)useKeyAsyncSign:(NSString *)priId
                     pubId:(NSString *)pubId
            trancationtext:(uint8_t *)trancationtext
                 serviceId:(NSString *)serviceId
                 accountId:(NSString *)accountId
                digestData:(uint8_t *)digestData
              digestLength:(size_t) digestLength
                 signature:(uint8_t *)signature
           signatureLength:(size_t *)signatureLength
                    method:(NSInteger)method
                   methods:(NSString *)methods;


-(OSStatus)useKeyAsyncVerify:(NSString *)priId
                        pubId:(NSString *)pubId
                   digestData:(uint8_t *)digestData
                 digestLength:(size_t) digestLength
                    signature:(uint8_t *)signature
              signatureLength:(size_t)signatureLength;


-(OSStatus)deleteKeyAsync:(NSString *)priId
                    pubId:(NSString *)pubId
                serviceId:(NSString *)serviceId
                accountId:(NSString *)accountId;

-(OSStatus)deleteKeyAsync_ios9:(NSString *)priId pubId:(NSString *)pubId;

-(SecKeyRef )setPublicRef:(NSString *)pubId;
-(NSData *)setPublicData:(NSString *)priId pubId:(NSString *)pubId;





//AES keypair algorithm
- (void)deleteSymmetricKey;
- (int)generateSymmetricKey;
- (NSData *)getSymmetricKeyBytes;


//AES key ENC&DEC function
//no use any more
- (NSData *)aes256_encrypt:(NSString *)key SourceData:(NSData *)SourceData;

//
- (size_t)aes256_encrypt_ext:(uint8_t *)SourceData  //加密
            SourceDataLength:(uint8_t)SourceDataLength
                     dstData:(uint8_t **)dstData
               dstDataLength:(uint8_t *)dstDataLength;


- (NSData *)aes256_decrypt:(NSString *)key SourceData:(NSData *)SourceData;

- (size_t)aes256_decrypt_ext:(uint8_t *)SourceData  //加密
            SourceDataLength:(uint8_t)SourceDataLength
                     dstData:(uint8_t **)dstData
               dstDataLength:(uint8_t *)dstDataLength;


//SHA256 algorithm
- (NSData *)getHashBytes:(NSData *)plainText;

- (uint8_t *)getHashBytesext:(uint8_t *)plainText length:(int)length;

- (uint8_t *)getSHA1Bytesext:(uint8_t *)plainText length:(int)length;


@end
