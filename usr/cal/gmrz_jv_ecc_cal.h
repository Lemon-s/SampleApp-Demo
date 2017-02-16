//
//  gmrz_jv_ecc_cal.h
//  gmrz_AuthSDK
//
//  Created by Lyndon on 16/4/28.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>


#define WARPKYEHANLE_SUCCESS 0
#define WARPKYEHANLE_FAILD -1060



#define  SYMMETRIC_KEY "1234567890123456";
@interface gmrz_jv_ecc_cal : NSObject
{
    
    NSData * publicTag;
    NSData * privateTag;
    
    SecKeyRef publicKeyRef;
    SecKeyRef privateKeyRef;
    
    NSData * symmetricTag;
    NSData * symmetricKeyRef;
}

//ecc algorithm
@property (nonatomic, strong) NSData * publicTag;
@property (nonatomic, strong) NSData * privateTag;


//AES algorithm
@property (nonatomic, strong) NSData * symmetricTag;
@property (nonatomic, strong) NSData * symmetricKeyRef;

// old no use

//ecc keypair generation function
- (BOOL)generateKeyPair:(NSUInteger)keySize ;
- (NSData *)getPublicKeyBits;
- (void)deleteAsymmetricKeys;
- (SecKeyRef)getPrivateKeyRef;
- (SecKeyRef)getPublicKeyRef;


//ecc keypair ENC&DEC function
- (NSData *)getSignatureBytes:(NSData *)plainText;
- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig;



//AES keypair algorithm
- (void)deleteSymmetricKey;
- (int)generateSymmetricKey;
- (NSData *)getSymmetricKeyBytes;


//AES key ENC&DEC function
- (NSData *)aes256_encrypt:(NSString *)key SourceData:(NSData *)SourceData;
- (NSData *)aes256_decrypt:(NSString *)key SourceData:(NSData *)SourceData;


//SHA256 algorithm
- (NSData *)getHashBytes:(NSData *)plainText;







//new cal lay function

//old no use too

- (NSString *) generateECPair:(nonnull NSString*) serviceID
                   sizeInBits:(nonnull NSNumber*)sizeInBits
                       errMsg:(NSString **)errMsg;


-(SecKeyRef)getPrivateKeyRef:(NSString *)serviceID
                         pub:(NSString *)base64pub
                      status:(OSStatus *)status;


-(NSData *)getPublicKeyDataByLabel:(NSString *)label;


-(SecKeyRef)getPrivateKeyRefExt:(NSString *)serviceID
                            pub:(NSString *)base64pub
                         status:(OSStatus *)status;


-(SecKeyRef)getPublicKeyRefExt:(NSString *)base64pub;






//new cal lay function

//old no use too too

-(OSStatus)generateKeyAsync :(NSString *)priId pubId:(NSString *)pubId;

- (OSStatus)useKeyAsyncSign:(NSString *)priId
                      pubId:(NSString *)pubId
                 digestData:(uint8_t *)digestData
               digestLength:(size_t) digestLength
                  signature:(uint8_t *)signature
            signatureLength:(size_t *)signatureLength;


- (OSStatus)useKeyAsyncVerify:(NSString *)priId
                      pubId:(NSString *)pubId
                 digestData:(uint8_t *)digestData
               digestLength:(size_t) digestLength
                  signature:(uint8_t *)signature
            signatureLength:(size_t)signatureLength;


- (OSStatus)deleteKeyAsync:(NSString *)priId pubId:(NSString *)pubId;

- (SecKeyRef)setPrivatecRef:(NSString *)priId pubId:(NSString *)pubId;
- (SecKeyRef )setPublicRef:(NSString *)priId pubId:(NSString *)pubId;
- (NSData *)setPublicData:(NSString *)priId pubId:(NSString *)pubId;

@end
