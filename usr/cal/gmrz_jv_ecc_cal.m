//
//  gmrz_jv_ecc_cal.m
//  gmrz_AuthSDK
//
//  Created by Lyndon on 16/4/28.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_jv_ecc_cal.h"
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>





// Global constants for padding schemes.
#define	kPKCS1					11
#define kTypeOfWrapPadding		kSecPaddingPKCS1
#define kTypeOfSigPadding		kSecPaddingPKCS1


#define kChosenCipherBlockSize	32
#define kChosenCipherKeySize	kCCKeySizeAES256
#define kChosenDigestLength		CC_SHA1_DIGEST_LENGTH


#define kPublicKeyTag			"com.apple.gmrz.jv.publickey"
#define kPrivateKeyTag			"com.apple.gmrz.jv.privatekey"
#define kSymmetricKeyTag		"com.apple.gmrz.jv.symmetrickey"


#if TARGET_OS_SIMULATOR
static BOOL isSimulator = YES;
#else
static BOOL isSimulator = NO;
#endif



@implementation gmrz_jv_ecc_cal
@synthesize publicTag, privateTag ,symmetricTag;


#if DEBUG
#define LOGGING_FACILITY(X, Y)	\
NSAssert(X, Y);

#define LOGGING_FACILITY1(X, Y, Z)	\
NSAssert1(X, Y, Z);
#else
#define LOGGING_FACILITY(X, Y)	\
if (!(X)) {			\
NSLog(Y);		\
}

#define LOGGING_FACILITY1(X, Y, Z)	\
if (!(X)) {				\
NSLog(Y, Z);		\
}
#endif

enum {
    CSSM_ALGID_NONE =					0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =			CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};


static const uint8_t publicKeyIdentifier[]		= kPublicKeyTag;
static const uint8_t privateKeyIdentifier[]		= kPrivateKeyTag;
static const uint8_t symmetricKeyIdentifier[]	= kSymmetricKeyTag;



//Class Init
-(id)init {
    if (self = [super init])
    {
        // Tag data to search for keys.
        privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
        publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
            }
    
    symmetricTag = [[NSData alloc] initWithBytes:symmetricKeyIdentifier length:sizeof(symmetricKeyIdentifier)];

    
    return self;
}


////
//
//
//ECC algorithm generate
//
//
//
//
//


//生成ECC 密钥对方法
- (BOOL)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    
//    LOGGING_FACILITY1( keySize == 512 || keySize == 1024 || keySize == 2048, @"%d is an invalid and unsupported key size.", keySize );
    
    // First delete current keys.
    [self deleteAsymmetricKeys];
    
     CFErrorRef error = NULL;
     SecAccessControlRef sacObjectpri;
    sacObjectpri = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                   kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                   kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(id)kSecAttrKeySizeInBits];
     [keyPairAttr setObject:CFBridgingRelease(sacObjectpri) forKey:(id)kSecAttrAccessControl];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(id)kSecAttrApplicationTag];
    [privateKeyAttr setObject:(id)kSecAttrTokenIDSecureEnclave forKey:(id)kSecAttrTokenID];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);

    return true;
}








#pragma mark - Tools

- (NSString *)keychainErrorToString:(OSStatus)error {
    NSString *message = [NSString stringWithFormat:@"%ld", (long)error];
    
    switch (error) {
        case errSecSuccess:
            message = @"success";
            break;
            
        case errSecDuplicateItem:
            message = @"error item already exists";
            break;
            
        case errSecItemNotFound :
            message = @"error item not found";
            break;
            
        case errSecAuthFailed:
            message = @"error item authentication failed";
            break;
            
        default:
            break;
    }
    
    return message;
}






//检索ECC密钥对

- (NSData *)getPublicKeyBits {
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
    
    // Get the key bits.
    sanityCheck = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (void *)&publicKeyBits);
    
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }
    
    queryPublicKey = nil;
    
    return publicKeyBits;
}






//删除ecc秘钥对
- (void)deleteAsymmetricKeys {
    OSStatus sanityCheck = noErr;
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    
    // Set the private key query dictionary.
    [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
    
    // Delete the private key.
    sanityCheck = SecItemDelete((CFDictionaryRef)queryPrivateKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing private key, OSStatus == %d.", sanityCheck );
    
    // Delete the public key.
    sanityCheck = SecItemDelete((CFDictionaryRef)queryPublicKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing public key, OSStatus == %d.", sanityCheck );
    
    
    
//    CFRelease((__bridge CFTypeRef)(queryPrivateKey));
//    CFRelease((__bridge CFTypeRef)(queryPublicKey));
    if (publicKeyRef) CFRelease(publicKeyRef);
    if (privateKeyRef) CFRelease(privateKeyRef);
}




- (SecKeyRef)getPrivateKeyRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if (privateKeyRef == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        
        // Set the private key query dictionary.
        [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
        [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        
        if (sanityCheck != noErr)
        {
            privateKeyReference = NULL;
        }
        
        queryPrivateKey = nil;
    } else {
        privateKeyReference = privateKeyRef;
    }
    
    return privateKeyReference;
}


- (SecKeyRef)getPublicKeyRef{
    
    
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (publicKeyRef == NULL) {
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
        [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(id)kSecAttrKeyTypeEC forKey:(id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        
        if (sanityCheck != noErr)
        {
            publicKeyReference = NULL;
        }
        
        queryPublicKey = nil;
    } else {
        publicKeyReference = publicKeyRef;
    }
    
    return publicKeyReference;
}

////
//
//
//ECC algorithm ENC&DNC
//
//
//
//
//



- (NSData *)getSignatureBytes:(NSData *)plainText
{
    OSStatus sanityCheck = noErr;
    NSData * signedResult = nil;
    
    uint8_t * signedBytes = NULL;
    size_t signedBytesSize = 0;
    
    SecKeyRef privateKey = NULL;
    
    privateKey = [self getPrivateKeyRef];
    signedBytesSize = SecKeyGetBlockSize(privateKey);
    
    // Malloc a buffer to hold signature.
    signedBytes = malloc( signedBytesSize * sizeof(uint8_t) );
    memset((void *)signedBytes, 0x0, signedBytesSize);
    
    
    uint8_t * signedHashBytes = NULL;
    size_t signedHashBytesSize = 0;
    signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    
    // Malloc a buffer to hold signature.
    signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
    memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
    
    // Sign the data.
//    sanityCheck = SecKeyRawSign(privateKey,
//                                kTypeOfSigPadding,
//                                (const uint8_t *)[[self getHashBytes:plainText] bytes],
//                                kChosenDigestLength,
//                                (uint8_t *)signedBytes,
//                                &signedBytesSize
//                                );
    
    sanityCheck = SecKeyRawSign(privateKey,
                                kSecPaddingPKCS1,
                                (const uint8_t *)[plainText bytes],
                                plainText.length,
                                (uint8_t *)signedHashBytes,
                                &signedHashBytesSize
                                );
    
    
//    LOGGING_FACILITY1( sanityCheck == noErr, @"Problem signing the SHA1 hash, OSStatus == %d.", sanityCheck );
    
    //the data signed without hash operation
    signedResult = [NSData dataWithBytes:(const void *)signedBytes length:(NSUInteger)signedBytesSize];
    
    if (signedBytes) free(signedBytes);
    
    return signedResult;
}


//- (NSData *)getSignatureBytes:(NSData *)plainText
//{
//    OSStatus sanityCheck = noErr;
//    size_t cipherBufferSize = 0;
//    size_t keyBufferSize = 0;
//    SecKeyRef privateKey = NULL;
//
//    
//    NSData * cipher = nil;
//    uint8_t * cipherBuffer = NULL;
//    
//    privateKey = [self getPrivateKeyRef];
//    
//    // Calculate the buffer sizes.
//    cipherBufferSize = SecKeyGetBlockSize(privateKey);
//    keyBufferSize = [plainText length];
//    
////    if (kTypeOfWrapPadding == kSecPaddingNone) {
////        LOGGING_FACILITY( keyBufferSize <= cipherBufferSize, @"Nonce integer is too large and falls outside multiplicative group." );
////    } else {
////        LOGGING_FACILITY( keyBufferSize <= (cipherBufferSize - 11), @"Nonce integer is too large and falls outside multiplicative group." );
////    }
//    
//    // Allocate some buffer space. I don't trust calloc.
//    cipherBuffer = malloc( cipherBufferSize * sizeof(uint8_t) );
//    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
//    
//    // Encrypt using the public key.
//    sanityCheck = SecKeyEncrypt(privateKey,
//                                kTypeOfWrapPadding,
//                                (const uint8_t *)[plainText bytes],
//                                keyBufferSize,
//                                cipherBuffer,
//                                &cipherBufferSize
//                                );
//    
//    // Build up cipher text blob.
//    cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];
//    
//    if (cipherBuffer) free(cipherBuffer);
//    
//    return cipher;
//}
//




- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig
{
    size_t signedHashBytesSize = 0;
    OSStatus sanityCheck = noErr;
    
    // Get the size of the assymetric block.
    signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    
    sanityCheck = SecKeyRawVerify(	publicKey,
                                  kTypeOfSigPadding,
                                  (const uint8_t *)[plainText bytes],
                                  kChosenDigestLength,
                                  (const uint8_t *)[sig bytes],
                                  signedHashBytesSize
                                  );
    
    return (sanityCheck == noErr) ? YES : NO;

}












////
//
//
//AES algorithm generate
//
//
//
//
//

- (void)deleteSymmetricKey
{
    OSStatus sanityCheck = noErr;
    
    NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];
    
    // Set the symmetric key query dictionary.
    [querySymmetricKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [querySymmetricKey setObject:symmetricTag forKey:(id)kSecAttrApplicationTag];
    [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(id)kSecAttrKeyType];
    
    // Delete the symmetric key.
    sanityCheck = SecItemDelete((CFDictionaryRef)querySymmetricKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing symmetric key, OSStatus == %d.", sanityCheck );
    
    querySymmetricKey = nil;
    symmetricKeyRef = nil;
}



- (int)generateSymmetricKey
{
    OSStatus sanityCheck = noErr;
    uint8_t * symmetricKey = NULL;
    
    // First delete current symmetric key.
    [self deleteSymmetricKey];
    
    // Container dictionary
    NSMutableDictionary *symmetricKeyAttr = [[NSMutableDictionary alloc] init];
    [symmetricKeyAttr setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [symmetricKeyAttr setObject:symmetricTag forKey:(id)kSecAttrApplicationTag];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(id)kSecAttrKeyType];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)] forKey:(id)kSecAttrKeySizeInBits];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)]	forKey:(id)kSecAttrEffectiveKeySize];
    [symmetricKeyAttr setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanEncrypt];
    [symmetricKeyAttr setObject:(id)kCFBooleanTrue forKey:(id)kSecAttrCanDecrypt];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanDerive];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanSign];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanVerify];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanWrap];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(id)kSecAttrCanUnwrap];

    
    // Allocate some buffer space. I don't trust calloc.
    symmetricKey = malloc( kChosenCipherKeySize * sizeof(uint8_t) );
    
    LOGGING_FACILITY( symmetricKey != NULL, @"Problem allocating buffer space for symmetric key generation." );
    
    memset((void *)symmetricKey, 0x0, kChosenCipherKeySize);
    
    sanityCheck = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
    LOGGING_FACILITY1( sanityCheck == noErr, @"Problem generating the symmetric key, OSStatus == %d.", sanityCheck );
    
    self.symmetricKeyRef = [[NSData alloc] initWithBytes:(const void *)symmetricKey length:kChosenCipherKeySize];
    
    // Add the wrapped key data to the container dictionary.
    [symmetricKeyAttr setObject:self.symmetricKeyRef
                         forKey:(id)kSecValueData];
    
    // Add the symmetric key to the keychain.
    sanityCheck = SecItemAdd((CFDictionaryRef) symmetricKeyAttr, NULL);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecDuplicateItem, @"Problem storing the symmetric key in the keychain, OSStatus == %d.", sanityCheck );
    
    if (symmetricKey) free(symmetricKey);
    symmetricKeyAttr = nil;
    
    return 0;
}



- (NSData *)getSymmetricKeyBytes
{
    
    OSStatus sanityCheck = noErr;
    NSData * symmetricKeyReturn = nil;
    
    if (self.symmetricKeyRef == nil) {
        NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];
        
        // Set the private key query dictionary.
        [querySymmetricKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
        [querySymmetricKey setObject:symmetricTag forKey:(id)kSecAttrApplicationTag];
        [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(id)kSecAttrKeyType];
        [querySymmetricKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
        
        // Get the key bits.
        sanityCheck = SecItemCopyMatching((CFDictionaryRef)querySymmetricKey, (void *)&symmetricKeyReturn);
        
        if (sanityCheck == noErr && symmetricKeyReturn != nil) {
            self.symmetricKeyRef = symmetricKeyReturn;
        } else {
            self.symmetricKeyRef = nil;
        }
        
        querySymmetricKey = nil;
    } else {
        symmetricKeyReturn = self.symmetricKeyRef;
    }
    
    return symmetricKeyReturn;

}




////
//
//
//AES algorithm function
//
//
//
//
//
- (size_t)aes256_encrypt_ext:(uint8_t *)key
                  SourceData:(uint8_t *)SourceData  //加密
                SourceDataLength:(uint8_t)SourceDataLength
                     dstData:(uint8_t *)dstData
                dstDataLength:(uint16_t *)dstDataLength
{

   
 
    int dataLength = SourceDataLength;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    unsigned char *buffer = (unsigned char *)malloc(bufferSize + 1);
    size_t numBytesEncrypted = 512;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          key, kCCBlockSizeAES128,
                                          NULL,
                                          SourceData, SourceDataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        
        dstData = buffer;
        *dstDataLength = bufferSize;
        return WARPKYEHANLE_FAILD;
        
    }
    free(buffer);
    return WARPKYEHANLE_FAILD;
}













- (NSData *)aes256_decrypt:(NSString *)key SourceData:(NSData *)SourceData //解密
{
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [SourceData length];;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeAES128,
                                          NULL,
                                          [SourceData bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        
    }
    free(buffer);
    return nil;
}


////
//
//
//SHA256  algorithm function
//
//
//
//
//
- (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA256_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    
    // Initialize the context.
    CC_SHA256_Init(&ctx);
    // Perform the hash.
    CC_SHA256_Update(&ctx, (void *)[plainText bytes], (CC_LONG)[plainText length]);
    // Finalize the output.
    CC_SHA256_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    
    if (hashBytes) free(hashBytes);
    
    return hash;
}




//callay new coding



- (NSString *) generateECPair:(nonnull NSString*) serviceID
                   sizeInBits:(nonnull NSNumber*)sizeInBits
                       errMsg:(NSString **)errMsg
{
    
    
    
    CFErrorRef sacErr = NULL;
    SecAccessControlRef sacObject;
    
    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage,
                                                &sacErr);
    
    if (sacErr) {
        //        *errMsg = [(__bridge NSError *)sacErr description];
        return nil;
    }
    
    // Create parameters dictionary for key generation.
    NSString* uuid = @"123456789011";
    NSString* pubKeyLabel = @"123456789011";
    NSMutableDictionary *privateKeyAttrs = [NSMutableDictionary dictionaryWithDictionary: @{
                                                                                            (__bridge id)kSecAttrIsPermanent: @YES,
                                                                                            (__bridge id)kSecAttrApplicationTag: uuid,
                                                                                   
                                                                                            }];
    
    if (!isSimulator) {
        [privateKeyAttrs setObject:(__bridge id)sacObject forKey:(__bridge id)kSecAttrAccessControl];
        //    [privateKeyAttrs setObject:(__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly forKey:(__bridge id)kSecAttrAccessible];
    }
    
    NSDictionary *publicKeyAttrs = @{
                                     (__bridge id)kSecAttrIsPermanent: isSimulator ? @YES : @NO,
                                     (__bridge id)kSecAttrApplicationTag: pubKeyLabel,
                                     
                                     };
    
    NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithDictionary: @{
                                                                                       (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                                                                       (__bridge id)kSecAttrKeySizeInBits: sizeInBits,
                                                                                       (__bridge id)kSecPrivateKeyAttrs: privateKeyAttrs,
                                                                                       (__bridge id)kSecPublicKeyAttrs: publicKeyAttrs,
                                                                                       }];
    
    if (!isSimulator && floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_8_0) {
        NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
        if (os.majorVersion >= 9) {
            [parameters setObject:(__bridge id)kSecAttrTokenIDSecureEnclave forKey:(__bridge id)kSecAttrTokenID];
        }
    }
    
    SecKeyRef publicKey, privateKey;
    
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    if (status != errSecSuccess) {
        //        *errMsg = keychainStatusToString(status);


        return nil;
    }
    
    if (!isSimulator) {
        status = SecItemAdd((__bridge CFDictionaryRef)@{
                                                        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                                                        (__bridge id)kSecAttrApplicationTag: pubKeyLabel,
                                                        (__bridge id)kSecValueRef: (__bridge id)publicKey
                                                        }, nil);
        
        if (status != errSecSuccess) {
            CFRelease(privateKey);
            CFRelease(publicKey);
            //            *errMsg = keychainStatusToString(status);
            return nil;
        }
    }
    
    NSData *data = [self getPublicKeyDataByLabel:pubKeyLabel];
    NSString* base64str = [data base64EncodedStringWithOptions:0];
    
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                0, &sacErr);
    
    status = SecItemAdd((__bridge CFDictionaryRef)@{
                                                    (__bridge id)kSecAttrAccessControl: (__bridge id)sacObject,
                                                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                                    (__bridge id)kSecAttrService: serviceID,
                                                    (__bridge id)kSecAttrAccount:base64str,
                                                    (__bridge id)kSecAttrGeneric:uuid,
                                                    }, nil);
    if (status != errSecSuccess) {
        CFRelease(privateKey);
        CFRelease(publicKey);
        //        *errMsg = keychainStatusToString(status);
        return nil;
    }
    CFRelease(privateKey);
    CFRelease(publicKey);
    
    return base64str;
}



-(NSData *)getPublicKeyDataByLabel:(NSString *)label
{
    
    NSDictionary* keyAttrs = @{
                               (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                               (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                               (__bridge id)kSecAttrApplicationTag: label,
                               (__bridge id)kSecReturnData: @YES,
                               };
    
    CFTypeRef result;
    OSStatus sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, &result);
    
    if (sanityCheck != noErr)
    {
        return nil;
    }
    
    return CFBridgingRelease(result);
}




-(SecKeyRef)getPrivateKeyRef:(NSString *)serviceID
                         pub:(NSString *)base64pub
                      status:(OSStatus *)status
{
    NSDictionary* uuidAttrs = @{
                                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecAttrService: serviceID,
                                (__bridge id)kSecAttrAccount:base64pub,
                                (__bridge id)kSecReturnAttributes: @YES,
                                };
    
    NSDictionary* found = nil;
    CFTypeRef foundTypeRef = NULL;
    *status = SecItemCopyMatching((__bridge CFDictionaryRef) uuidAttrs, (CFTypeRef*)&foundTypeRef);
    
    if (*status != errSecSuccess) {
        return nil;
    }
    
    found = (__bridge NSDictionary*)(foundTypeRef);
    NSString* uuid = [found objectForKey:(__bridge id)(kSecAttrGeneric)];
    return [self getKeyRefByLabel:uuid status:status];
}

-(SecKeyRef)getPublicKeyRef:(NSString *)base64pub
{
    NSDictionary* keyAttrs = @{
                               (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                               (__bridge id)kSecReturnRef: @YES,
                               (__bridge id)kSecAttrApplicationTag: base64pub
                               };
    
    SecKeyRef keyRef;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (CFTypeRef *)&keyRef);
    if (status != errSecSuccess)
    {
        return nil;
    }
    
    return keyRef;
}


-(SecKeyRef)getKeyRefByLabel:(NSString *)label status:(OSStatus*)status
{
    SecKeyRef keyRef;
    *status = SecItemCopyMatching((__bridge CFDictionaryRef)@{
                                                              (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                              (__bridge id)kSecReturnRef: @YES,
                                                              (__bridge id)kSecAttrApplicationLabel:label
                                                              }, (CFTypeRef *)&keyRef);
    
    if (*status != errSecSuccess)
    {
        return nil;
    }
    
    return keyRef;
}


-(SecKeyRef)getPrivateKeyRefExt:(NSString *)serviceID
                         pub:(NSString *)base64pub
                      status:(OSStatus *)status
{
    NSDictionary* uuidAttrs = @{
                                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecAttrService: serviceID,
                                (__bridge id)kSecAttrAccount:base64pub,
                                (__bridge id)kSecReturnAttributes: @YES,
                                };
    
    NSDictionary* found = nil;
    CFTypeRef foundTypeRef = NULL;
    *status = SecItemCopyMatching((__bridge CFDictionaryRef) uuidAttrs, (CFTypeRef*)&foundTypeRef);
    
    if (*status != errSecSuccess) {
        return nil;
    }
    
    found = (__bridge NSDictionary*)(foundTypeRef);
    NSString* uuid = [found objectForKey:(__bridge id)(kSecAttrGeneric)];
    return [self getKeyRefByLabel:uuid status:status];
}





-(SecKeyRef)getPublicKeyRefExt:(NSString *)base64pub
{
    NSDictionary* keyAttrs = @{
                               (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                               (__bridge id)kSecReturnRef: @YES,
                               (__bridge id)kSecAttrApplicationTag: base64pub,
                               (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeEC
                               };
    
    SecKeyRef keyRef;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (CFTypeRef *)&keyRef);
    if (status != errSecSuccess)
    {
        return nil;
    }
    
    return keyRef;
}

- (void)deleteKeyAsync:(NSString *)base64pub{
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecAttrApplicationTag: base64pub
                           
                            
                            };
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        
        
    });
}


































-(OSStatus)generateKeyAsync :(NSString *)priId pubId:(NSString *)pubId
{
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject;
    __block OSStatus status = noErr;
    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
    
    // Create parameters dictionary for key generation.
    NSDictionary *parameters = @{
                                 //        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                 (__bridge id)kSecAttrKeySizeInBits: @256,
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrAccessControl: (__bridge id)sacObject,
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrApplicationTag: priId,
                                         },
                                 (__bridge id)kSecPublicKeyAttrs: @{
                                         
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrApplicationTag: pubId,
                                         },
                                 
                                 };
    
    if (!isSimulator && floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_8_0) {
        NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
        if (os.majorVersion >= 9) {
            [parameters setValue:(__bridge id)kSecAttrTokenIDSecureEnclave forKey:(__bridge id)kSecAttrTokenID];
        }
    }

    
           // Generate key pair.
        SecKeyRef publicKey, privateKey;
        status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
        if (status == errSecSuccess) {
            // In your own code, here is where you'd store/use the keys.

            CFRelease(privateKey);
            CFRelease(publicKey);
        }

        

    return status;
}






- (OSStatus)useKeyAsyncSign:(NSString *)priId
                                   pubId:(NSString *)pubId
                              digestData:(uint8_t *)digestData
                            digestLength:(size_t) digestLength
                               signature:(uint8_t *)signature
                         signatureLength:(size_t *)signatureLength
{
    // Query private key object from the keychain.
    
    
    __block OSStatus status = noErr;
   
    
   
        // Retrieve the key from the keychain.  No authentication is needed at this point.
        SecKeyRef privateKey = [self setPrivatecRef:priId pubId:pubId];
        if (!privateKey) {
            status = -1;
        }
        //
        if (status == errSecSuccess) {
            // Sign the data in the digest/digestLength memory block.
            status = SecKeyRawSign(privateKey, kSecPaddingPKCS1, digestData, digestLength, signature, signatureLength);

            
            if (status == errSecSuccess) {
                // In your own code, here is where you'd continue with the signature of the digest.
                
                //
                CFRelease(privateKey);
            }
            
        }

    
    return status;
}


- (OSStatus)useKeyAsyncVerify:(NSString *)priId
                      pubId:(NSString *)pubId
                 digestData:(uint8_t *)digestData
               digestLength:(size_t) digestLength
                  signature:(uint8_t *)signature
            signatureLength:(size_t )signatureLength
{
    // Query private key object from the keychain.
    
    
    __block OSStatus status = noErr;
    
    
    
    // Retrieve the key from the keychain.  No authentication is needed at this point.
    SecKeyRef publicKey = [self setPublicRef:priId pubId:pubId];
    if (!publicKey) {
        status = -1;
    }
    //
    if (status == errSecSuccess) {
        // Sign the data in the digest/digestLength memory block.
        status = SecKeyRawVerify(publicKey, kSecPaddingPKCS1, digestData, digestLength, signature, signatureLength);
        
        
        if (status == errSecSuccess) {
            // In your own code, here is where you'd continue with the signature of the digest.
            
            //
        }
        
    }
    
    
    return status;

}



- (OSStatus)deleteKeyAsync:(NSString *)priId pubId:(NSString *)pubId
{
    __block OSStatus status = noErr;
    NSDictionary *query = @{
                            //        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrApplicationTag: priId,
                            (__bridge id)kSecReturnRef: @YES,
                            };
    
    status = SecItemDelete((__bridge CFDictionaryRef)query);
        

    return  status;
}



- (SecKeyRef)setPrivatecRef:(NSString *)priId pubId:(NSString *)pubId
{
    __block OSStatus status = noErr;
    
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrApplicationTag: priId,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecUseOperationPrompt: @"Authenticate to sign data"
                            };
    SecKeyRef privateKey = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (void *)&privateKey);

    
    return privateKey;
}




- (SecKeyRef )setPublicRef:(NSString *)priId pubId:(NSString *)pubId
{
    __block OSStatus status = noErr;
    
    NSDictionary* keyAttrs = @{
                                  (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                  (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                                  (__bridge id)kSecAttrApplicationTag: pubId,
                                  (__bridge id)kSecReturnRef: @YES,
                                  
                                  };

    SecKeyRef publicKey = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (void *)&publicKey);
    
    return publicKey;
}


- (NSData *)setPublicData:(NSString *)priId pubId:(NSString *)pubId
{
    __block OSStatus status = noErr;
    CFTypeRef result;
    NSDictionary* keyAttrs = @{
                               (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                               (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                               (__bridge id)kSecAttrApplicationTag: pubId,
                               (__bridge id)kSecReturnData: @YES,
                               
                               };
    
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (void *)&result);
    if (status != noErr) {
        return nil;
    }
    return CFBridgingRelease(result);
}




@end
