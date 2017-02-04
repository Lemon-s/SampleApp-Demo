//
//  gmrz_jv_ecc_cal_ext.m
//  TestAkcmd
//
//  Created by Lyndon on 16/6/30.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_jv_ecc_cal_ext.h"
#include "gmrz_jv_util_func.h"
#include "uaf_ak_defs.h"
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#define gmrz_default 0
#define gmrz_keychain 1
#define gmrz_local    2
#define kSymmetricKeyTag		"com.apple.gmrz.jv.symmetrickey"
static const uint8_t symmetricKeyIdentifier[]	= kSymmetricKeyTag;
const static uint8_t * SYMMETRIC_KEY = "1234567890123456";

// Global constants for padding schemes.
#define	kPKCS1					11
#define kTypeOfWrapPadding		kSecPaddingPKCS1
#define kTypeOfSigPadding		kSecPaddingPKCS1


#define kChosenCipherBlockSize	32
#define kChosenCipherKeySize	kCCKeySizeAES256
#define kChosenDigestLength		CC_SHA1_DIGEST_LENGTH
#define SystemVersion [[UIDevice currentDevice] systemVersion].floatValue
enum {
    CSSM_ALGID_NONE =					0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =			CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};





@import LocalAuthentication;
@implementation gmrz_jv_ecc_cal_ext
@synthesize symmetricTag;



static gmrz_jv_ecc_cal_ext *sharedObj = nil;



+(gmrz_jv_ecc_cal_ext *)sharedManager
{
    @synchronized (self)
    {
        if (sharedObj == nil)
        {
            sharedObj = [[self alloc] init];
            
        }
    }
    return sharedObj;
}

- (id)init
{
    @synchronized(self) {
        symmetricTag = [[NSData alloc] initWithBytes:symmetricKeyIdentifier length:sizeof(symmetricKeyIdentifier)];
        return self;
    }
}

+ (id) allocWithZone:(NSZone *)zone //第三步：重写allocWithZone方法
{
    @synchronized (self) {
        if (sharedObj == nil) {
            sharedObj = [super allocWithZone:zone];
            return sharedObj;
        }
    }
    return nil;
}




-(OSStatus)generateKeyAsync :(NSString *)priId
                       pubId:(NSString *)pubId
                   serviceId:(NSString *)serviceId
                   accountId:(NSString *)accountId
{
    CFErrorRef error = NULL;
    SecAccessControlRef __weak sacObjectpri;
    __block OSStatus status = noErr;
    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
    sacObjectpri = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                   kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                   kSecAccessControlUserPresence, &error);
    
    
    // Create parameters dictionary for key generation.
    NSDictionary * parameterspri = @{
                                     
                                     (__bridge id)kSecAttrAccessControl: (__bridge id)sacObjectpri,
                                     (__bridge id)kSecAttrIsPermanent: @YES,
                                     (__bridge id)kSecAttrApplicationTag: priId,
                                     
                                     };
    
    NSDictionary * parameterspub = @{
                                     (__bridge id)kSecAttrIsPermanent: @YES,
                                     (__bridge id)kSecAttrApplicationTag:pubId,
                                     
                                     };
    
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                 (__bridge id)kSecAttrKeySizeInBits: @256,
                                 (__bridge id)kSecUseNoAuthenticationUI: @YES,
                                 (__bridge id)kSecPrivateKeyAttrs: parameterspri,
                                 (__bridge id)kSecPublicKeyAttrs: parameterspub,
                                 };
    
    
    
    // Generate key pair.
    SecKeyRef publicKey, privateKey;
    status = SecKeyGeneratePair(( CFDictionaryRef)parameters, &publicKey, &privateKey);
    if (status == errSecSuccess) {
        // In your own code, here is where you'd store/use the keys.

        CFRelease(privateKey);
        CFRelease(publicKey);
        sacObjectpri = nil;
    }
    else
        return  GENKEYPAIR_FAILED;
    
    
    
    
   
//    sacObjectpri = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//                                                   kSecAttrAccessibleAlways,
//                                                   kSecAccessControlUserPresence, &error);
//    NSDictionary *attributes = @{
//                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
//                                 (__bridge id)kSecAttrService: serviceId,
//                                 (__bridge id)kSecAttrAccount:accountId,
//                                 (__bridge id)kSecValueData: [priId dataUsingEncoding:NSUTF8StringEncoding],
//                                 (__bridge id)kSecUseNoAuthenticationUI: @YES,
//                                 (__bridge id)kSecAttrAccessControl: (__bridge id)sacObjectpri
//                                 };
//    
//    
//
//    status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
////    status = SecItemCopyMatching((__bridge CFDictionaryRef)attributes, (void *)&result);
//    
//    if (status == -25308 || status == -25299) {
//        
//        status = SecItemDelete((__bridge CFDictionaryRef)attributes);
//        status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
//    }
    
    
    return status;
}








-(OSStatus)generateKeyAsync_ios9 :(NSString *)priId pubId:(NSString *)pubId publickeybyte:(UInt8 **)publickeybyte
{
    CFErrorRef error = NULL;
    SecAccessControlRef __weak sacObject;
    __block OSStatus status = noErr;
    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.

    //delete the keypair genrate before
    
    {
        NSDictionary *keygenbefore = @{
                                       (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                       (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                                       (__bridge id)kSecAttrApplicationTag: priId,
                                       (__bridge id)kSecReturnRef: @YES,
                                       
                                       };
        
        SecKeyRef privateKey;
        status = SecItemCopyMatching((__bridge CFDictionaryRef)keygenbefore, (CFTypeRef *)&privateKey);
        
        status = SecItemDelete((__bridge CFDictionaryRef)keygenbefore);
    }
    
    
    
    
//     Create parameters dictionary for key generation.
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);

    
    // Create parameters dictionary for key generation.
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                 (__bridge id)kSecAttrKeySizeInBits: @256,
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrApplicationTag: priId,
                                         },
                                 };

    
    // Generate key pair.
    SecKeyRef publicKey, privateKey;
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    if (status == errSecSuccess) {
        // In your own code, here is where you'd store/use the keys.


        
        NSDictionary *pubDict = @{
                                  (__bridge id)kSecClass              : (__bridge id)kSecClassKey,
                                  (__bridge id)kSecAttrKeyType        : (__bridge id)kSecAttrKeyTypeEC,
                                  (__bridge id)kSecAttrApplicationTag :@"",
                                  (__bridge id)kSecAttrIsPermanent    : @YES,
                                  (__bridge id)kSecValueRef           : (__bridge id)publicKey,
                                  (__bridge id)kSecAttrKeyClass       : (__bridge id)kSecAttrKeyClassPublic,
                                  (__bridge id)kSecReturnData         : @YES
                                  };
        CFTypeRef dataRef = NULL;
        status = SecItemAdd((__bridge CFDictionaryRef)pubDict, &dataRef);
        NSData *publicdata = (__bridge NSData *)(dataRef);
        *publickeybyte = [publicdata bytes];

        
        
        
        CFRelease(privateKey);
        CFRelease(publicKey);
    }
    else
        return GENKEYPAIR_FAILED;
    
    
    
    return status;
}








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
                    methods:(NSString *)methods
{
    // Query private key object from the keychain.
    
    
     OSStatus status = noErr;
    
    SecKeyRef privateKey = NULL;
    // Retrieve the key from the keychain.  No authentication is needed at this point.
    
//    NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
    if (SystemVersion >= 9) {

       NSString *  priID =  [gmrz_jv_util_func asmDB_data_id:serviceId counterid:[[NSBundle mainBundle] bundleIdentifier] username:accountId ext:@"pri"];
       
        status = [self setPrivatecRef_ios9:priID pubId:pubId trancationtext:trancationtext method:method privateKey:&privateKey methods:methods];
    }
    else{
          NSString *  priID =  [gmrz_jv_util_func asmDB_data_id:serviceId counterid:[[NSBundle mainBundle] bundleIdentifier] username:accountId ext:@"pri"];
        status = [self setPrivatecRef:priID pubId:nil serviceId:serviceId accountId:accountId trancationtext:trancationtext privateKey:&privateKey];
    }
    if (status != errSecSuccess) {
        return status;
    }

    if (status == errSecSuccess) {
        // Sign the data in the digest/digestLength memory block.
        printf("%s", " CreateUAFV1RegResponse_useKeyAsyncSign\n");
        
        status = SecKeyRawSign(privateKey, kSecPaddingNone, digestData, digestLength, signature, signatureLength);
        printf("%s", "end CreateUAFV1RegResponse_useKeyAsyncSign\n");
        NSLog(@"%f",SystemVersion);
        
        if (status == errSecSuccess) {
            CFRelease(privateKey);
            //
        }
        else if(SystemVersion >= 10 && status == -25293 && ![gmrz_jv_util_func checkiftouchidlocked])
        {
            NSCondition *conditionLock = [[NSCondition alloc] init];
            LAContext *context = [[LAContext alloc] init];
            NSString* dataUTF8 = nil;
            if([methods isEqualToString:@"reg"])
                dataUTF8 = NSLocalizedString(@"Link your Touch ID fingerprint to your account",nil);
            
            
            else if([methods isEqualToString:@"auth"] && trancationtext != NULL)
                dataUTF8 = [NSString stringWithCString:(char*)trancationtext encoding:NSUTF8StringEncoding];
            else if([methods isEqualToString:@"auth"] && trancationtext == NULL)
                dataUTF8 = NSLocalizedString(@"Log in to your account.",nil);
            
            __block int reg_status;
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication localizedReason:dataUTF8 reply:^(BOOL success, NSError *authenticationError) {
                
                reg_status = authenticationError.code;
//                is_auth_figerprint = YES;
                [conditionLock signal];
            }];
            
            [conditionLock lock];
            [conditionLock wait];
            [conditionLock unlock];
            if (reg_status == 0) {
            
                status = SecKeyRawSign(privateKey, kSecPaddingNone, digestData, digestLength, signature, signatureLength);

            }
           
            
            if (status == errSecSuccess) {
                // In your own code, here is where you'd continue with the signature of the digest.
                CFRelease(privateKey);
                //
            }else{
                CFRelease(privateKey);
                return status;
            }
        }else{
            
            return status;
        }
    }
    
    
    return status;
}


-(OSStatus)useKeyAsyncVerify:(NSString *)priId
                        pubId:(NSString *)pubId
                   digestData:(uint8_t *)digestData
                 digestLength:(size_t) digestLength
                    signature:(uint8_t *)signature
              signatureLength:(size_t )signatureLength
{
    // Query private key object from the keychain.
    
    
    OSStatus status = noErr;
    
    
    
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
            
            CFRelease(publicKey);
        }
        
    }
    
    
    return status;
    
}



-(OSStatus)deleteKeyAsync:(NSString *)priId
                    pubId:(NSString *)pubId
                serviceId:(NSString *)serviceId
                accountId:(NSString *)accountId
{
    
    
    
    OSStatus status = noErr;
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecAttrApplicationTag:priId
                            };
    status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess) {
        return SECITEMDELETE_FAILED;
    }
    
    NSDictionary *querypub = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecAttrApplicationTag:pubId
                            };
    status = SecItemDelete((__bridge CFDictionaryRef)querypub);
    
    return  status;
}


-(OSStatus)deleteKeyAsync_ios9:(NSString *)priId pubId:(NSString *)pubId
{
    OSStatus status = noErr;
    NSDictionary *query = @{
                            (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrApplicationTag: priId,
                            (__bridge id)kSecReturnRef: @YES,
                            };
    
    status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    
    return  status;
}



-(OSStatus)setPrivatecRef:(NSString *)priId
                           pubId:(NSString *)pubId
                           serviceId:(NSString *)serviceId
                           accountId:(NSString *)accountId
                        trancationtext:(uint8_t *)trancationtext
                        privateKey:(SecKeyRef *)privateKey
{
     OSStatus status = noErr;
    
    if (trancationtext != NULL) {
        
        
        NSString * dataUTF8 = [NSString stringWithCString:(char*)trancationtext encoding:NSUTF8StringEncoding];
        NSDictionary *query = @{
                                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                (__bridge id)kSecReturnRef: @YES,
                                //                                (__bridge id)kSecUseOperationPrompt: [NSString stringWithFormat:@"%s", trancationtext],
                                (__bridge id)kSecUseOperationPrompt: dataUTF8,
                                (__bridge id)kSecAttrApplicationTag:priId
                                };

        status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)privateKey);
    }
    else
    {
        NSDictionary *query = @{
                                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                (__bridge id)kSecReturnRef: @YES,
                               (__bridge id)kSecUseOperationPrompt: NSLocalizedString(@"Log in to your account", nil),
                                (__bridge id)kSecAttrApplicationTag:priId
                                };

        status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)privateKey);
    }
  
    if (status == -128) {
        // CFRelease(foundTypeRef);
        return  status;
    }
    else if (status != errSecSuccess && status != 128) {
       // CFRelease(foundTypeRef);
        return  SECITEMCOPYMATCHING_FAILED;
    }
    
    
    return status;
}




-(OSStatus)setPrivatecbyte:(NSString *)priId
                    pubId:(NSString *)pubId
                serviceId:(NSString *)serviceId
                accountId:(NSString *)accountId
               privateKey:(SecKeyRef *)privateKey
{
    OSStatus status = noErr;
    
    
    NSDictionary* uuidAttrs = @{
                                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecAttrService: serviceId,
                                (__bridge id)kSecAttrAccount:accountId,
                                (__bridge id)kSecReturnData: @YES,
                                (__bridge id)kSecUseOperationPrompt: @"check your self"
                                };
    
    NSData* found = nil;
    CFTypeRef foundTypeRef;
    
    NSLog(@"setPrivatecRef SecItemCopyMatching  kSecClassGenericPassword");
    status = SecItemCopyMatching((__bridge CFDictionaryRef)uuidAttrs, &foundTypeRef);
    NSLog(@"end setPrivatecRef SecItemCopyMatching");
    if (status != errSecSuccess) {
        CFRelease(foundTypeRef);
        return  SECITEMCOPYMATCHING_FAILED;
        
    }
    
    found = (__bridge NSData *)(foundTypeRef);
    //    NSData * aa =[found objectForKey:(__bridge id)(kSecValueData)];
    NSString* uuid =  [[NSString alloc] initWithData:found  encoding:NSUTF8StringEncoding];
    
    
    NSLog(@" setPrivatecRef SecItemCopyMatching  privateKey");
    status = SecItemCopyMatching((__bridge CFDictionaryRef)@{
                                                             (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                                             (__bridge id)kSecReturnData: @YES,
                                                             (__bridge id)kSecAttrApplicationTag:uuid
                                                             }, (CFTypeRef *)privateKey);
    
    
    NSLog(@"end setPrivatecRef SecItemCopyMatching");
    if (status != errSecSuccess) {
        CFRelease(foundTypeRef);
        return  SECITEMCOPYMATCHING_FAILED;
    }
    
    return status;
}





-(OSStatus)setPrivatecRef_ios9:(NSString *)priId pubId:(NSString *)pubId trancationtext:(uint8_t *)trancationtext method:(NSInteger)method privateKey:(SecKeyRef *)privateKey methods :(NSString *)methods
{
    
    OSStatus status = noErr;

    NSString *dataUTF8;
    
    NSDictionary *query;
    NSCondition *conditionLock = [[NSCondition alloc] init];
    self.mConditionLock = conditionLock;
    
    
    NSInteger __block __weak auth_status = 0;
    BOOL __block __weak is_auth_figerprint = NO;
    
    if (trancationtext != NULL)
        dataUTF8 = [NSString stringWithCString:(char*)trancationtext encoding:NSUTF8StringEncoding];
    else
        dataUTF8 = NSLocalizedString(@"Log in to your account.", nil);
    
    
    
    if ([methods isEqualToString:@"auth"])
    {
        if (method == gmrz_local) {
            
        
        LAContext *context = [[LAContext alloc] init];
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:dataUTF8 reply:^(BOOL success, NSError *authenticationError) {
            auth_status = authenticationError.code;
            is_auth_figerprint = YES;
            [self.mConditionLock signal];
        }];
        
        [conditionLock lock];
        
        NSLog(@"authencation operation staring!");
        [conditionLock wait];
        [conditionLock unlock];
        NSLog(@"authencation operation success!");
        
        if (auth_status) {
            return auth_status;
        }
        
        query = @{
                                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                                (__bridge id)kSecAttrApplicationTag: priId,
                                (__bridge id)kSecReturnRef: @YES,
                                (__bridge id)kSecUseAuthenticationContext:context,
                                };
            
            
        }
        else if(method == gmrz_keychain || method == gmrz_default) {
            
            query = @{
                                    (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                                    (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                                    (__bridge id)kSecAttrApplicationTag: priId,
                                    (__bridge id)kSecReturnRef: @YES,
                                    (__bridge id)kSecUseOperationPrompt: dataUTF8
                                    };
            
            
        }
    
    }
    else
    {
        query = @{
                  (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                  (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                  (__bridge id)kSecAttrApplicationTag: priId,
                  (__bridge id)kSecReturnRef: @YES,
                   (__bridge id)kSecUseOperationPrompt: NSLocalizedString(@"Link your Touch ID fingerprint to your account.", nil),
                  };
    }
    
    
    

    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)privateKey);

   
    if (status == -128) {
        // CFRelease(foundTypeRef);
        return  status;
    }
    else if (status != errSecSuccess && status != 128) {
        // CFRelease(foundTypeRef);
        return  SECITEMCOPYMATCHING_FAILED;
    }
    
    return status;
}

-(OSStatus)setPrivatecRef_ios10:(NSString *)priId pubId:(NSString *)pubId trancationtext:(uint8_t *)trancationtext method:(NSInteger)method privateKey:(SecKeyRef *)privateKey methods :(NSString *)methods
{
    
    OSStatus status = noErr;
    
    NSString *dataUTF8;
    
    NSDictionary *query;
    NSCondition *conditionLock = [[NSCondition alloc] init];
    self.mConditionLock = conditionLock;
    
    
    NSInteger __block __weak auth_status = 0;
    BOOL __block __weak is_auth_figerprint = NO;
    
    if (trancationtext != NULL)
        dataUTF8 = [NSString stringWithCString:(char*)trancationtext encoding:NSUTF8StringEncoding];
    else
        dataUTF8 = NSLocalizedString(@"Log in to your account.", nil);
    
    
    
    if ([methods isEqualToString:@"auth"])
    {
        if (method == gmrz_local) {
            
            
            LAContext *context = [[LAContext alloc] init];
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:dataUTF8 reply:^(BOOL success, NSError *authenticationError) {
                auth_status = authenticationError.code;
                is_auth_figerprint = YES;
                [self.mConditionLock signal];
            }];
            
            [conditionLock lock];
            
            NSLog(@"authencation operation staring!");
            [conditionLock wait];
            [conditionLock unlock];
            NSLog(@"authencation operation success!");
            
            if (auth_status) {
                return auth_status;
            }
            
            query = @{
                      (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                      (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                      (__bridge id)kSecAttrApplicationTag: priId,
                      (__bridge id)kSecReturnRef: @YES,
                      (__bridge id)kSecUseAuthenticationContext:context,
                      };
            
            
        }
        else if(method == gmrz_keychain || method == gmrz_default) {
            
            query = @{
                      (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                      (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                      (__bridge id)kSecAttrApplicationTag: priId,
                      (__bridge id)kSecReturnRef: @YES,
                      (__bridge id)kSecUseOperationPrompt: dataUTF8
                      };
            
            
        }
        
    }
    else
    {
        query = @{
                  (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                  (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                  (__bridge id)kSecAttrApplicationTag: priId,
                  (__bridge id)kSecReturnRef: @YES,
                  (__bridge id)kSecUseOperationPrompt: NSLocalizedString(@"Link your Touch ID fingerprint to your account.", nil),
                  };
    }
    
    
    
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)privateKey);
    
    
    if (status == -128) {
        // CFRelease(foundTypeRef);
        return  status;
    }
    else if (status != errSecSuccess && status != 128) {
        // CFRelease(foundTypeRef);
        return  SECITEMCOPYMATCHING_FAILED;
    }
    
    return status;
}



-(SecKeyRef )setPublicRef:(NSString *)priId pubId:(NSString *)pubId
{
    OSStatus status = noErr;
    
    NSDictionary* keyAttrs = @{
                               (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                               (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                               (__bridge id)kSecAttrApplicationTag: pubId,
                               (__bridge id)kSecReturnRef: @YES,
                               
                               };
    
    SecKeyRef publicKey = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttrs, (CFTypeRef *)&publicKey);
    
    return publicKey;
}


-(NSData *)setPublicData:(NSString *)priId pubId:(NSString *)pubId
{
    
    OSStatus status = noErr;
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
    return (__bridge NSData *)(result);
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

    
    memset((void *)symmetricKey, 0x0, kChosenCipherKeySize);
    
    sanityCheck = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
   
    
    self.symmetricKeyRef = [[NSData alloc] initWithBytes:(const void *)symmetricKey length:kChosenCipherKeySize];
    
    // Add the wrapped key data to the container dictionary.
    [symmetricKeyAttr setObject:self.symmetricKeyRef
                         forKey:(id)kSecValueData];
    
    // Add the symmetric key to the keychain.
    sanityCheck = SecItemAdd((CFDictionaryRef) symmetricKeyAttr, NULL);

    
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
- (NSData *)aes256_encrypt:(NSString *)key SourceData:(NSData *)SourceData  //加密
{
    
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [SourceData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeAES128,
                                          NULL,
                                          [SourceData bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}



- (size_t)aes256_encrypt_ext:(uint8_t *)SourceData  //加密
            SourceDataLength:(uint8_t)SourceDataLength
                     dstData:(uint8_t **)dstData
               dstDataLength:(uint8_t *)dstDataLength
{
    
    
    
    int dataLength = SourceDataLength;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    unsigned char *buffer = (unsigned char *)malloc(bufferSize + 1);
    size_t numBytesEncrypted = 512;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          SYMMETRIC_KEY, kCCBlockSizeAES128,
                                          NULL,
                                          SourceData, SourceDataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        
        *dstData = buffer;
        *dstDataLength = numBytesEncrypted;
        return WARPKYEHANLE_SUCCESS;
        
    }
    
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





- (size_t)aes256_decrypt_ext:(uint8_t *)SourceData  //加密
            SourceDataLength:(uint8_t)SourceDataLength
                     dstData:(uint8_t **)dstData
               dstDataLength:(uint8_t *)dstDataLength
{
    int dataLength = SourceDataLength;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    unsigned char *buffer = (unsigned char *)malloc(bufferSize + 1);
    size_t numBytesEncrypted = 512;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          SYMMETRIC_KEY, kCCBlockSizeAES128,
                                          NULL,
                                          SourceData, SourceDataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        
        *dstData = buffer;
        *dstDataLength = numBytesEncrypted;
        return WARPKYEHANLE_SUCCESS;
        
    }
    
    return WARPKYEHANLE_FAILD;
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
   
    
    if(!plainText)
    {
        printf("getHashBytes:  param is nil\n");
        return nil;
    }
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    memset(digest, 0, CC_SHA256_DIGEST_LENGTH);
    
    CC_SHA256([plainText bytes], [plainText length], digest);

    
    return  [NSData dataWithBytes:digest length:32];
}



- (uint8_t *)getHashBytesext:(uint8_t *)plainText length:(int)length {
    
    
    if(!plainText)
    {
        printf("getHashBytes:  param is nil\n");
        return nil;
    }
    
    uint8_t  * digest = (uint8_t *)malloc(sizeof(uint8_t) * CC_SHA256_DIGEST_LENGTH);
    
    memset(digest, 0x0, CC_SHA256_DIGEST_LENGTH);
    
    CC_SHA256(plainText, length, digest);
    
    
    return  digest;
}

- (uint8_t *)getSHA1Bytesext:(uint8_t *)plainText length:(int)length{
    
    
    if(!plainText)
    {
        printf("getHashBytes:  param is nil\n");
        return nil;
    }
    
    uint8_t  * digest = (uint8_t *)malloc(sizeof(uint8_t) * CC_SHA1_DIGEST_LENGTH);
    
    memset(digest, 0x0, CC_SHA1_DIGEST_LENGTH);
    
    CC_SHA1(plainText, length, digest);
    
    
    return  digest;
}






@end
