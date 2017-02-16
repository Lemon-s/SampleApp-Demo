//
//  gmrz_jv_asm_db.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/10.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_jv_asm_db.h"

@implementation gmrz_jv_asm_db


+ (OSStatus)gmrz_jv_asm_DB_Add:(NSString *)serviceId
                   counterIn:(NSString *)counterIn
                   DB_dataIn:(NSString *)DB_dataIn
{
    CFErrorRef error = NULL;
    OSStatus status;
    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                        kSecAttrAccessibleAlways,
                                                                    0, &error);
    
    if (sacObject == NULL || error != NULL) {
        NSLog(@"SecItemAdd can't create sacObject: %@", error);
              return -1;
    }
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *attributes = @{
                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: serviceId,
                                 (__bridge id)kSecAttrAccount: counterIn,
                                 (__bridge id)kSecValueData: [DB_dataIn dataUsingEncoding:NSUTF8StringEncoding],
                                 (__bridge id)kSecUseNoAuthenticationUI: @YES,
                                 (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                 };
    
    
    status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        
    NSString *errorString = [self keychainErrorToString:status];
    NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", errorString];


  
    return status;
}


+ (OSStatus)gmrz_jv_asm_DB_Query:(NSString *)serviceId
                   counterIn:(NSString *)counterIn
                   DB_dataIn:(NSString **)DB_dataIn
{
    
    OSStatus status;
    CFTypeRef dataTypeRef = NULL;
    NSString *message;
    NSString *result;
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: serviceId,
                            (__bridge id)kSecAttrAccount: counterIn,
                            (__bridge id)kSecReturnData: @YES,
                            };
    status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status == errSecSuccess) {
        NSData *resultData = (__bridge_transfer NSData *)dataTypeRef;
        
        result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        message = [NSString stringWithFormat:@"Result: %@\n", result];
        
    }else {
        message = [NSString stringWithFormat:@"SecItemCopyMatching status: %@", [self keychainErrorToString:status]];
    }
    
    *DB_dataIn = [result copy];
    

    
    return status;
}



+ (OSStatus)gmrz_jv_asm_DB_Delete:(NSString *)serviceId
                       counterIn:(NSString *)counterIn
                     
{
    
    OSStatus status;
    CFTypeRef dataTypeRef = NULL;
    NSString *message;
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: serviceId,
                            (__bridge id)kSecAttrAccount: counterIn,

                            };
     status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    NSString *errorString = [self keychainErrorToString:status];
    
    message = [NSString stringWithFormat:@"SecItemDelete status: %@", errorString];

    return status;
}





+ (NSString *)keychainErrorToString:(OSStatus)error {
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



@end
