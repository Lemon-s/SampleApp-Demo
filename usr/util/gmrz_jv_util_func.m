//
//  gmrz_jv_util_func.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/4.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_jv_util_func.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <UIKit/UIKit.h>
//空字符串
#define     LocalStr_None           @""
#define MALLOC_SIZE 2048
#define SystemVersion [[UIDevice currentDevice] systemVersion].floatValue
@implementation gmrz_jv_util_func

+(NSString *)DecodeBase64ToNSStr:(NSString *)Base64Str
{
    NSData *nsdataFromBase64String = [[NSData alloc]
                                      initWithBase64EncodedString:Base64Str options:0];
    NSString * DecodeString = [[NSString alloc]
                               initWithData:nsdataFromBase64String encoding:NSUTF8StringEncoding];
    return DecodeString;
}




static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";




+ (NSString *)base64StringFromText:(NSString *)text
{
    if (text && ![text isEqualToString:LocalStr_None]) {
        //取项目的bundleIdentifier作为KEY  改动了此处
        //NSString *key = [[NSBundle mainBundle] bundleIdentifier];
        NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
        //IOS 自带DES加密 Begin  改动了此处
        //data = [self DESEncrypt:data WithKey:key];
        //IOS 自带DES加密 End
        return [self base64EncodedStringFrom:data];
    }
    else {
        return LocalStr_None;
    }
}

+ (NSString *)textFromBase64String:(NSString *)base64
{
    if (base64 && ![base64 isEqualToString:LocalStr_None]) {
        //取项目的bundleIdentifier作为KEY   改动了此处
        //NSString *key = [[NSBundle mainBundle] bundleIdentifier];
        NSData *data = [self dataWithBase64EncodedString:base64];
        //IOS 自带DES解密 Begin    改动了此处
        //data = [self DESDecrypt:data WithKey:key];
        //IOS 自带DES加密 End
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    else {
        return LocalStr_None;
    }
}


+ (NSString *)textFromBase64StringExt:(NSString *)base64
{
    if (base64 && ![base64 isEqualToString:LocalStr_None]) {
        NSData *nsdata = [base64
                          dataUsingEncoding:NSUTF8StringEncoding];
        
        // Get NSString from NSData object in Base64
        NSString *base64Encoded = [nsdata base64EncodedStringWithOptions:0];
        
        // Print the Base64 encoded string
       return [nsdata base64EncodedStringWithOptions:0];
    }
    else {
        return LocalStr_None;
    }
}





/******************************************************************************
 函数名称 : + (NSData *)dataWithBase64EncodedString:(NSString *)string
 函数描述 : base64格式字符串转换为文本数据
 输入参数 : (NSString *)string
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 :
 ******************************************************************************/
+ (NSData *)dataWithBase64EncodedString:(NSString *)string
{
    if (string == nil)
        [NSException raise:NSInvalidArgumentException format:nil];
    if ([string length] == 0)
        return [NSData data];
    
    static char *decodingTable = NULL;
    if (decodingTable == NULL)
    {
        decodingTable = malloc(256);
        if (decodingTable == NULL)
            return nil;
        memset(decodingTable, CHAR_MAX, 256);
        NSUInteger i;
        for (i = 0; i < 64; i++)
            decodingTable[(short)encodingTable[i]] = i;
    }
    
    const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
    if (characters == NULL)     //  Not an ASCII string!
        return nil;
    char *bytes = malloc((([string length] + 3) / 4) * 3);
    if (bytes == NULL)
        return nil;
    NSUInteger length = 0;
    
    NSUInteger i = 0;
    while (YES)
    {
        char buffer[4];
        short bufferLength;
        for (bufferLength = 0; bufferLength < 4; i++)
        {
            if (characters[i] == '\0')
                break;
            if (isspace(characters[i]) || characters[i] == '=')
                continue;
            buffer[bufferLength] = decodingTable[(short)characters[i]];
            if (buffer[bufferLength++] == CHAR_MAX)      //  Illegal character!
            {
                free(bytes);
                return nil;
            }
        }
        
        if (bufferLength == 0)
            break;
        if (bufferLength == 1)      //  At least two characters are needed to produce one byte!
        {
            free(bytes);
            return nil;
        }
        
        //  Decode the characters in the buffer to bytes.
        bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (bufferLength > 2)
            bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
        if (bufferLength > 3)
            bytes[length++] = (buffer[2] << 6) | buffer[3];
    }
    
    bytes = realloc(bytes, length);
    return [NSData dataWithBytesNoCopy:bytes length:length];
}

/******************************************************************************
 函数名称 : + (NSString *)base64EncodedStringFrom:(NSData *)data
 函数描述 : 文本数据转换为base64格式字符串
 输入参数 : (NSData *)data
 输出参数 : N/A
 返回参数 : (NSString *)
 备注信息 :
 ******************************************************************************/
+ (NSString *)base64EncodedStringFrom:(NSData *)data
{
    if ([data length] == 0)
        return @"";
    
    char *characters = malloc((([data length] + 2) / 3) * 4);
    if (characters == NULL)
        return nil;
    NSUInteger length = 0;
    
    NSUInteger i = 0;
    while (i < [data length])
    {
        char buffer[3] = {0,0,0};
        short bufferLength = 0;
        while (bufferLength < 3 && i < [data length])
            buffer[bufferLength++] = ((char *)[data bytes])[i++];
        
        //  Encode the bytes in the buffer to four characters, including padding "=" characters if necessary.
        characters[length++] = encodingTable[(buffer[0] & 0xFC) >> 2];
        characters[length++] = encodingTable[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
        if (bufferLength > 1)
            characters[length++] = encodingTable[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
        else characters[length++] = '=';
        if (bufferLength > 2)
            characters[length++] = encodingTable[buffer[2] & 0x3F];
        else characters[length++] = '=';
    }
    
    return [[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSASCIIStringEncoding freeWhenDone:YES];
}

//+(NSString *)EncodeNSStrToBase64:(NSString *)PlainText
//{
//    
//}


const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char * gmrz_base64_encode_ext( const unsigned char * bindata, char * base64, int binlength )
{
    int i, j;
    unsigned char current;
    
    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];
        
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];
        
        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];
        
        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return base64;
}










int gmrz_base64_decode_ext( const unsigned char * base64, unsigned char * bindata )
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }
        
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
        ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;
        
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
        ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;
        
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
        ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}












char *gmrz_base64_encode(const unsigned char* data, int data_len)
{
    //int data_len = strlen(data);
    int prepare = 0;
    int ret_len;
    int temp = 0;
    char *ret = NULL;
    char *f = NULL;
    int tmp = 0;
    char changed[4];
    int i = 0;
    ret_len = data_len / 3;
    temp = data_len % 3;
    if (temp > 0)
    {
        ret_len += 1;
    }
    ret_len = ret_len*4 + 1;
    ret = (char *)malloc(MALLOC_SIZE);
    
    if ( ret == NULL)
    {
        printf("No enough memory.\n");
        exit(0);
    }
    memset(ret, 0, MALLOC_SIZE);
    f = ret;
    while (tmp < data_len)
    {
        temp = 0;
        prepare = 0;
        memset(changed, '\0', 4);
        while (temp < 3)
        {
            //printf("tmp = %d\n", tmp);
            if (tmp >= data_len)
            {
                break;
            }
            prepare = ((prepare << 8) | (data[tmp] & 0xFF));
            tmp++;
            temp++;
        }
        prepare = (prepare<<((3-temp)*8));
        //printf("before for : temp = %d, prepare = %d\n", temp, prepare);
        for (i = 0; i < 4 ;i++ )
        {
            if (temp < i)
            {
                changed[i] = 0x40;
            }
            else
            {
                changed[i] = (prepare>>((3-i)*6)) & 0x3F;
            }
            *f = encodingTable[changed[i]];
            //printf("%.2X", changed[i]);
            f++;
        }
    }
    *f = '\0';
    
    return ret;
    
}
static char find_pos(char ch)
{
    char *ptr = (char*)strrchr(encodingTable, ch);//the last position (the only) in base[]
    return (ptr - encodingTable);
}

char *gmrz_base64_decode(const unsigned char* data, int data_len)
{
   
        int ret_len = (data_len / 3 ) * 4 ;
        int ret_len_s= 0;
        int equal_count = 0;
        char *ret = NULL;
        char *f = NULL;
        int tmp = 0;
        int temp = 0;
        char need[3];
        int prepare = 0;
        int i = 0;
        if (*(data + data_len - 1) == '=')
        {
            equal_count += 1;
        }
        if (*(data + data_len - 2) == '=')
        {
            equal_count += 1;
        }
        if (*(data + data_len - 3) == '=')
        {//seems impossible
            equal_count += 1;
        }
        switch (equal_count)
        {
            case 0:
                ret_len += 4;//3 + 1 [1 for NULL]
                break;
            case 1:
                ret_len += 4;//Ceil((6*3)/8)+1
                break;
            case 2:
                ret_len += 3;//Ceil((6*2)/8)+1
                break;
            case 3:
                ret_len += 2;//Ceil((6*1)/8)+1
                break;
        }
        ret = (char *)malloc(MALLOC_SIZE);
        if (ret == NULL)
        {
            printf("No enough memory.\n");
            exit(0);
        }
        memset(ret, 0, MALLOC_SIZE);
        f = ret;
        while (tmp < (data_len - equal_count))
        {
            temp = 0;
            prepare = 0;
            memset(need, 0, 3);
            while (temp < 4)
            {
                if (tmp >= (data_len - equal_count))
                {
                    break;
                }
                prepare = (prepare << 6) | (find_pos(data[tmp]));
                temp++;
                tmp++;
            }
            prepare = prepare << ((4-temp) * 6);
            for (i=0; i<3 ;i++ ) 
            { 
                if (i == temp) 
                { 
                    break; 
                } 
                *f = (char)((prepare>>((2-i)*8)) & 0xFF); 
                f++;
                ++ret_len_s;
            } 
        }

        *f = '\0';
        return ret;
    
}


+ (NSString *)base64urlconv:(uint8_t *)base64
{
    NSString * assertions = [[NSString alloc ] initWithCString:base64 encoding:NSUTF8StringEncoding];
    assertions = [assertions stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    assertions = [assertions stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    assertions = [assertions stringByReplacingOccurrencesOfString:@"=" withString:@""];
    
    return assertions;
}


+ (NSString *)convbase64url:(uint8_t *)base64
{
    NSString * assertions = [[NSString alloc ] initWithCString:base64 encoding:NSUTF8StringEncoding];
    assertions = [assertions stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    assertions = [assertions stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    
    return assertions;
}


+ (OSStatus)userlistadd:(NSString *)username userlistJsonIn:(NSString *)userlistJsonIn userlistJsonOut:(NSString **)userlistJsonOut
{
    NSString *userlist;
    NSError *err;
    
    
    if (userlistJsonIn == nil) {
        NSMutableDictionary *userDic = [[NSMutableDictionary alloc]init];
        [userDic setObject:username forKey:@"username"];
        
        
        NSArray *arrUserList = [[NSArray alloc] initWithObjects:userDic, nil ];
        
        NSMutableDictionary *userListDic = [[NSMutableDictionary alloc] init];
        [userListDic setObject:arrUserList forKey:@"userlist"];
        
        NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:userListDic options:NSJSONWritingPrettyPrinted error:&err];
        userlist = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
        

        *userlistJsonOut = [userlist copy];

    }
    else
    {
        NSData *jsonData = [userlistJsonIn dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                  options:NSJSONReadingMutableContainers
                                                                    error:&err];
        
        NSMutableArray *arr = [jsonparse valueForKey:@"userlist"];
        
        NSMutableDictionary *userDic = [[NSMutableDictionary alloc]init];
        [userDic setObject:username forKey:@"username"];
        [arr addObject:userDic];
        
        NSMutableDictionary *userListDic = [[NSMutableDictionary alloc] init];
        [userListDic setObject:arr forKey:@"userlist"];
        
        NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:userListDic options:NSJSONWritingPrettyPrinted error:&err];
        userlist = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
        
     
        *userlistJsonOut = [userlist copy];

    }
    
    
    return errSecSuccess;
}



+(OSStatus)checkifUVSchange:(NSString *)serviceID
{
    //0 表示变化 1 表示无变化 2表示指纹没有设置
    OSStatus status = 0;
    
    //get current UVS
    NSString *UVS = nil;
    BOOL success = [self canEvaluatePolicy:&UVS];
    if (success) {
//        LAContext *context = [[LAContext alloc] init];
//        uint *uvs_str = gmrz_base64_encode([[context evaluatedPolicyDomainState] bytes], [[context evaluatedPolicyDomainState] length]);
//        UVS = [[[NSString alloc] initWithUTF8String:uvs_str] copy];
    }
    else{
        NSLog(@"touch id no set Or anyother");
        return 2;
    }
    
    
    NSString *ItemOut = nil;
    [gmrz_jv_util_func db_items_match:serviceID Itemjson:&ItemOut];
    NSError *err;
    NSData *jsonData = [ItemOut dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    
    
    NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
   
    for (int i = 0; i < arr.count; i++) {
        NSString *_tempUVS =[arr[i] valueForKeyPath:@"UVS"];
        if ([_tempUVS isEqualToString:UVS]) {
            status = 1;
            break;
        }
    }
    
    return status;
}


+ (BOOL)canEvaluatePolicy:(NSString **)UVS{
    

    NSError *error;
    BOOL success;
     LAContext *context = [[LAContext alloc] init];
    // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
//    success = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    
    if (SystemVersion > 9.3) {
        // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
        success = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthentication error:&error];
        
    }
    else{
        // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
        success = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    }

    
    if (success) {
       
//        uint *uvs_str = gmrz_base64_encode([[context evaluatedPolicyDomainState] bytes], [[context evaluatedPolicyDomainState] length]);
        uint8_t *uvs_str = (uint8_t *)malloc(1024);
        
        gmrz_base64_encode_ext([[context evaluatedPolicyDomainState] bytes], uvs_str, [[context evaluatedPolicyDomainState] length]);
        
        *UVS = [[[NSString alloc] initWithUTF8String:uvs_str] copy];
        
        free(uvs_str);
    }
    else {
        *UVS = nil;

    }
    return success;
}

+ (BOOL)checkiftouchidisavaliable{
    
    
    NSError *error;
    BOOL success = false;
    LAContext *context = [[LAContext alloc] init];
    
    if (SystemVersion > 9.3) {
        // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
        success = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthentication error:&error];
        
    }
    else{
        // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
        success = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    }
  
    
    return success;
}
+ (BOOL)checkiftouchidlocked{
    
    
    NSError *error;
    BOOL success = false;
    LAContext *context = [[LAContext alloc] init];
    
    
    // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
    success = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    
    
    
    return success;
}




+ (OSStatus)KeychainItem_add:(NSString *)username
                   keyhandle:(NSString *)keyhandle
                       keyid:(NSString *)keyid
                         UVS:(NSString *)UVS
                   serviceId:(NSString *)serviceId
                   accountId:(NSString *)accountId
                       priId:(NSString *)priId
             userlistJsonIn:(NSString *)userlistJsonIn
             userlistJsonOut:(NSString **)userlistJsonOut
{
    NSString *userlist;
    NSError *err;
    

    if (SystemVersion >=9.0) {
   
        [self canEvaluatePolicy:&UVS];
    }
    
    if (userlistJsonIn == nil) {
        NSMutableDictionary *privatekeyinfo = [[NSMutableDictionary alloc]init];
        [privatekeyinfo setObject:serviceId forKey:@"serviceId"];
        [privatekeyinfo setObject:accountId forKey:@"accountId"];
        [privatekeyinfo setObject:priId forKey:@"priId"];
        
        
        NSMutableDictionary *authcatitorinfo = [[NSMutableDictionary alloc]init];
        [authcatitorinfo setObject:username forKey:@"username"];
        [authcatitorinfo setObject:keyhandle forKey:@"keyhandle"];
        [authcatitorinfo setObject:keyid forKey:@"keyid"];
  
        [authcatitorinfo setObject:UVS forKey:@"UVS"];
        [authcatitorinfo setObject:privatekeyinfo forKey:@"privatekeyinfo"];

        
        NSArray *arrUserList = [[NSArray alloc] initWithObjects:authcatitorinfo, nil ];
        
        NSMutableDictionary *userListDic = [[NSMutableDictionary alloc] init];
        [userListDic setObject:arrUserList forKey:@"info_list"];
        
        NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:userListDic options:NSJSONWritingPrettyPrinted error:&err];
        userlist = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
        

        *userlistJsonOut = [userlist copy];
        
    }
    else
    {
        NSData *jsonData = [userlistJsonIn dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                                  options:NSJSONReadingMutableContainers
                                                                    error:&err];
        
        NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
        
        NSMutableDictionary *privatekeyinfo = [[NSMutableDictionary alloc]init];
        [privatekeyinfo setObject:serviceId forKey:@"serviceId"];
        [privatekeyinfo setObject:accountId forKey:@"accountId"];
        [privatekeyinfo setObject:priId forKey:@"priId"];
        
        
        NSMutableDictionary *authcatitorinfo = [[NSMutableDictionary alloc]init];
        [authcatitorinfo setObject:username forKey:@"username"];
        [authcatitorinfo setObject:keyhandle forKey:@"keyhandle"];
        [authcatitorinfo setObject:keyid forKey:@"keyid"];
        [authcatitorinfo setObject:UVS forKey:@"UVS"];
        [authcatitorinfo setObject:privatekeyinfo forKey:@"privatekeyinfo"];
        

        for (int i = 0; i < arr.count; i++) {
            if ([[arr[i] valueForKeyPath:@"username"] isEqualToString:username]) {
                [arr removeObject:arr[i]];
            }
        }
        
        
        [arr addObject:authcatitorinfo];
        
        NSMutableDictionary *userListDic = [[NSMutableDictionary alloc] init];
        [userListDic setObject:arr forKey:@"info_list"];
        
        NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:userListDic options:NSJSONWritingPrettyPrinted error:&err];
        userlist = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
        

        *userlistJsonOut = [userlist copy];
        
 
   
    }
    
    
    return errSecSuccess;
}




+ (OSStatus)KeychainItem_Getkey:(NSString *)username
                         jsonIn:(NSString *)jsonIn
                         dicOut:(NSDictionary **)dicOut

{
    
    NSError *err;
    int i = 0;
    NSData *jsonData = [jsonIn dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
    for ( i = 0; i < arr.count; i++) {
        if ([[arr[i] valueForKeyPath:@"username"] isEqualToString:username]) {
            break;
        }
        continue;
    }
    
    if (i < arr.count) {
        *dicOut = [arr[i] copy];
    }
    else
        *dicOut = nil;
 
    
    return errSecSuccess;
}


+ (OSStatus)KeychainItem_Delkey:(NSString *)username
                         jsonIn:(NSString *)jsonIn
                userlistJsonOut:(NSString **)userlistJsonOut

{
    
    NSError *err;
    int i = 0;

    
    if (jsonIn == nil) {
        *userlistJsonOut = nil;
        return errSecSuccess;
    }
    NSData *jsonData = [jsonIn dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *jsonparse = [NSJSONSerialization JSONObjectWithData:jsonData
                                                              options:NSJSONReadingMutableContainers
                                                                error:&err];
    NSMutableArray *arr = [jsonparse valueForKey:@"info_list"];
    for ( i = 0; i < arr.count; i++) {
        if ([[arr[i] valueForKeyPath:@"username"] isEqualToString:username]) {
            break;
        }
        continue;
    }
    
    if (i < arr.count) {
        [arr removeObjectAtIndex:i];
    }
    
    if(arr.count == 0){
        *userlistJsonOut = nil;
        return errSecSuccess;
    }
    NSMutableDictionary * userListStr= [[NSMutableDictionary alloc]init];
    [userListStr setObject:arr forKey:@"info_list"];

    
    NSData *jsonDatafinal = [NSJSONSerialization dataWithJSONObject:userListStr options:NSJSONWritingPrettyPrinted error:&err];
    NSString * userlist = [[NSString alloc] initWithData:jsonDatafinal  encoding:NSUTF8StringEncoding];
    
    *userlistJsonOut = [userlist copy];

    
    return errSecSuccess;
}



int strTobcd(unsigned char *dest, const char *src ,int srclen)
{
    int i;
    unsigned char hbit,lbit;
    
    int len = srclen;
    for(i = 0; i < len; i+=2)
    {
        hbit = (src[i] > '9') ? ((src[i] & 0x0F) + 9) : (src[i] & 0x0F);
        lbit = (src[i+1] > '9') ? ((src[i+1] & 0x0F) + 9) : (src[i+1] & 0x0F);
        dest[i/2] = (hbit << 4) | lbit;
    }
    return 0;
}

//serviceID appID + bundleID
+(OSStatus)db_items_add:(NSString *)ServiveId Data2Json:(NSString *)Data2Json
{
    
    CFErrorRef error = NULL;
    
    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                               kSecAttrAccessibleAlways,
                                                                    0, &error);
    
    if (sacObject == NULL || error != NULL) {
        
        return errSecAllocate;
    }
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *attributes = @{
                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: ServiveId,
                                 (__bridge id)kSecValueData: [Data2Json dataUsingEncoding:NSUTF8StringEncoding],
                                 (__bridge id)kSecUseNoAuthenticationUI: @YES,
                                 (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                 };

//                              };

    OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
    if (status != errSecSuccess) {
        
        
        NSDictionary *attributesupdata = @{
                                     (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                     (__bridge id)kSecAttrService: ServiveId,
                                   
                                     (__bridge id)kSecUseNoAuthenticationUI: @YES,
                                     (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                     };
        NSDictionary *changes = @{
                            (__bridge id)kSecValueData: [Data2Json dataUsingEncoding:NSUTF8StringEncoding]
                                                                };
       status = SecItemUpdate((__bridge CFDictionaryRef)attributes, (__bridge CFDictionaryRef)changes);
    }

    return status;
}


//serviceID appID + bundleID
+(OSStatus)db_items_match:(NSString *)ServiveId
                Itemjson:(NSString **)Itemjson
{
    
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: ServiveId,
                            (__bridge id)kSecReturnData: @YES,    
                            };
    

    CFTypeRef dataTypeRef = NULL;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status == errSecSuccess) {
        NSData *resultData = (__bridge_transfer NSData *)dataTypeRef;
            
        NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        *Itemjson = [result copy];
     
    };
    
    return status;


}

+(OSStatus)db_items_delete:(NSString *)ServiveId FuncItemIndex:(int *)FuncItemIndex
{
    
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: ServiveId
                            };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
 
    return status;

  }




+(NSInteger)getIOSversion
{
    NSInteger  os_system = 0;
    NSOperatingSystemVersion  os = [[NSProcessInfo processInfo] operatingSystemVersion];
    os_system = os.majorVersion;
    return os_system;
}



+(NSString *)asmDB_data_id:(NSString *)serviceID
                 counterid:(NSString *)counterid
                  username:(NSString *)username
                       ext:(NSString *)ext
{
    NSString * result;
    NSString * resultacii;
    int i = 0;
// [[NSBundle mainBundle] bundleIdentifier]]
    
    result = [@"" stringByAppendingString:serviceID ];
    result = [result stringByAppendingString:@"-"];
    result = [result stringByAppendingString:counterid];
    result = [result stringByAppendingString:@"-"];
    result = [result stringByAppendingString:username];
    result = [result stringByAppendingString:@"-"];
    result = [result stringByAppendingString:ext];
    
    if (i == 0) {
        resultacii = [NSString stringWithFormat:@"%d", [result characterAtIndex:i]];
    }
    
    for (int i = 1; i < result.length; i++) {
        resultacii = [resultacii stringByAppendingFormat:@"%d", [result characterAtIndex:i]];
    }
    
    return  resultacii;

}





@end
