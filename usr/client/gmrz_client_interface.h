//
//  gmrz_client_interface.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/5.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <Foundation/Foundation.h>
//此枚举为选择注册，交易，解注册，检测是否可以进行注册/认证
typedef  NS_ENUM (NSInteger,op){
    gmrz_register = 0,//注册
    gmrz_authtication,//交易
    gmrz_deregister,//解注册
    gmrz_checkpolicy,//检测是否可以进行注册/认证
    
};
//此枚举为选择弹出local UI认证界面（仅适用于认证操作，其他操作请选择gmrz_default）
//认证操作gmrz_default为keyChain
typedef  NS_ENUM (NSInteger,methods) {
    gmrz_default = 0,
    gmrz_keychain,
    gmrz_local,
};

@interface gmrz_client_interface:NSObject
+(OSStatus)process:(NSString *)FidoIn DoFido:(op)DoFido Methods:(methods)Methods FidoOut:(NSString **)FidoOut;
@end
