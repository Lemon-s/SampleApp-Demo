//
//  TAUtils.h
//  FIDOPro
//
//  Created by 张宁 on 16/8/2.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface TAUtils : UIView
+(void)displayMessage:(NSString *)state andShow:(NSString *)showMessage;
+(void)showProgressDialog:(UIView *)view;
+(void)dismissProgressDialog;
@end
