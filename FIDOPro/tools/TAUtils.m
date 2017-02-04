//
//  TAUtils.m
//  FIDOPro
//
//  Created by 张宁 on 16/8/2.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "TAUtils.h"
#import "MBProgressHUD.h"
@implementation TAUtils

+(void)displayMessage:(NSString *)state andShow:(NSString *)showMessage {
    
    
    
    [[NSOperationQueue mainQueue] addOperationWithBlock:^ {
        UIAlertController * alert =   [UIAlertController
                                       alertControllerWithTitle:showMessage
                                       message:state
                                       preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction* ok = [UIAlertAction
                             actionWithTitle:@"OK"
                             style:UIAlertActionStyleDefault
                             handler:^(UIAlertAction * action)
                             {
                                 [alert dismissViewControllerAnimated:YES completion:nil];
                                 
                             }];
        [alert addAction:ok];
        

        UIWindow *window = [UIApplication sharedApplication].keyWindow;
        UIViewController *rootViewController = window.rootViewController;
        
        [rootViewController presentViewController:alert animated:YES completion:nil];
        
        
        

    }];
}




static MBProgressHUD *customProgress = nil;
+(void)showProgressDialog:(UIView *)view
{
    [UIApplication sharedApplication].networkActivityIndicatorVisible = TRUE;
    
    if  (customProgress == nil) {
        customProgress = [[MBProgressHUD alloc] initWithView:view];
    }
    [view addSubview:customProgress];
    customProgress.dimBackground = YES;
    [customProgress show:YES];
}

+(void)dismissProgressDialog
{
    if  (customProgress != nil) {
        [customProgress removeFromSuperview];
        customProgress = nil;
        [UIApplication sharedApplication].networkActivityIndicatorVisible = FALSE;
    }
}
@end
