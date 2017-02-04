//
//  modelAlert.m
//  naoku_EChannel
//
//  Created by Lyndon on 2017-07-06.
//  Copyright (c) 2017年 bravetorun. All rights reserved.
//

#import "modelAlert.h"

@implementation modelAlert
- (int)showModelAlertMsg:(NSString *)_strMsg title:(NSString *)_strTitle okBtn:(NSString *)_strOk cancelBtn:(NSString *)_strCancel otherBtn:(NSString *)_strOther, ...
{
    _bEnd = false;
    va_list argumentList;
    NSString *eachStr;
    UIAlertView *_alert = [[UIAlertView alloc] initWithTitle:_strTitle message:_strMsg delegate:self cancelButtonTitle:_strOk otherButtonTitles:_strCancel, nil];
    if (_strOther) {
        [_alert addButtonWithTitle:_strOther];
        va_start(argumentList, _strOther);
        
        while ((eachStr = va_arg(argumentList, NSString *))) {
            [_alert addButtonWithTitle:eachStr];
        }
        va_end(argumentList);
    }
    
    [_alert show];
    
    while (!_bEnd) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
    }
    
    
    return _nSelected;
}


- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    _bEnd = true;
    _nSelected = buttonIndex;
}
@end
