//
//  modelAlert.m
//  naoku_EChannel
//
//  Created by Lyndon on 2017-07-06.
//  Copyright (c) 2017年 bravetorun. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
@interface modelAlert:UIView
{
    bool _bEnd;
    int _nSelected;
}

- (int)showModelAlertMsg:(NSString *)_strMsg title:(NSString *)_strTitle okBtn:(NSString *)_strOk cancelBtn:(NSString *)_strCancel otherBtn:(NSString *)_strOther,...;
@end
