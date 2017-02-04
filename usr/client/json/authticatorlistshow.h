//
//  authticatorlistshow.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/25.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <UIKit/UIKit.h>
typedef void (^pBlock)(NSString * selectdata);

@interface authticatorlistshow : UIView<UIPickerViewDelegate,UIPickerViewDataSource>
{
    UIPickerView * pic;
}

@property (nonatomic,strong) pBlock _pBlock;

- (instancetype)initWithFrame:(CGRect)frame andDataSource:(NSArray *)array;
- (void)getSelectValue:(pBlock)params;
@end
