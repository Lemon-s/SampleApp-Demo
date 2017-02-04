//
//  tanchu.h
//  123123
//
//  Created by 张宁 on 16/7/18.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import <UIKit/UIKit.h>


typedef void (^pBlock)(NSString * selectdata);
@interface tanchu : UIView<UIPickerViewDelegate,UIPickerViewDataSource>
{
    UIPickerView * pic;
}
@property (nonatomic,assign) pBlock _pBlock;
- (instancetype)initWithFrame:(CGRect)frame andDataSource:(NSArray *)array andBlock:(void(^)(NSString *))finish;

//- (NSString *)dataSource:(NSArray *)array;

@end
