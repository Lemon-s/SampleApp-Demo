//
//  gmrz_reg_name.h
//  TestAkcmd
//
//  Created by Lyndon on 16/7/18.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface gmrz_reg_name : UIView<UIAlertViewDelegate, UIPickerViewDataSource, UIPickerViewDelegate>

{
    NSArray *pickerArray;
    
}


- (id) initWithFrame:(CGRect)frame testarray:(NSArray *)testarray;
@end
