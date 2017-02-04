//
//  gmrz_reg_name.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/18.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "gmrz_reg_name.h"



@implementation gmrz_reg_name



- (id) initWithFrame:(CGRect)frame testarray:(NSArray *)testarray
{
    
   
    self = [super initWithFrame:frame];
    if (self) {
        UIPickerView *upv = [[UIPickerView alloc] initWithFrame:CGRectMake(0, 200, 100, 200)];
        //    array = [[NSArray alloc] initWithObjects:@"陈凯", @"至尊宝",@"菩提老祖",@"二当家",@"紫霞仙子",@"蜗牛",nil];
        pickerArray = testarray;
        upv.userInteractionEnabled = true;
        upv.delegate = self;
        upv.dataSource = self;
        [self addSubview:upv];
    }
   
    
    return self;
    
}

-(NSInteger)numberOfComponentsInPickerView:(UIPickerView *)pickerView{
    return 1;
}
-(NSInteger) pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component{
    return [pickerArray count];
}
-(NSString*) pickerView:(UIPickerView *)pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component{
   
    return [pickerArray objectAtIndex:row];
}


@end
