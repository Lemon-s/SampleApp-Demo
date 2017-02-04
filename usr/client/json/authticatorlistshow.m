//
//  authticatorlistshow.m
//  TestAkcmd
//
//  Created by Lyndon on 16/7/25.
//  Copyright © 2016年 lenovo. All rights reserved.
//

#import "authticatorlistshow.h"

@interface authticatorlistshow() {
    
    NSArray * arrays;
    NSString *str;
}
@end

@implementation authticatorlistshow

- (instancetype)initWithFrame:(CGRect)frame andDataSource:(NSArray *)array {
    
    
    
    if (self == [super initWithFrame:frame]) {
        
        
        self.backgroundColor = [UIColor whiteColor];
        pic = [[UIPickerView alloc]initWithFrame:CGRectMake(0, 100, self.bounds.size.width-40, self.bounds.size.height)];
        pic.delegate = self;
        pic.dataSource = self;
        pic.backgroundColor = [UIColor whiteColor];
        
        UIButton * button = [[UIButton alloc]initWithFrame:CGRectMake(self.bounds.size.width-100, 60, 80, 40)];
        [button setTitle:@"确定" forState:UIControlStateNormal];
        button.backgroundColor = [UIColor blackColor];
        [button addTarget:self action:@selector(button) forControlEvents:UIControlEventTouchUpInside];
        
        [self addSubview:button];
        arrays = array;
        [self addSubview:pic];
        
        UIWindow * window= [[UIApplication sharedApplication].delegate window ];
        [window addSubview:self];
        
    }
    
    
    
    
    return self;
    
}


- (void)getSelectValue:(pBlock)params
{
    self._pBlock = params;
}



- (void)button {
    NSInteger row =[pic selectedRowInComponent:0];
    str = [arrays objectAtIndex:row];
    NSLog(@"%@",str);
    self->__pBlock(str);

    [self removeFromSuperview];
    
}


- (NSInteger)numberOfComponentsInPickerView:(UIPickerView*)pickerView
{
    return 1; // 返回1表明该控件只包含1列
}

//UIPickerViewDataSource中定义的方法，该方法的返回值决定该控件指定列包含多少个列表项
- (NSInteger)pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component
{
    // 由于该控件只包含一列，因此无须理会列序号参数component
    // 该方法返回teams.count，表明teams包含多少个元素，该控件就包含多少行
    return arrays.count;
}


// UIPickerViewDelegate中定义的方法，该方法返回的NSString将作为UIPickerView
// 中指定列和列表项的标题文本
- (NSString *)pickerView:(UIPickerView *)pickerView
             titleForRow:(NSInteger)row forComponent:(NSInteger)component
{
    // 由于该控件只包含一列，因此无须理会列序号参数component
    // 该方法根据row参数返回teams中的元素，row参数代表列表项的编号，
    // 因此该方法表示第几个列表项，就使用teams中的第几个元素
    
    return [arrays objectAtIndex:row];
}


- (void)pickerView:(UIPickerView *)pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component
{
    //    if (component == 0) {
    //        NSLog(@"%@",arrays[row]);
    //        str = arrays[row];
    //        [pickerView selectedRowInComponent:0];
    //        //        //重新加载数据
    //        //        [pickerView reloadAllComponents];
    //        //        //重新加载指定列的数据
    //        //        [pickerView reloadComponent:1];
    //    }
    //    else
    //    {
    //        NSLog(@"%@",arrays[row]);
    //    }
}



@end
