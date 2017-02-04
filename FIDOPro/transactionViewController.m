//
//  transactionViewController.m
//  testPro
//
//  Created by 张宁 on 16/7/13.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "transactionViewController.h"
#import "ShoppingCart.h"
@interface transactionViewController ()

@property (weak, nonatomic) IBOutlet UITextField *productNumaber;


@end

@implementation transactionViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Do any additional setup after loading the view from its nib.
    
        
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)addShoppingCar:(id)sender {
    
    ShoppingCart * shopping = [[ShoppingCart alloc]init];

    shopping.Number = _productNumaber.text;
    [self.navigationController pushViewController:shopping animated:YES];
    
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    
    [_productNumaber resignFirstResponder];
    
}




@end
