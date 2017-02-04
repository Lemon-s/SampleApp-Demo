//
//  MainViewController.m
//  testPro
//
//  Created by 张宁 on 16/7/11.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "MainViewController.h"
#import "managerViewController.h"
#import "transactionViewController.h"
#import "validateViewController.h"

@interface MainViewController ()

@end

@implementation MainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view
    [self addViewController];


    
}

- (void)addViewController {
    NSMutableArray *controllers = [[NSMutableArray alloc]initWithObjects:@"validateViewController",@"transactionViewController",@"managerViewController", nil];
    NSArray *iconImage = @[@"icon_setup",@"icon_transaction",@"icon_settings"];
    NSArray *seleImage = @[@"icon_setup_over",@"icon_transaction_over",@"icon_settings_over"];
    NSArray * nameController = @[@"验证设置",@"交易",@"验证管理"];
    for (int i = 0; i < controllers.count; i ++) {
        Class controller = NSClassFromString(controllers[i]);
        UIViewController * viewController = [[controller alloc]init];
        [viewController.tabBarItem setImage:[[UIImage imageNamed:iconImage[i]]imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal]];
        [viewController.tabBarItem setSelectedImage:[[UIImage imageNamed:seleImage[i]]imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal]];
        viewController.title = nameController[i];
        UINavigationController * nav = [[UINavigationController alloc]initWithRootViewController:viewController];
        [controllers replaceObjectAtIndex:i withObject:nav];
    }
    
    self.viewControllers = controllers;
}



- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/


@end
