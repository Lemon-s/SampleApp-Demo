//
//  BaseViewController.m
//  testPro
//
//  Created by 张宁 on 16/7/11.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "BaseViewController.h"
#import "AppDelegate.h"
#import "registerController.h"



@interface BaseViewController ()

@end

@implementation BaseViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    UIBarButtonItem * barbutton = [[UIBarButtonItem alloc]initWithTitle:@"退出" style:UIBarButtonItemStylePlain target:self action:@selector(buttonClick)];
    self.navigationItem.rightBarButtonItem = barbutton;

    self.view.backgroundColor = [UIColor colorWithRed:242/255.0 green:242/255.0 blue:242/255.0 alpha:1];
    
    
    
}


- (void)buttonClick {
    
    
    [[NSUserDefaults standardUserDefaults]setValue:@"off" forKey:@"online"];
    //[[UIApplication sharedApplication] unregisterForRemoteNotifications];
    UIApplication * app = [UIApplication sharedApplication];
    AppDelegate * app2 = app.delegate;
    registerController * regist = [[registerController alloc]init];
    UINavigationController *nav = [[UINavigationController alloc]initWithRootViewController:regist];
    
    app2.window.rootViewController = nav;
    
    
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
