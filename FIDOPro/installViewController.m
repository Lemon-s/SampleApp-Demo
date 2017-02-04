//
//  installViewController.m
//  FIDOPro
//
//  Created by 张宁 on 16/7/19.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "installViewController.h"
#import "PlistTools.h"
@interface installViewController ()<UITextFieldDelegate>
@property (weak, nonatomic) IBOutlet UITextField *connectUrl;

@property (weak, nonatomic) IBOutlet UITextField *API;



@end

@implementation installViewController



- (void)viewDidLoad {
    
    [super viewDidLoad];

    
    _connectUrl.delegate = self;
    _API.delegate = self;
    
    

    
    NSLog(@"%@",[[NSUserDefaults  standardUserDefaults] objectForKey:@"connectUrl"]);
    
    if ([[[NSUserDefaults standardUserDefaults] objectForKey:@"connectUrl"] length]==0) {
        
        
        self.connectUrl.text = [PlistTools readPlist:@"REST_SERVER_ADDRESS"];
        self.API.text = [PlistTools readPlist:@"V1_API_PREFIX"];
        
        
        [[NSUserDefaults standardUserDefaults] setValue:self.connectUrl.text forKey:@"connectUrl"];
        [[NSUserDefaults standardUserDefaults] setValue:self.API.text forKey:@"API"];
        }else
        
        NSLog(@"+++++++++++%@",[[NSUserDefaults standardUserDefaults] stringForKey:@"connectUrl"]);
        self.connectUrl.text =  [[NSUserDefaults standardUserDefaults] stringForKey:@"connectUrl"];
        self.API.text = [[NSUserDefaults standardUserDefaults] stringForKey:@"API"];
        
    
    
    
    
    
    
    
    
    
    
    // Do any additional setup after loading the view.
    
    
    
    
    
    //_connectUrl.text = [plistTool readPlist:@"REST_SERVER_ADDRESS"];
    
    //_API.text = [plistTool readPlist:@"V1_API_PREFIX"];
    
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)submitClick:(id)sender {
    
    if ([_API.text isEqualToString:@""]&&[_connectUrl.text isEqualToString:@""]) {
        
        self.connectUrl.text = [PlistTools readPlist:@"REST_SERVER_ADDRESS"];
        self.API.text = [PlistTools readPlist:@"V1_API_PREFIX"];
        
        
    }
    UIAlertController * alertController = [UIAlertController alertControllerWithTitle: @"配置成功"                                                                             message:nil                                                                       preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction * alert = [UIAlertAction actionWithTitle:@"ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        
        [[NSUserDefaults standardUserDefaults] setValue:self.connectUrl.text forKey:@"connectUrl"];
        [[NSUserDefaults standardUserDefaults] setValue:self.API.text forKey:@"API"];

    }];
    [alertController addAction:alert];
    [self presentViewController:alertController animated:YES completion:nil];
    
    
    
    [self.connectUrl resignFirstResponder];
    [self.API resignFirstResponder];
    

}





- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    
    [_connectUrl resignFirstResponder];
    [_API resignFirstResponder];
    return YES;
    
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
