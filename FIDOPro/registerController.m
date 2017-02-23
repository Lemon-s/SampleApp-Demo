//
//  registerController.m
//  testPro
//
//  Created by 张宁 on 16/7/8.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "registerController.h"
#import "AppDelegate.h"
#import "MainViewController.h"
#import "installViewController.h"
#import "PlistTools.h"
#import "HttpConnection.h"
#import "TutorialAppException.h"
#import "gmrz_client_interface.h"
#import "TAUtils.h"


#define SIZE [UIScreen mainScreen].bounds.size
@interface registerController () {
    UITextField * username;
    UITextField * password;
}

extern HttpConnection* gHttpConnection;

@end

@implementation registerController

- (void)viewDidLoad {
    [super viewDidLoad];

    
    self.title = @"登录";
    UIBarButtonItem * Navbutton = [[UIBarButtonItem alloc]initWithTitle:@"设置" style:UIBarButtonItemStylePlain target:self action:@selector(NavButtonClick)];
    self.navigationItem.rightBarButtonItem = Navbutton;
    

    [self greateUI];
    
    
    
    
}





- (void)greateUI {
    NSArray *plahold = @[@"用户名",@"密码"];
    username = [[UITextField alloc]initWithFrame:CGRectMake(0,SIZE.height/4, SIZE.width, 40)];
    password = [[UITextField alloc]initWithFrame:CGRectMake(0,SIZE.height/4+50, SIZE.width, 40)];
    NSArray *user = @[username,password];

    
    for (int i =0; i < plahold.count; i++) {
        UITextField *tf = user[i];
        tf.placeholder= [NSString stringWithFormat:@"  %@",plahold[i]];
        tf.keyboardType = UIKeyboardTypeDefault;
        tf.backgroundColor = [UIColor lightGrayColor];
        tf.layer.cornerRadius = 10;
        if(i==1){
            tf.secureTextEntry = YES;
            
        }
        if (i==0) {
            tf.autocorrectionType = UITextAutocorrectionTypeNo;
        }
        [self.view addSubview:tf];
        


    }
    
    
    UIButton * button = [[UIButton alloc]initWithFrame:CGRectMake(70, SIZE.height/4+120 , SIZE.width-140, 40)];
    [button setTitle:@"登录" forState:UIControlStateNormal];
    button.backgroundColor = [UIColor orangeColor];
    [button setTitleColor:[UIColor grayColor] forState:UIControlStateHighlighted];
    [button addTarget:self action:@selector(buttonClick:) forControlEvents:UIControlEventTouchUpInside];
    button.tag = 1001;
    button.layer.cornerRadius = 20;
    [self.view addSubview:button];
    
    
    
    UIButton * Fidobutton = [[UIButton alloc]initWithFrame:CGRectMake(70, SIZE.height/4+100 + 80, SIZE.width - 140, 40)];
    [Fidobutton setTitle:@"Log In with FIDO" forState:UIControlStateNormal];
    [Fidobutton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [Fidobutton setTitleColor:[UIColor grayColor] forState:UIControlStateHighlighted];
    Fidobutton.backgroundColor = [UIColor greenColor];
    Fidobutton.tag = 1000;
    Fidobutton.layer.cornerRadius = 20;
    [Fidobutton addTarget:self action:@selector(buttonClick:) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:Fidobutton];
    UIImage * image = [UIImage imageNamed:@"fido_alliance"];
    float scale =  image.size.width/image.size.height;
    UIImageView *imageView = [[UIImageView alloc]initWithFrame:CGRectMake(0, SIZE.height - SIZE.width/scale - 80, SIZE.width, SIZE.width/scale)];
    imageView.image = image;
    [self.view addSubview:imageView];
    
    
    
    
}



- (void)buttonClick:(UIButton *)button {
    switch (button.tag) {
        case 1000:
        {
            [username resignFirstResponder];
            [password resignFirstResponder];

            
            
            [TAUtils showProgressDialog:self.view];

            dispatch_queue_t queue = dispatch_queue_create("com.ios.tutorialapp", NULL);
            dispatch_async(queue, ^{

                NSString *connect = [[[NSUserDefaults standardUserDefaults] objectForKey:@"connectUrl"] stringByAppendingString:[[NSUserDefaults standardUserDefaults]objectForKey:@"API"]];
            
                NSString *url = [connect stringByAppendingString:@"/auth/receive"];
                
                //@"https://test31.noknoklabs.cn:8443/uaf/v1/auth/receive";
            NSMutableDictionary* payload = [[NSMutableDictionary alloc] init];
            NSMutableDictionary* value = [[NSMutableDictionary alloc] init];
            //////////
            //
            //
            //    //Construct the transaction text
            
            [value   setObject:@"default"          forKey:@POLICY_NAME];
            [payload setObject:value forKey:@CONTEXT];
            
            
            
            NSError* error;
            NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload
                                                               options:(NSJSONWritingOptions)NSJSONWritingPrettyPrinted
                                                                 error:&error];
            NSString* jsonNSStringBody =  [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            
            NSMutableString* response = [[NSMutableString alloc] init];
            // [gHttpConnection setUserID:userName];
            // send and read response from server
            try {
                httpSendRequestReadResponse(gHttpConnection,
                                            url,
                                            jsonNSStringBody,
                                            @"POST",
                                            &response);
            } catch(TutorialAppException& ex) {
                
                //throw ex;
                [TAUtils displayMessage:@"connect error." andShow:@"error"];
                return;
            }
            
                NSLog(@"FIDO Server response is %@", response);

            
            
            NSMutableString* uafRequestMessage = [[NSMutableString alloc] init];
            //parse out the json data
            NSDictionary* json = [NSJSONSerialization
                                  JSONObjectWithData: [response dataUsingEncoding:NSUTF8StringEncoding] //1
                                  
                                  options:kNilOptions
                                  error:&error];
            //    if(nil != json && nil == error){
            uafRequestMessage = [json objectForKey:@UAF_REQUEST];
            NSInteger statusCode        = [[json objectForKey:@STATUS_CODE] integerValue];
            
            NSString * JsonOuttext = [[NSString alloc] init];
            
            
                
                
                
                
             NSString* str = @"{\"uafRequest\" : \"[{\"header\":{\"upv\":{\"major\":1,\"minor\":0},\"op\":\"Auth\",\"appID\":\"https:\/\/mobile.bankgy.com:6064\/uaf\/facets.uaf\",\"serverData\":\"vYn03WmcViWKOx41zsc7HIBau57hwLeR7S-FpiVnGVC9UCoBRTf0c8fOBaP8lCbwd4DHsUGnc_fwr56rRAiD7SpqK3wEh7NDBtLl22mqLReE6UZsASX67uaFQ0TLBKU0jdMe9kthM2IgHUE6r40e\"},\"challenge\":\"e8WMrEvAbLyt-Ip8ExJ3PzqEEVlHWu-3xqjtspccwG4\",\"policy\":{\"accepted\":[[{\"aaid\":[\"001A#3333\"],\"keyIDs\":[\"7HNBRQUeqMtrYYUeRaZdJ_GDLd6OGt9myc50t5dkZog\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"OPK2mwsiywDCbKakQqXQRDnPf10exUZ4atL6Un_ndnQ\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"1VPUjgG3UqNp9_CA0zesPM10XJ_TVvRukDrwSpbxAzQ\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"R5J54Zuu1b_5Zefs8B8zn6nB11NfdPu9VeH6J_tE-cs\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"Eis6e_BxVxoA_iMtKtva8W1wTMpJoYoRR8R9immmk4g\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"Dn1LoziodUpTMhtqkFXfXKPty6ag3AWC8qwwcflNOXE\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"Tc1gNqSGzSgoVkPzaKg6QEZ9O6iviYm5b1zrDFcyhWQ\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"GLfNRBPxOqiirtNdzmLh6rtryfLs7ZTTycnm19848YI\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"kImKYRkSuKDR0ghRQ3yvgRd2uqOjw_zKfy58I2NrpUI\"]}],[{\"aaid\":[\"4e4e#400b\"],\"keyIDs\":[\"vy9h1CznoG0KtPBCDfTDSsvWfFOQriIZxVS4fPGjuVE\"]}]]}}]\"}";
                
            //
                int status =   [gmrz_client_interface process:response DoFido:gmrz_authtication Methods:gmrz_default FidoOut:&JsonOuttext];
            
            NSLog(@"JsonOuttext %@ ,status %d", JsonOuttext, status);
            
            if (status == 0) {

                NSMutableDictionary* payload = [[NSMutableDictionary alloc] init];
                [payload setObject:JsonOuttext forKey:@"uafResponse"];
                NSError* error;
                NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload
                                                                   options:(NSJSONWritingOptions)NSJSONWritingPrettyPrinted
                                                                     error:&error];
                NSString* jsonNSString =  [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
                
                NSMutableString *a_pServerResponse;
                //Send response to server
                NSString *urlsend = [url stringByReplacingOccurrencesOfString:@"receive" withString:@"send"];
                //NSString* urlsend =@"https://test31.noknoklabs.cn:8443/uaf/v1/auth/send";
                httpSendRequestReadResponse(gHttpConnection,
                                            urlsend,
                                            jsonNSString,
                                            @"POST",
                                            &a_pServerResponse);
                
                NSLog(@"a_pServerResponse %@", a_pServerResponse);
                if (a_pServerResponse) {
                    
                    NSError *errors = nil;
                    NSData *data = [a_pServerResponse dataUsingEncoding:NSUTF8StringEncoding];
                    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&errors];
                    if (!errors) {
                        NSString *userName = dict[@"description"][@"authenticatorsSucceeded"][0][@"userName"];
                        [[NSUserDefaults standardUserDefaults]setValue:userName forKey:@"username"];
                        NSNumber * statusCode = dict[@"statusCode"];
                        if ([statusCode  isEqual: @1200]) {
                            
                            dispatch_async(dispatch_get_main_queue(), ^{
                                
                                [self changeMainView];
                                
                            });
                            
                        }else{
                            
                            
                            [TAUtils displayMessage:@"Authentication failed." andShow:@"error"];
                            
                        }
                        
                        
                    }else{
                        NSLog(@"%@",errors);
                    }

                    
                }else{
                    [TAUtils displayMessage:@"don't have data." andShow:@"error"];
                    
                }
                
               
                
            } else if(status == 1)
            {
                [TAUtils displayMessage:@"running failed" andShow:@"testak"];
            }
            else if(status == 2)
            {
                [TAUtils displayMessage:@"usercanal" andShow:@"testak"];
            }
            else if(status == 3)
            {
                [TAUtils displayMessage:@" have no avaliable authticator" andShow:@"testak"];
            }
            else if(status == 10)
            {

                [TAUtils displayMessage:@"PROTOCOL ERROR" andShow:@"testak"];
            }
            else if(status == 11)
            {
                [TAUtils displayMessage:@"policy can not understand" andShow:@"testak"];
            }
                
                NSLog(@"JsonOuttext %@ ,status %d", JsonOuttext, status);
              
            
            
                dispatch_async(dispatch_get_main_queue(), ^{
                    [TAUtils dismissProgressDialog];
                });

            
            });

            
        }
            
            break;
        case 1001:
        {
            
            NSString * usernames = [username.text stringByReplacingOccurrencesOfString:@" " withString:@""];
            
            
            if (![usernames isEqualToString:@""] ) {
                
                [[NSUserDefaults standardUserDefaults]setValue:username.text forKey:@"username"];
                
                //[[NSUserDefaults standardUserDefaults]setValue:password.text forKey:@"password"];
                
                
                
                [self changeMainView];
                
            }else{
                [TAUtils displayMessage:@"Please check the user name and password." andShow:@"warning"];
            }
            
            
            
            
            
        }
            
            
      
            break;
            
        default:
            break;
    }
    
    
    
    

}

- (void)changeMainView {
    
    UIApplication * app = [UIApplication sharedApplication];
    AppDelegate * app2 = app.delegate;
    MainViewController * mainbar = [[MainViewController alloc]init];
    mainbar.labelName = username.text;
    app2.window.rootViewController = mainbar;
    
    [[NSUserDefaults standardUserDefaults]setValue:@"on" forKey:@"online"];
}


- (void)NavButtonClick {
    
    installViewController *install = [[installViewController alloc]init];
    [self.navigationController pushViewController:install animated:YES];
    
    
    
}




- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    
    
    [username resignFirstResponder];
    [password resignFirstResponder];
}








@end
