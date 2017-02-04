//
//  ShoppingCart.m
//  testPro
//
//  Created by 张宁 on 16/7/13.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "ShoppingCart.h"
#import "HttpConnection.h"
#import "TutorialAppException.h"
#import "gmrz_client_interface.h"
#import "TAUtils.h"
@interface ShoppingCart ()

extern HttpConnection* gHttpConnection;


@property (weak, nonatomic) IBOutlet UILabel *priceNumber;


@property (weak, nonatomic) IBOutlet UILabel *priceSum;



@end

@implementation ShoppingCart


- (void)viewDidLoad {
    [super viewDidLoad];
    _priceNumber.text = self.Number;
    NSLog(@"%@",self.Number);
    
    _priceSum.text = [NSString stringWithFormat:@"$%d",[self.Number intValue] * 100];

    
}




- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)FIDOPay:(id)sender {
    
    [TAUtils showProgressDialog:self.view];

    
    dispatch_queue_t queue = dispatch_queue_create("com.ios.tutorialapp", NULL);
    dispatch_async(queue, ^{

        
    NSString *connect = [[[NSUserDefaults standardUserDefaults] objectForKey:@"connectUrl"] stringByAppendingString:[[NSUserDefaults standardUserDefaults]objectForKey:@"API"]];
        
    NSString *url = [connect stringByAppendingString:@"/auth/receive"];
    
    
    //NSString * url = @"https://test31.noknoklabs.cn:8443/uaf/v1/auth/receive";
    NSMutableDictionary* payload = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* value = [[NSMutableDictionary alloc] init];
  
    //    //Construct the transaction text
    NSString * transtext = [NSString stringWithFormat:@"你需要支付 $%d元",[self.Number intValue] *100];
        


    //    // Need top do base64 encoding on transaction text
    NSData *nsdata = [transtext    dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Encoded = [nsdata base64EncodedStringWithOptions:0];
        //
    [value   setObject:[[NSUserDefaults standardUserDefaults] objectForKey:@"username"] forKey:@USER_NAME];
    [value   setObject:@"default"          forKey:@POLICY_NAME];
    [value setObject:base64Encoded forKey:@TRANSACTION_TEXT];
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
        //        dispatch_async(dispatch_get_main_queue(), ^{
        //            [UIUtil dismissProgressDialog];
        //        });
        //throw ex;
        [TAUtils displayMessage:@"connect error." andShow:@"error"];
//        return;

    }
    
    
    NSLog(@"%@", response);
    
    
    NSMutableString* uafRequestMessage = [[NSMutableString alloc] init];
        if (response) {
            
    //parse out the json data
//    NSDictionary* json = [NSJSONSerialization
//                          JSONObjectWithData: [response dataUsingEncoding:NSUTF8StringEncoding] //1
//                          
//                          options:kNilOptions
//                          error:&error];
            NSDictionary* json  = @{};
            if (!error) {
    //    if(nil != json && nil == error){
    uafRequestMessage = [json objectForKey:@UAF_REQUEST];
    NSInteger statusCode        = [[json objectForKey:@STATUS_CODE] integerValue];
    
    NSString * JsonOuttext = [[NSString alloc] init];
    
    
        if (statusCode==0) {
          
//            NSString *str =@"{\"uafRequest\":\"[{\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":0},\\\"op\\\":\\\"Auth\\\",\\\"appID\\\":\\\"https://test.pinshan.com.cn:8443/UAFSampleProxy/uaf/facets.uaf\\\",\\\"serverData\\\":\\\"nZOG-bSwUdRSk9xw9GRSyiAl2IDoP6i46xEoG--X6l--Jjqtx69JfOp2yx5cx3RDuiEZ1ov5PuK4D9licbGRkzQgEP6Aww90D_SOBX8LAHa3_cD6uTD0Z3a7A49kzZXVyDmhIr0NGn5lyZ2egibJ\\\"},\\\"challenge\\\":\\\"Wwuwbhr5bOH1-fI_C-dD0A5jodIxfRacaBG2c8Lpo0s\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"EVBVrLrbQn9oZCrOuDNvyb03lJmF9PDaQpDZ0KYnlQw\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"OnDXEPaze1SUD-fzBZTFvenzP3iiLTS5yCwss9njxJ4\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"XPxH2Q7p_rEikNUfBXVSFhoagdz6dfVwjG941GU_XlA\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"xbWriK-vDUGOAJMlx02DjBsb7SOHcfrXvFuAYhn15VA\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"JrGKE_1kU-Dwh8SzEywZxK9o-IyjdMYqKytqLfwvsnM\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"XQkQu5Fwf5B_ych7WPYP62eFN5-E0pA_CDUqkLOTxAY\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"VlyFrJeAwWjaFV3C_CuAH2oyRKp02s1XARXwRWVa5G8\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"tT8-s_eDg6uaH8OS77dB_sJcg5RkSGRcFFhj17TDYdw\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"qugT4zxCDSlVrZVkGInXOwufHTCEVGWWeC39lhUd2_Q\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"ojMIbo1xik2KHEJWYPaMAEZIZeMNAbl5zGGRuLw2Psk\\\"]}],[{\\\"aaid\\\":[\\\"4e4e#400b\\\"],\\\"keyIDs\\\":[\\\"6kGSwaFr465lfzEAooi1CtKhlEjUdZTTdnXiM8o51iU\\\"]}],[{\\\"aaid\\\":[\\\"001A#3333\\\"],\\\"keyIDs\\\":[\\\"9jG4djjkvmq-YQa7OvRPp8Ngr5-n08AgOWUHrTzdvyw\\\"]}]]}}]\"}";
         
         int status =   [gmrz_client_interface process:response DoFido:gmrz_checkpolicy Methods:gmrz_default FidoOut:&JsonOuttext];
            
            
        status =   [gmrz_client_interface process:response DoFido:gmrz_authtication Methods:gmrz_keychain FidoOut:&JsonOuttext];
            
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
                        
                        NSNumber * statusCode = dict[@"statusCode"];
                        if ([statusCode  isEqual: @1200]) {
                            

                                
                            [TAUtils displayMessage:@"running success" andShow:@"testak"];
                            
                            
                        }else if([statusCode isEqual:@1498]){
                            
                            
                            [TAUtils displayMessage:@"Authentication failed." andShow:@"error"];
                            
                        }
                        
                        
                    }else{
                        NSLog(@"%@",errors);
                    }
                    
                    
                }
                
                
                
                
                
            }else if(status == 1)
            {
                
                [TAUtils displayMessage:@"running failed" andShow:@"testak"];
            }
            else if(status == 2)
            {
                [TAUtils displayMessage:@"usercanal" andShow:@"testak"];
            }
            else if(status == 3)
            {
                [TAUtils displayMessage:@"have no avaliable authticator" andShow:@"testak"];
            }
            else if(status == 8)
            {
                [TAUtils displayMessage:@"Pop Password authentication" andShow:@"testak"];
            }
            else if(status == 10)
            {
                
                [TAUtils displayMessage:@"PROTOCOL ERROR" andShow:@"testak"];
            }
            else if(status == 11)
            {
                [TAUtils displayMessage:@"policy can not understand" andShow:@"testak"];
            }

            
        }else if(statusCode == 1481){
            
            NSLog(@"%ld",(long)statusCode);
            [TAUtils displayMessage:@"Sorry , No Register" andShow:@"testak"];
        }
        
            }else{
                
                NSLog(@"%@",error);
            }
    
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [TAUtils dismissProgressDialog];
        });

    
    });
    
    
}


- (IBAction)passWordPay:(id)sender {
    UIAlertController * con = [UIAlertController alertControllerWithTitle:@"testak" message:@"请输入支付密码" preferredStyle:UIAlertControllerStyleAlert];
    [con addAction:[UIAlertAction actionWithTitle:@"ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        
        UITextField *tf =  con.textFields.firstObject;
        [tf resignFirstResponder];
        NSLog(@"%@",tf.text);
        if ([tf.text isEqualToString:[[NSUserDefaults standardUserDefaults]objectForKey:@"password"]]&&tf.text.length!=0) {
            [TAUtils displayMessage:@"Pay for success." andShow:@"testak"];
        }else{
            [TAUtils displayMessage:@"Pay for failure , Please check the payment password" andShow:@"testak"];

        }
        //按钮触发的方法
    }]];
    [con addAction:[UIAlertAction actionWithTitle:@"cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
        
        [TAUtils displayMessage:@"cancel trading." andShow:@"testak"];
        //按钮触发的方法
    }]];
    [con addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        
        textField.textAlignment = NSTextAlignmentCenter;
        
    }];
    [self presentViewController:con animated:YES completion:nil];
    
    
    
    
}





@end
