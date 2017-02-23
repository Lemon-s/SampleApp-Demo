//
//  validateViewController.m
//  testPro
//
//  Created by 张宁 on 16/7/13.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "validateViewController.h"
#import "HttpConnection.h"
#import "TutorialAppException.h"
#import "gmrz_client_interface.h"
#import "TAUtils.h"


@interface validateViewController ()
@property (weak, nonatomic) IBOutlet UILabel *username;
@end

@implementation validateViewController

extern HttpConnection* gHttpConnection;


- (void)viewDidLoad {
    [super viewDidLoad];

    self.user = [[NSUserDefaults standardUserDefaults]objectForKey:@"username"];
    // Do any additional setup after loading the view from its nib.
    
    _username.text = [NSString stringWithFormat:@"%@,%@",@"Welcome",self.user];

}


- (IBAction)usersetting:(id)sender {
    

    [TAUtils showProgressDialog:self.view];
    dispatch_queue_t queue = dispatch_queue_create("com.ios.tutorialapp", NULL);
    dispatch_async(queue, ^{
        
    NSString *connect = [[[NSUserDefaults standardUserDefaults] objectForKey:@"connectUrl"] stringByAppendingString:[[NSUserDefaults standardUserDefaults]objectForKey:@"API"]];
        
        NSLog(@"%@",connect);
    NSString *url = [connect stringByAppendingString:@"/reg/receive"];

        
    
    
    NSMutableDictionary* payload = [[NSMutableDictionary alloc] init];
    NSMutableDictionary* value = [[NSMutableDictionary alloc] init];
    
    [value   setObject:self.user forKey:@USER_NAME];
    [value   setObject:@"default"          forKey:@POLICY_NAME];
    [payload setObject:value               forKey:@CONTEXT];
    
    
    
    
    
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
    
    
    NSLog(@"regist response is %@", response);
    

    NSMutableString* uafRequestMessage = [[NSMutableString alloc] init];
    //parse out the json data
    NSDictionary* json = [NSJSONSerialization
                          JSONObjectWithData: [response dataUsingEncoding:NSUTF8StringEncoding] //1
                          
                          options:kNilOptions
                          error:&error];
    //    if(nil != json && nil == error){
    uafRequestMessage = [json objectForKey:@UAF_REQUEST];
    NSInteger statusCode        = [[json objectForKey:@STATUS_CODE] integerValue];
        NSLog(@"%lu",(long)statusCode);
        
        if (statusCode == 1200) {
//        if (1) {
    NSString * JsonOuttext = [[NSString alloc] init];
    
    
//            NSString *str = @"{\"uafRequest\": \"[{\\\"header\\\":{\\\"upv\\\":{\\\"major\\\":1,\\\"minor\\\":0},\\\"op\\\":\\\"Reg\\\",\\\"appID\\\":\\\"https://test.pinshan.com.cn:8443/UAFSampleProxy/uaf/facets.uaf\\\",\\\"serverData\\\":\\\"TDMdfYWTO9Q0WxO7Zf1BXa7pGQkKECZ5MB2yW3VH_R3vusCfpOA6SgFD7c06mxjgHuLQXuT91ALpQ72dZ_9ajtVQ-xkCnGEcSukfVyeFht1Dr4DkFgU9tLLi1A0MoMp3kElUKj8YI_J-GpYSGNLV\\\"},\\\"challenge\\\":\\\"ygkpA965R6pNkGJhLwcBJfiu-sgmrkpvInmofQgPED8\\\",\\\"username\\\":\\\"15256560736\\\",\\\"policy\\\":{\\\"accepted\\\":[[{\\\"aaid\\\":[\\\"001A#2121\\\"]}],[{\\\"aaid\\\":[\\\"53EC#C002\\\"]}],[{\\\"aaid\\\":[\\\"4e4e#400b\\\"]}],[{\\\"aaid\\\":[\\\"001A#3333\\\"]}],[{\\\"aaid\\\":[\\\"ABCD#ABCD\\\"]}]],\\\"disallowed\\\":[{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"EVBVrLrbQn9oZCrOuDNvyb03lJmF9PDaQpDZ0KYnlQw\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"OnDXEPaze1SUD-fzBZTFvenzP3iiLTS5yCwss9njxJ4\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"XPxH2Q7p_rEikNUfBXVSFhoagdz6dfVwjG941GU_XlA\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"xbWriK-vDUGOAJMlx02DjBsb7SOHcfrXvFuAYhn15VA\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"JrGKE_1kU-Dwh8SzEywZxK9o-IyjdMYqKytqLfwvsnM\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"XQkQu5Fwf5B_ych7WPYP62eFN5-E0pA_CDUqkLOTxAY\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"VlyFrJeAwWjaFV3C_CuAH2oyRKp02s1XARXwRWVa5G8\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"tT8-s_eDg6uaH8OS77dB_sJcg5RkSGRcFFhj17TDYdw\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"qugT4zxCDSlVrZVkGInXOwufHTCEVGWWeC39lhUd2_Q\\\"]},{\\\"aaid\\\":[\\\"53EC#C002\\\"],\\\"keyIDs\\\":[\\\"ojMIbo1xik2KHEJWYPaMAEZIZeMNAbl5zGGRuLw2Psk\\\"]}]}}]\"}";
//        
    int status =   [gmrz_client_interface process:response DoFido:gmrz_register Methods:gmrz_default FidoOut:&JsonOuttext];
    
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
        //NSString* urlsend =@"https://test31.noknoklabs.cn:8443/uaf/v1/reg/send";
        httpSendRequestReadResponse(gHttpConnection,
                                    urlsend,
                                    jsonNSString,
                                    @"POST",
                                    &a_pServerResponse);
        
        NSLog(@"a_pServerResponse %@", a_pServerResponse);
        NSError *errors = nil;
        NSData *data = [a_pServerResponse dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&errors];
        if (!errors) {
            NSNumber *status = dict[@"statusCode"];
            NSString *statusMsg = dict[@"description"][@"statusMsg"];
            if ([status isEqual:@1200]) {
            [TAUtils displayMessage:@"running success" andShow:@"testak"];
            }else{
            [TAUtils displayMessage:statusMsg andShow:@"testak"];
            }
            
        }else {
            NSLog(@"%@",errors);
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

    
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [TAUtils dismissProgressDialog];
        });
        
    });
    
    
    
    
    
    
    
}













- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
