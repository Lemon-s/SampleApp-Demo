//
//  AppDelegate.m
//  FIDOPro
//
//  Created by 张宁 on 16/7/14.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "AppDelegate.h"
#import "registerController.h"
#import "PlistTools.h"
#import "MainViewController.h"


@interface AppDelegate ()
@end

@implementation AppDelegate



- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    /*
    
    if ([application respondsToSelector:@selector(isRegisteredForRemoteNotifications)])
    {
        //IOS8
        //创建UIUserNotificationSettings，并设置消息的显示类类型
        UIUserNotificationSettings *notiSettings = [UIUserNotificationSettings settingsForTypes:(UIUserNotificationTypeNone) categories:nil];
        
        [application registerUserNotificationSettings:notiSettings];
        
    } else{ // ios7
        [application registerForRemoteNotificationTypes:(UIRemoteNotificationTypeNone)];
    }
    

    */
    
    
    
    if ([[[NSUserDefaults standardUserDefaults]objectForKey:@"online"]isEqualToString:@"on"]&&[[[NSUserDefaults standardUserDefaults]objectForKey:@"username"] length]!=0) {
        
        if ([[[NSUserDefaults standardUserDefaults] objectForKey:@"connectUrl"] length]==0) {
            
            
            [[NSUserDefaults standardUserDefaults] setValue:[PlistTools readPlist:@"REST_SERVER_ADDRESS"] forKey:@"connectUrl"];
            [[NSUserDefaults standardUserDefaults] setValue:[PlistTools readPlist:@"V1_API_PREFIX"] forKey:@"API"];
            
            
            
        }

            


        
        _window = [[UIWindow alloc]initWithFrame:[UIScreen mainScreen].bounds];
        _window.backgroundColor = [UIColor whiteColor];
        MainViewController *main = [[MainViewController alloc]init];
        _window.rootViewController = main;
        [_window makeKeyAndVisible];
        

        
        
    }else {
        

        
        if ([[[NSUserDefaults standardUserDefaults] objectForKey:@"connectUrl"] length]==0) {
            
            
            [[NSUserDefaults standardUserDefaults] setValue:[PlistTools readPlist:@"REST_SERVER_ADDRESS"] forKey:@"connectUrl"];
            [[NSUserDefaults standardUserDefaults] setValue:[PlistTools readPlist:@"V1_API_PREFIX"] forKey:@"API"];
            
            
            
        }

        

        
    _window = [[UIWindow alloc]initWithFrame:[UIScreen mainScreen].bounds];
    _window.backgroundColor = [UIColor whiteColor];
    registerController *rec = [[registerController alloc]init];
    UINavigationController * nav = [[UINavigationController alloc]initWithRootViewController:rec];
    _window.rootViewController = nav;
    [_window makeKeyAndVisible];


    }
    
    
    return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}





- (void)application:(UIApplication *)application
didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)deviceToken
{
    //NSLog(@"DeviceToken: {%@}",deviceToken);
    //这里进行的操作，是将Device Token发送到服务端
    
    
}








- (void)application:(UIApplication *)application didReceiveRemoteNotification:(NSDictionary *)userInfo{
    
    
    
    
    
    
    NSString *message = [[userInfo objectForKey:@"aps"]objectForKey:@"alert"];
    
    
    NSNotification * notice = [NSNotification notificationWithName:@"send" object:nil userInfo:@{@"sender":message}];
//    //发送消息
    [[NSNotificationCenter defaultCenter]postNotification:notice];
    
    
    
}
- (void)application:(UIApplication *)application didFailToRegisterForRemoteNotificationsWithError:(NSError *)error{
    
    NSLog(@"Regist fail%@",error);
}



- (void) application:(UIApplication *)application didRegisterUserNotificationSettings:(UIUserNotificationSettings *)notificationSettings{
    //[application registerForRemoteNotifications];
    
    
}





- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    
    }
- (void)dealloc {
    //[super dealloc];  非ARC中需要调用此句
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}


@end
