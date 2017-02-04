//
//  managerViewController.h
//  testPro
//
//  Created by 张宁 on 16/7/13.
//  Copyright © 2016年 张宁. All rights reserved.
//

#import "BaseViewController.h"

@interface managerViewController : BaseViewController<UITableViewDelegate, UITableViewDataSource>
@property (weak, nonatomic) IBOutlet UITableView *mRegistrationsTable;
@property (nonatomic) bool               mbGetList;
@property (nonatomic,strong)NSMutableArray *mAuthList;
@property (nonatomic,strong)NSString *urlCont;
@end
