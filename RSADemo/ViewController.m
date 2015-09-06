//
//  ViewController.m
//  RSADemo
//
//  Created by lizhichao on 15/7/2.
//  Copyright (c) 2015年 com.doing. All rights reserved.
//

#import "ViewController.h"
#import "RSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *privateKey = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"RSAPrivateKey" ofType:@"txt"]
                                                     encoding:NSUTF8StringEncoding
                                                        error:nil];
    NSString *publicKey = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"RSAPublicKey" ofType:@"txt"]
                                                    encoding:NSUTF8StringEncoding
                                                       error:nil];

    NSString *ret = [RSA encryptString:@"tian1000" publicKey:publicKey];
    NSLog(@"encrypted: ***%@***", ret);
    
    NSString *mingWen = [RSA decryptString:ret privateKey:privateKey];
    NSLog(@"mingwen is %@",mingWen);
    
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
