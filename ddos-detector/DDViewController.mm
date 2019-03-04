//
//  DDViewController.mm
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import "DDViewController.h"
#import "PCAPAnalyzer.h"
#import "AFNetworking.h"

#include <iostream>

using namespace std;

typedef NSMutableDictionary DDAttack;

// constants that define the id for a certain part of the table view (each cell)
static const NSString *destCellId = @"DestCellID";
static const NSString *sourceCellId = @"SourceCellID";
static const NSString *protocolCellId = @"ProtocolCellID";
static const NSString *packetNumCellId = @"PacketNumberCellID";

@interface DDViewController ()

// extra props in view controller
@property (nonatomic, retain) PCAPAnalyzer *analyzer;
@property (atomic, retain) NSMutableArray<DDAttack *> *attacks;
@property (nonatomic, assign) CFTimeInterval ticks;
@property (nonatomic, retain) NSTimer *timer;
@property (nonatomic, retain) NSMutableSet *ips;

@end

@implementation DDViewController

// constructor for view controller
- (instancetype)init
{
    self = [super init];
    if (self) {
        
    }
    return self;
}

#pragma mark - View LifeCycle

// these functions implement events in NSViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.attacks = [NSMutableArray new];
    self.ips = [NSMutableSet new];
    [self.progressIndicator setMinValue: 0.0];
    [self.progressIndicator setMaxValue: 1.0];
    
    PCAPAnalyzer *analyzer = [PCAPAnalyzer new];
    self.analyzer = analyzer;

    // defines notif for certain events and their callback functions (selector)
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(endPacketNotification:)
                                                 name:packetFinish
                                               object:nil];
}

- (void) viewDidAppear  {
    [super viewDidAppear];
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

#pragma mark - Notifications

- (void) endPacketNotification: (NSNotification *) notification {
    self.alertButton.enabled = true;
    NSDictionary *dict = [notification userInfo];
    self.attacks = [dict objectForKey: @"attacks"];
    [self.alertLabel setStringValue: @"capture finished"];
    // create weak version of self in order to veer away from a reference cycle
    // essentially, create weak version so that it deallocates when it goes out of scope after callback
    __weak __typeof__(self) weakSelf = self;
    [self.analyzer filterAttacks:self.attacks completion:^(NSMutableSet *response) {
        // create strong version of the weak version ? welcome to objective-c buddies
        __typeof__(self) strongSelf = weakSelf;
        strongSelf.attacks = [response allObjects].mutableCopy;
        for (DDAttack *attack in strongSelf.attacks) {
            for (NSString *ip in [attack objectForKey:@"sourceIps"]) {
                [strongSelf.ips addObject:ip.mutableCopy];
            }
        }
        
        // call ipinfo API for geolocation data
        NSURL *baseURL = [NSURL URLWithString:@"http://ipinfo.io/"];
        AFHTTPSessionManager *manager = [[AFHTTPSessionManager alloc] initWithBaseURL:baseURL];
        for (NSMutableString *ip in strongSelf.ips) {
           [ip appendString:@"/json"];
            [manager GET:ip parameters:nil progress:^(NSProgress * _Nonnull downloadProgress) {
                NSLog(@"%@", downloadProgress);
            } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
                if (responseObject[@"city"] != nil) {
                    CLLocationCoordinate2D coord;
                    NSString *loc = responseObject[@"loc"];
                    NSArray *latlon = [loc componentsSeparatedByString:@","];
                    coord.latitude = ((NSString *) latlon[0]).doubleValue;
                    coord.longitude = ((NSString *) latlon[1]).doubleValue;
                    MKPointAnnotation *point = [MKPointAnnotation new];
                    point.coordinate = coord;
                    point.title = responseObject[@"hostname"];
                    [strongSelf.mapView addAnnotation: point];
                }
            } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
                NSLog(@"Failure: %@", error);
            }];
        }
        
        [strongSelf.progressIndicator setDoubleValue: 1.0];
        [strongSelf.tableView reloadData];
        [strongSelf.timer invalidate];
    }];
}

#pragma mark - NSTableView

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex {
    DDAttack *attack = [self.attacks objectAtIndex:rowIndex];
    if ([aTableColumn.identifier isEqualToString: destCellId.mutableCopy]) {
        return (NSString *) [attack objectForKey: @"destIp"];
    }
    if ([aTableColumn.identifier isEqualToString: protocolCellId.mutableCopy]) {
        return (NSString *) [attack objectForKey: @"protocol"];
    }
    if ([aTableColumn.identifier isEqualToString:sourceCellId.mutableCopy]) {
        NSMutableString *ips = @"".mutableCopy;
        for (NSString *ip in (NSMutableSet *)[attack objectForKey: @"sourceIps"]) {
            [ips appendString:ip];
            [ips appendString:@"|"];
        }
        [ips deleteCharactersInRange:NSMakeRange([ips length] - 1, 1)];
        return ips;
    }
    if ([aTableColumn.identifier isEqualToString: packetNumCellId.mutableCopy]) {
        return [NSString stringWithFormat:@"%@", [attack objectForKey:@"numPackets"]];
    }
    return nil;
}

// TableView Datasource method implementation
- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return self.attacks.count;
}

#pragma mark - View Actions

- (IBAction)analyzeButtonTapped:(id)sender {
    self.ticks = 0.0;
    [self.progressIndicator setDoubleValue:0.0];
    [PCAPAnalyzer resetProgress];
    self.alertButton.enabled = false;
    [self.mapView removeAnnotations:self.mapView.annotations];
    self.timer = [NSTimer scheduledTimerWithTimeInterval: 1.0 target: self selector: @selector(timerTick:) userInfo: nil repeats:YES];
    [self.attacks removeAllObjects];
    [self.timerLabel setStringValue: [NSString stringWithFormat: @"%02.0f:%02.0f:%02.0f", 0.0, 0.0, 0.0]];
    [self.alertLabel setStringValue: @"started capture..."];
    [self.tableView reloadData];
    // create another thread to do the pcap analysis (with no delay)
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char filename[] = "14pcap.pcap";
        [self.analyzer analyze: filename];
    });
}

#pragma mark - Timer

- (void)timerTick:(NSTimer *)timer {
    // Timers are not guaranteed to tick at the nominal rate specified, so this isn't technically accurate.
    // However, this is just an example to demonstrate how to stop some ongoing activity, so we can live with that inaccuracy.
    self.ticks += 1;
    double seconds = fmod(_ticks, 60.0);
    double minutes = fmod(trunc(_ticks / 60.0), 60.0);
    double hours = trunc(_ticks / 3600.0);
    [self.progressIndicator setDoubleValue:[PCAPAnalyzer progress] * 100.0];
    [self.timerLabel setStringValue: [NSString stringWithFormat: @"%02.0f:%02.0f:%02.0f", hours, minutes, seconds]];
}

@end
