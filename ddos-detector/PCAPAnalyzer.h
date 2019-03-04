//
//  PCAPAnalyzer.h
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#ifndef PCAPAnalyzer_h
#define PCAPAnalyzer_h

#import <Cocoa/Cocoa.h>
#import "DDViewController.h"

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/stat.h>

using namespace std;

#pragma mark - typedef

// callback function for after filter block
typedef void (^FilterBlock)(NSMutableSet *_Nonnull result);

typedef NSMutableDictionary DDAttack;
typedef NSMutableDictionary DDPair;
typedef NSMutableDictionary DDUniquePairsMap;

// struct for a ddos attack
typedef struct DDOSAttack {
    int protocol;
    NSMutableSet * _Nonnull sourceIps;
    time_t startTime;
    time_t endTime;
    u_int numPackets;
} ddos_t;

#pragma mark - Globals

// min number of packets to even be considered a ddos attack
static const u_int THRESHOLD = 1000;
// min number of intervals to be considered a ddos attack
static const u_int MIN_INTERVALS = 6;
// interval in seconds
static const u_int INTERVAL = 600; // 10 min
// value of k for SpaceSaving algorithm
static const u_int MAP_MAX_SIZE = 1000000;

/* ALL USED FOR PROGRESS BAR
   DIVIDE NUM PACKETS BY FILE SIZE */

// for the progress bar in view
static double_t progress = 0;
// counts how many packets
static u_int counter = 0;
// file size
static off_t fSize;


static time_t startT;
static time_t endT;

// event names for packet analysis events
static NSString * _Nonnull const attackDetectedEvent = @"AttackDetected";
static NSString * _Nonnull const packetEvent = @"PacketReceived";
static NSString * _Nonnull const packetFinish = @"PacketsFinished";
static NSString * _Nonnull const filterFinish = @"FilteringFinished";

// self to be used for c functions - dark magic
__weak static id _Nullable __self;

// define interface for PCAPAnalyzer
@interface PCAPAnalyzer : NSObject

+ (time_t) startT;
+ (time_t) endT;
+ (double) progress;
+ (void) resetProgress;
- (void) analyze: (char *_Nonnull)filename;
- (void) filterAttacks: (NSArray *_Nonnull)attacks completion: (FilterBlock _Nonnull)block;

@end


#endif /* PCAPAnalyzer_h */
