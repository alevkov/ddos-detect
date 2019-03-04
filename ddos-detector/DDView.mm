//
//  DDView.m
//  ddos-detector
//
//  Created by Joanna Bitton on 4/16/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import "DDView.h"

@implementation DDView

// makes view background white
- (void)drawRect:(NSRect)dirtyRect {
    // set any NSColor for filling, say white:
    [[NSColor whiteColor] setFill];
    NSRectFill(dirtyRect);
    [super drawRect:dirtyRect];
}

@end
