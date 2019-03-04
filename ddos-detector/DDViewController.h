//
//  DDViewController.h
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <MapKit/MapKit.h>

// controller conforms to these protocols: NSTableViewDelegate & NSTableViewDataSource
// aka -> implement functions pre-defined in these protocols for the table view
@interface DDViewController : NSViewController<NSTableViewDelegate, NSTableViewDataSource>

// these properties connect to the view (storyboard)
@property (weak) IBOutlet NSTextField *alertLabel;
@property (weak) IBOutlet NSTableView *tableView;
@property (weak) IBOutlet NSProgressIndicator *progressIndicator;
@property (weak) IBOutlet NSTextField *timerLabel;
@property (weak) IBOutlet NSButton *alertButton;
@property (weak) IBOutlet MKMapView *mapView;

@end

