#import <Cocoa/Cocoa.h>

#import "GCDWebServer.h"
#import "GCDWebServerDataResponse.h"

@interface KagiDelegate : NSObject <NSApplicationDelegate, NSTableViewDataSource>

    @property NSUserDefaults*       defaults;
    @property SecKeyAlgorithm       signingAlgorithm;
    @property NSMutableDictionary*  keyPairs;
    @property GCDWebServer*         webServer;

    @property IBOutlet NSWindow*    window;
    @property IBOutlet NSTableView* keysView;

@end
