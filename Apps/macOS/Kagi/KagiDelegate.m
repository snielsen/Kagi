#import "KagiDelegate.h"

#import <objc/runtime.h>

#import "KeyRowView.h"
#import "NewKeyRowView.h"

@implementation KagiDelegate

- (IBAction) createNewKey:(id)sender
{
    NSAlert* newKeyAlert = [[NSAlert alloc] init];

    [newKeyAlert addButtonWithTitle:@"OK"];
    [newKeyAlert addButtonWithTitle:@"Cancel"];
    newKeyAlert.messageText = @"New Key File Name";
    newKeyAlert.informativeText = @"Chose a descriptive name that reflects the identity or purpose of your new key.";

        NSTextField* fileNameInput = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
//        fileNameInput.stringValue = @"id_rsa";
        [newKeyAlert.window setInitialFirstResponder:fileNameInput];

    newKeyAlert.accessoryView = fileNameInput;

    NSModalResponse response = [newKeyAlert runModal];

    if( response == NSAlertFirstButtonReturn )
    {
        if( [[self.keyPairs allKeys] doesContain:fileNameInput.stringValue] )
        {
            NSAlert* alreadyExistsAlert = [[NSAlert alloc] init];
            [alreadyExistsAlert setMessageText:[NSString stringWithFormat:@"Key \"%@\" already exists", fileNameInput.stringValue]];
            [alreadyExistsAlert addButtonWithTitle:@"OK"];
            [alreadyExistsAlert runModal];
        }
        else
        {
            CFErrorRef error = NULL;
            SecKeyRef newPrivateKey = SecKeyCreateRandomKey( (__bridge CFDictionaryRef)@{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeySizeInBits: @2048 }, &error );

            CFDataRef privatekeyBytes;
            SecItemImportExportKeyParameters keyParams = { .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION, .passphrase = @"" };
            if( SecItemExport( newPrivateKey, kSecFormatOpenSSL, 0, &keyParams, &privatekeyBytes ) == 0 )
            {
                NSString* newKey = [(__bridge NSData*)privatekeyBytes base64EncodedStringWithOptions:0];

                NSArray* chunks = [[NSRegularExpression regularExpressionWithPattern:@".{1,64}" options:0 error:nil] matchesInString:newKey options:0 range:NSMakeRange( 0, newKey.length )];
                NSMutableString* lineBrokenKey = [NSMutableString string]; for( NSTextCheckingResult* chunk in chunks ){ [lineBrokenKey appendFormat:@"%@\n", [newKey substringWithRange: chunk.range]]; }

                NSString* completeKey = [NSString stringWithFormat:@"-----BEGIN RSA PRIVATE KEY-----\n%@-----END RSA PRIVATE KEY-----", lineBrokenKey];

                NSString* newKeyLocation = [NSString stringWithFormat:@"%@/%@", self.sshDirectory, fileNameInput.stringValue];

                // Eventually write the key with restricted permissions from the get go to prevent rogue processes from trying to pick it up.
                [completeKey writeToFile:newKeyLocation atomically:YES encoding:NSUTF8StringEncoding error:nil];
                [[NSFileManager defaultManager] setAttributes:@{ NSFilePosixPermissions : [NSNumber numberWithShort:0600] } ofItemAtPath:newKeyLocation error:nil];

                [self loadKeyPairs];
            }
        }
    }
}

- (IBAction) keyExposedCheck:(NSButton*)sender
{
    NSString* publickeyName = objc_getAssociatedObject( sender, @"publickeyName" );

    NSMutableDictionary* keyDefaults = [NSMutableDictionary dictionaryWithDictionary:[self.defaults objectForKey:publickeyName]];

    if( sender.state == NSControlStateValueOn ){ keyDefaults[ @"exposed" ] = @(YES); self.keyPairs[ publickeyName ][ @"exposed" ] = @(YES); }
                                           else{ keyDefaults[ @"exposed" ] = @(NO);  self.keyPairs[ publickeyName ][ @"exposed" ] = @(NO);  }

    [self.defaults setObject:keyDefaults forKey:publickeyName];
    [self.defaults synchronize];
}

- (NSInteger) numberOfRowsInTableView:(NSTableView*)tableView { return [self.keyPairs count] + 1; }

- (NSView*) tableView:(NSTableView*)tableView viewForTableColumn:(NSTableColumn*)tableColumn row:(NSInteger)row
{
    NSView* tableRow;

    if( row < [self.keyPairs count] )
    {
        KeyRowView* keyRow = [tableView makeViewWithIdentifier:@"KeyRowView" owner:self];

        NSString* publickeyName = [[self.keyPairs allKeys] objectAtIndex:row];
        NSDictionary* keyPair = self.keyPairs[ publickeyName ];

        keyRow.keyLabel.stringValue = publickeyName;

        if( [keyPair[ @"exposed" ] isEqualTo:@(YES)] ){ keyRow.keyExposed.state = NSControlStateValueOn;  }
                                                  else{ keyRow.keyExposed.state = NSControlStateValueOff; }

        objc_setAssociatedObject( keyRow.keyExposed, @"publickeyName", publickeyName, OBJC_ASSOCIATION_RETAIN_NONATOMIC );

        tableRow = keyRow;
    }
    else
    {
        NewKeyRowView* newKeyRow = [tableView makeViewWithIdentifier:@"NewKeyRowView" owner:self];

        tableRow = newKeyRow;
    }

    return tableRow;
}

- (void) loadKeyPairs
{
    self.keyPairs = [NSMutableDictionary dictionary];

    for( NSString* file in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.sshDirectory error:NULL] )
    {
        NSString* content = [NSString stringWithContentsOfFile:[NSString stringWithFormat:@"%@/%@", self.sshDirectory, file] encoding:NSUTF8StringEncoding error:nil];
        if( content )
        {
            NSMutableArray* lines = [NSMutableArray arrayWithArray:[content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]];

            NSString* firstLine = [lines firstObject];
            NSString* lastLine  = [lines lastObject]; while( [lastLine isEqualToString:@""] ){ [lines removeLastObject]; lastLine  = [lines lastObject]; }

            if( [firstLine isEqualToString:@"-----BEGIN RSA PRIVATE KEY-----"] &&
                [lastLine  isEqualToString:@"-----END RSA PRIVATE KEY-----"  ] )
            {
                NSString* keyString = @""; for( NSString* line in lines ){ if( (line != firstLine) && (line != lastLine) ){ keyString = [NSString stringWithFormat:@"%@%@", keyString, line]; } }

                NSData* data = [[NSData alloc] initWithBase64EncodedString:keyString options:0];

                SecKeyRef privatekey = SecKeyCreateWithData( (__bridge CFDataRef)data, (__bridge CFDictionaryRef)@{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate }, nil );
                if( privatekey )
                {
                    if( SecKeyIsAlgorithmSupported( privatekey, kSecKeyOperationTypeSign, self.signingAlgorithm ) )
                    {
                        SecKeyRef publickey = SecKeyCopyPublicKey( privatekey );
                        if( publickey )
                        {
                            CFDataRef publickeyBytes;
                            SecItemImportExportKeyParameters keyParams = { .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION, .passphrase = @"" };
                            if( SecItemExport( publickey, kSecFormatOpenSSL, 0, &keyParams, &publickeyBytes ) == 0 )
                            {
                                BOOL keyExposed = NO;

                                NSDictionary* keyDefaults = [self.defaults objectForKey:file];

                                if( keyDefaults ){ if( [keyDefaults[ @"exposed" ] isEqualTo:@(YES)] ){ keyExposed = YES; } }

                                NSMutableDictionary* keyPair = [NSMutableDictionary dictionaryWithDictionary:@{ @"privatekey" : (__bridge id _Nullable)(privatekey),
                                                                                                                @"publickey"  : [(NSData*)CFBridgingRelease( publickeyBytes ) base64EncodedStringWithOptions:0],
                                                                                                                @"exposed"    : @(keyExposed) }];
                                [self.keyPairs setObject:keyPair forKey:file];
                            }
                        }
                    }
                }
            }
        }
    }

    [self.keysView reloadData];
}

- (GCDWebServerDataResponse*) list
{
    NSMutableDictionary* publicKeys = [NSMutableDictionary dictionary];

    for( NSString* file in self.keyPairs )
    {
        if( [self.keyPairs[ file ][ @"exposed" ] isEqualTo:@(YES)] )
        {
            [publicKeys setObject:self.keyPairs[ file ][ @"publickey" ] forKey:file];
        }
    }

    return [GCDWebServerDataResponse responseWithJSONObject:publicKeys];
}

- (GCDWebServerResponse*) sign:(NSDictionary*)query
{
    NSString* publickey = query[@"publickey"];

    if( publickey )
    {
        BOOL foundKey = false;

        for( NSString* file in self.keyPairs )
        {
            NSDictionary* keyPair = self.keyPairs[ file ];

            if( [publickey isEqualToString:keyPair[ @"publickey" ]] )
            {
                NSString* challengeString = query[ @"challenge" ];
                if( challengeString )
                {
                    NSString* characters  = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789"; int charactersLength = (int)[characters length];
                    NSMutableString* prefixString = [NSMutableString stringWithCapacity:128];
                    for( int i = 0; i < 128; i++ ){ [prefixString appendFormat:@"%C", [characters characterAtIndex:arc4random_uniform( charactersLength )]]; }

                    NSData* signature = (NSData*)CFBridgingRelease( SecKeyCreateSignature( (__bridge SecKeyRef)(keyPair[ @"privatekey" ]), self.signingAlgorithm, (__bridge CFDataRef)[[NSString stringWithFormat:@"%@_%@", prefixString, challengeString] dataUsingEncoding:NSUTF8StringEncoding], nil ) );
                    if( signature )
                    {
                        return [GCDWebServerDataResponse responseWithJSONObject:@{ @"publickey": publickey, @"prefix": prefixString, @"challenge": challengeString, @"signature": [signature base64EncodedStringWithOptions:0] }];
                    }
                    else{ return [GCDWebServerResponse responseWithStatusCode:500]; }
                }

                foundKey = true;
                break;
            }
        }

        if( !foundKey ){ return [GCDWebServerResponse responseWithStatusCode:404]; }
    }

    return [GCDWebServerResponse responseWithStatusCode:400];
}

- (void) applicationDidFinishLaunching:(NSNotification*)aNotification
{
    self.defaults         = [NSUserDefaults standardUserDefaults];
    self.signingAlgorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
    self.sshDirectory     = [NSString stringWithFormat:@"%@/.ssh/", NSHomeDirectory()];

    [self loadKeyPairs];

    self.webServer = [[GCDWebServer alloc] init];

    [self.webServer addDefaultHandlerForMethod:@"GET" requestClass:[GCDWebServerRequest class] processBlock: ^GCDWebServerResponse* ( GCDWebServerRequest* request )
    {
        GCDWebServerResponse* response = [GCDWebServerResponse responseWithStatusCode:404];

             if( [request.URL.path isEqualToString:@"/list"] ){ response = [self list];               }
        else if( [request.URL.path isEqualToString:@"/sign"] ){ response = [self sign:request.query]; }

        [response setValue:@"*" forAdditionalHeader:@"Access-Control-Allow-Origin"];

        return response;
    }];

    [self.webServer startWithPort:18797 bonjourName:nil];
}

- (void) applicationWillTerminate:(NSNotification*)aNotification
{
    // Insert code here to tear down your application
}

@end
