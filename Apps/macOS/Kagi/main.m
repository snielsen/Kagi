#import <Foundation/Foundation.h>

#import "GCDWebServer.h"
#import "GCDWebServerDataResponse.h"

int main( int argc, const char* argv[] )
{
    @autoreleasepool
    {
        SecKeyAlgorithm signingAlgorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;

        NSMutableDictionary* keyPairs = [NSMutableDictionary dictionary];

        NSString* sshDirectory = [NSString stringWithFormat:@"%@/.ssh/", NSHomeDirectory()];

        for( NSString* file in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:sshDirectory error:NULL] )
        {
            NSString* content = [NSString stringWithContentsOfFile:[NSString stringWithFormat:@"%@/%@", sshDirectory, file] encoding:NSUTF8StringEncoding error:nil];
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
                        if( SecKeyIsAlgorithmSupported( privatekey, kSecKeyOperationTypeSign, signingAlgorithm ) )
                        {
                            SecKeyRef publickey = SecKeyCopyPublicKey( privatekey );
                            if( publickey )
                            {
                                CFDataRef publickeyBytes;
                                SecItemImportExportKeyParameters keyParams = { .version =  SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION, .passphrase = @"" };
                                if( SecItemExport( publickey, kSecFormatOpenSSL, 0, &keyParams, &publickeyBytes ) == 0 )
                                {
                                    [keyPairs setObject:@{ @"privatekey": (__bridge id _Nullable)(privatekey), @"publickey": [(NSData*)CFBridgingRelease( publickeyBytes ) base64EncodedStringWithOptions:0] } forKey:file];
                                }
                            }
                        }
                    }
                }
            }
        }

        GCDWebServer* webServer = [[GCDWebServer alloc] init]; // Create server

        // Add a handler to respond to GET requests on any URL
        [webServer addDefaultHandlerForMethod:@"GET" requestClass:[GCDWebServerRequest class] processBlock: ^GCDWebServerResponse* (GCDWebServerRequest* request)
        {
            GCDWebServerResponse* response = [GCDWebServerResponse responseWithStatusCode:404];

            if( [request.URL.path isEqualToString:@"/list"] )
            {
                NSMutableDictionary* publicKeys = [NSMutableDictionary dictionary];

                for( NSString* file in keyPairs )
                {
                    NSDictionary* keyPair = keyPairs[ file ];

//                    [publicKeys setObject:[[keyPair[ @"publickey" ] stringByReplacingOccurrencesOfString:@"/" withString:@"_"] stringByReplacingOccurrencesOfString:@"+" withString:@"-"] forKey:file];
                    [publicKeys setObject:keyPair[ @"publickey" ] forKey:file];
                }

                response = [GCDWebServerDataResponse responseWithJSONObject:publicKeys];
            }
            else if( [request.URL.path isEqualToString:@"/sign"] )
            {
                NSString* publickey = request.query[@"publickey"];
                if( publickey )
                {
                    BOOL foundKey = false;

//                    publickey = [[publickey stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"];

                    for( NSString* file in keyPairs )
                    {
                        NSDictionary* keyPair = keyPairs[ file ];

                        if( [publickey isEqualToString:keyPair[ @"publickey" ]] )
                        {
                            NSString* challengeString = request.query[ @"challenge" ];
                            if( challengeString )
                            {
                                NSString* characters  = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789"; int charactersLength = (int)[characters length];
                                NSMutableString* prefixString = [NSMutableString stringWithCapacity:128];
                                for( int i = 0; i < 128; i++ ){ [prefixString appendFormat:@"%C", [characters characterAtIndex:arc4random_uniform( charactersLength )]]; }

                                NSData* signature = (NSData*)CFBridgingRelease( SecKeyCreateSignature( (__bridge SecKeyRef)(keyPair[ @"privatekey" ]), signingAlgorithm, (__bridge CFDataRef)[[NSString stringWithFormat:@"%@_%@", prefixString, challengeString] dataUsingEncoding:NSUTF8StringEncoding], nil ) );
                                if( signature )
                                {
                                    response = [GCDWebServerDataResponse responseWithJSONObject:@{ @"publickey": publickey, @"prefix": prefixString, @"challenge": challengeString, @"signature": [signature base64EncodedStringWithOptions:0] }];
                                }
                                else{ response = [GCDWebServerResponse responseWithStatusCode:500]; }
                            }

                            foundKey = true;
                            break;
                        }
                    }

                    if( !foundKey ){ response = [GCDWebServerResponse responseWithStatusCode:404]; }
                }
                else{ response = [GCDWebServerResponse responseWithStatusCode:400]; }
            }

            [response setValue:@"*" forAdditionalHeader:@"Access-Control-Allow-Origin"];
            return response;
        }];

        [webServer runWithPort:18797 bonjourName:nil];
    }
    
    return 0;
}
