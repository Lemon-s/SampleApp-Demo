//
//  HttpConnection.m

#import "HttpConnection.h"
#import "TutorialAppException.h"
#import <UIKit/UIKit.h>
#include "Constants.h"
#import "TAUtils.h"

HttpConnection* gHttpConnection = [[HttpConnection alloc] init];


//NSString * fidoV1URL(NSString * folder)
//{
//    //Construct the fido URL to be used for request processing
//    
//    NSString* fido_url =  [NSString stringWithFormat: @REST_SERVER_ADDRESS];
//    NSString* url = [[fido_url stringByAppendingString: @V1_API_PREFIX] stringByAppendingString:folder];
//    
//    return url;
//}



void httpSendRequest (const HttpConnection* httpcon,
                      NSString* aURL,
                      NSString* aBody,
                      NSString* aMethod)
{
    // check is valid connection is passed
    if (!httpcon) {
        throw TutorialAppException("Error",
                                   "Connection error",
                                   EXCEPTION_TYPE_CONNECTION_ERROR);
    }
    NSString *protocol = [aURL substringToIndex:5];
    if( ![[protocol  lowercaseString] isEqualToString:@"https"])
        throw TutorialAppException("Error",
                                   "Connection error",
                                   EXCEPTION_TYPE_CONNECTION_ERROR);
    
    [httpcon sendRequestWithData:aBody withMethod:aMethod withURL:aURL];
    
}

void httpReadResponse(const HttpConnection* httpcon,
                      NSString** aBody)
{
    // check is valid connection is passed
    if (!httpcon) {
        throw TutorialAppException("Error",
                                   "Connection error",
                                   EXCEPTION_TYPE_CONNECTION_ERROR);
    }
    
    long error = [httpcon readResponseWithData:aBody];
    
    if(!error) {
#if !__has_feature(objc_arc)
        [nsResBody release];
#endif
    }
    
    if(error != HTTP_OK)
        [TAUtils displayMessage:@"connect error." andShow:@"error"];
    return;

//        throw TutorialAppException("",
//                                   "Connection error",
//                                   EXCEPTION_TYPE_CONNECTION_ERROR);
}

void httpSendRequestReadResponse (const HttpConnection* aHttpConnection,
                                  NSString* aInURL,
                                  NSString*  aInBody,
                                  NSString*  aMethod,
                                  NSString**  aOutBody)
{
    httpSendRequest(aHttpConnection, aInURL, aInBody, aMethod);
    
    httpReadResponse(aHttpConnection, aOutBody);
}



@implementation HttpConnection

-(id)init
{
    self = [super init];
    mHttpHeaders = [[ NSMutableDictionary alloc] init];
    mResponseHeaders = [[NSMutableDictionary alloc] init];
    mReceivedData = [[NSMutableData alloc] init];
    mCookies = [[NSMutableDictionary alloc] init];
    [self setHeadersValue:@"application/fido+uaf; charset=UTF-8" forKey: @"Content-Type"];
    return self;
}

- (void) setHeadersValue:(NSString*) value forKey:(NSString*) key
{
    [mHttpHeaders setValue: value forKey: key];
}

/**
 * Send an HTTP request to the proxy
 */
- (void)sendRequestWithData:(NSString *)aData withMethod:(NSString *)aMethod withURL:(NSString *) aURL{
    if ([aURL length] == 0) {
        throw TutorialAppException("Error",
                                   "Connection error",
                                   EXCEPTION_TYPE_CONNECTION_ERROR);
    }
    NSString* urlTextEscaped = [aURL stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    NSURL* URL = [NSURL URLWithString:urlTextEscaped];
    // get host address
    NSMutableURLRequest *request = [NSMutableURLRequest
                                    requestWithURL:URL
                                    cachePolicy:NSURLRequestUseProtocolCachePolicy
                                    timeoutInterval:10.0];
    
    [request setHTTPMethod:aMethod];

    if(![aData isEqualToString:@""])
    {
        [request addValue: @"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
        [request addValue: [NSString stringWithFormat:@"%lu", (unsigned long)[aData length]] forHTTPHeaderField:@"Content-Length"];

        [request setHTTPBody: [aData dataUsingEncoding:NSUTF8StringEncoding]];
    }

    for (NSString* key in mHttpHeaders)
    {
        NSString* value = [mHttpHeaders objectForKey:key];
        [request setValue: value forHTTPHeaderField:key];
    }

    mError = 0;

    // clear any existing data.
    [mResponseHeaders removeAllObjects];
    [mReceivedData setLength: 0];
    [mCookies removeAllObjects];

    
     mConnection = [[NSURLConnection alloc] initWithRequest:request delegate:self startImmediately: YES];

    isProcessed = NO;

    NSRunLoop *loop = [NSRunLoop currentRunLoop];
    while ((!isProcessed) && ([loop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]]))
    {
    }
}
- (long)readResponseWithData:(NSString **)aData {
    if(!mError) {
        *aData = [[NSString alloc] initWithData:mReceivedData encoding:NSUTF8StringEncoding];
    }
    return mError;
}


- (long)readResponseWithData:(NSString **)aData statusCode:(long*) aStatusCode {
    if(!mError) {
        *aData = [[NSString alloc] initWithData:mReceivedData encoding:NSUTF8StringEncoding];
        *aStatusCode = mStausCode;
    }
    return mError;
}

/**
 * Get the cookie from this connection
 */
- (NSString *)getCookie:(NSString *)aCookieName {
    NSString *cookie = [mCookies valueForKey: aCookieName];
    if(cookie == nil)
        cookie = @"";

    return cookie;
}

/**
 * Set the user ID
 */
- (void) setUserID:(NSString *)userID
{
    NSString* cookieValue = [NSString stringWithFormat:@"userID=%@", userID ];
    [mHttpHeaders setValue: cookieValue forKey: @"Cookie"];
}

/**
 * Clear the cookie
 */
- (void) clearCookie {
    [mHttpHeaders removeObjectForKey:@"Cookie"];
}

/**
 * Delegate method for NSURLConnection
 */
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
	NSHTTPURLResponse *resp = (NSHTTPURLResponse*)response;
	if ([resp respondsToSelector:@selector(allHeaderFields)]) {
        [mResponseHeaders addEntriesFromDictionary:[resp allHeaderFields]];
        
        mStausCode = [resp statusCode];
	}

    for(NSHTTPCookie *cookie in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL: resp.URL]) {
        [mCookies setValue: cookie.value forKey: cookie.name];
    }
}
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    [mReceivedData appendData:data];
}
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    mError = [error code];
    isProcessed = YES;
    [connection cancel];
}
- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    isProcessed = YES;
    [connection cancel];
}


+ (void)httpDeleteCookie:(NSString *) NSCookieName;{
    NSArray *cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies];
    for (NSHTTPCookie *cookie in cookies)
    {
        if([cookie.name isEqualToString:NSCookieName ] )
        {
            [[NSHTTPCookieStorage sharedHTTPCookieStorage] deleteCookie:cookie];
        }
    }
    [gHttpConnection clearCookie];
}



/**
 * Call the proxy with the UAF response
 */
//+ (void)callProxyWithFidoResponse: (NSString *)aFidoRsp
//                     forOperation: (NSString *)aOperation
//               getServerResponse: (NSMutableString**)a_pServerResponse
//{
//    
//    NSString* url = fidoV1URL(aOperation);
//    NSMutableDictionary* payload = [[NSMutableDictionary alloc] init];
//    [payload setObject: aFidoRsp forKey:@"uafResponse"];
//    NSError* error;
//    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload
//                                                       options:(NSJSONWritingOptions)NSJSONWritingPrettyPrinted
//                                                         error:&error];
//    NSString* jsonNSString =  [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
//    
//    //Send response to server
//    httpSendRequestReadResponse(gHttpConnection,
//                                url,
//                                jsonNSString,
//                                @"POST",
//                                a_pServerResponse);
//
//}

@end

@implementation AuthnrRegInfo

@synthesize descr;
@synthesize aaid;
@synthesize userName;
@synthesize regID;




@end
