//
//  HttpConnection.h

#import <Foundation/Foundation.h>

#define STATUS_CODE "statusCode"
#define POLICY_NAME "policyName"
#define CONTEXT     "context"
#define USER_NAME   "userName"
#define UAF_REQUEST "uafRequest"
#define TRANSACTION_TEXT       "transactionText"

@interface AuthnrRegInfo : NSObject

@property NSString* descr;
@property NSString* aaid;
@property NSString* userName;
@property NSObject* regID;

@end




@interface HttpConnection : NSObject
{
    @private NSMutableData       *mReceivedData;
    @private NSMutableDictionary *mResponseHeaders;
    @private NSMutableDictionary *mCookies;
    @private long                mError;
    @private BOOL                isProcessed;
    @private NSInteger           mStausCode;
    @private NSMutableDictionary *mHttpHeaders;
    @private NSURLConnection     *mConnection;
}
- (void)sendRequestWithData:(NSString *)aData withMethod:(NSString *)aMethod withURL:(NSString *) aURL;
- (long)readResponseWithData:(NSString **)aData;
- (long)readResponseWithData:(NSString **)aData statusCode:(long*) aStatusCode;
- (NSString *)getCookie:(NSString *)aCookieName;
- (void) setUserID:(NSString *)userID;
- (void) clearCookie;
- (void) setHeadersValue:(NSString*) value forKey:(NSString*) key;
+ (void)httpDeleteCookie:(NSString *) NSCookieName;



//+ (void)callProxyWithFidoResponse: (NSString *)aFidoRsp
//                        forOperation: (NSString *)aOperation
//                        getServerResponse: (NSMutableString**)a_pServerResponse;

void httpSendRequestReadResponse (const HttpConnection* aHttpConnection,
                                  NSString* aInURL,
                                  NSString*  aInBody,
                                  NSString*  aMethod,
                                  NSString**  aOutBody);
@end
