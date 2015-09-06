/*
 @author: ideawu
 @link: https://github.com/ideawu/Objective-C-RSA
*/

#import <Foundation/Foundation.h>

@interface RSA : NSObject

/*
 RSA加密
 string：要加密的文本
 publicKey： 公钥
 */
+ (NSString *)encryptString:(NSString *)string publicKey:(NSString *)publicKey;

/*
 RSA加密
 data：要加密的二进制
 publicKey 公钥
 */
+ (NSString *)encryptData:(NSData *)data publicKey:(NSString *)publicKey;
/*
 RSA解密
 cipherString: 要解密的密文文本
 privateKey：解密的私钥
 */
+(NSString *)decryptString:(NSString *)cipherString privateKey:(NSString *)privateKey ;

@end
