/*
 @author: ideawu
 @link: https://github.com/ideawu/Objective-C-RSA
*/

#import "RSA.h"
#import <Security/Security.h>

@implementation RSA

/*
static NSString *base64_encode(NSString *str){
	NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
	if(!data){
		return nil;
	}
	return base64_encode_data(data);
}
*/

static NSString *base64_encode_data(NSData *data){
	data = [data base64EncodedDataWithOptions:0];
	NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return ret;
}

static NSData *base64_decode(NSString *str){
	NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
	return data;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key{
	// Skip ASN.1 public key header
	if (d_key == nil) return(nil);
	
	unsigned long len = [d_key length];
	if (!len) return(nil);
	
	unsigned char *c_key = (unsigned char *)[d_key bytes];
	unsigned int  idx    = 0;
	
	if (c_key[idx++] != 0x30) return(nil);
	
	if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
	else idx++;
	
	// PKCS #1 rsaEncryption szOID_RSA_RSA
	static unsigned char seqiod[] =
	{ 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
		0x01, 0x05, 0x00 };
	if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
	
	idx += 15;
	
	if (c_key[idx++] != 0x03) return(nil);
	
	if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
	else idx++;
	
	if (c_key[idx++] != '\0') return(nil);
	
	// Now make a new NSData from this buffer
	return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (SecKeyRef)addPublicKey:(NSString *)key{
	NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
	NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
	if(spos.location != NSNotFound && epos.location != NSNotFound){
		NSUInteger s = spos.location + spos.length;
		NSUInteger e = epos.location;
		NSRange range = NSMakeRange(s, e-s);
		key = [key substringWithRange:range];
	}
	key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
	key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
	key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
	key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
	
	// This will be base64 encoded, decode it.
	NSData *data = base64_decode(key);
	data = [RSA stripPublicKeyHeader:data];
	if(!data){
		return nil;
	}
	
	NSString *tag = @"what_the_fuck_is_this";
	NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
	
	// Delete any old lingering key with the same tag
	NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
	[publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
	[publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
	SecItemDelete((__bridge CFDictionaryRef)publicKey);
	
	// Add persistent version of the key to system keychain
	[publicKey setObject:data forKey:(__bridge id)kSecValueData];
	[publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
	 kSecAttrKeyClass];
	[publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
	 kSecReturnPersistentRef];
	
	CFTypeRef persistKey = nil;
	OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
	if (persistKey != nil){
		CFRelease(persistKey);
	}
	if ((status != noErr) && (status != errSecDuplicateItem)) {
		return nil;
	}

	[publicKey removeObjectForKey:(__bridge id)kSecValueData];
	[publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
	[publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
	[publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	
	// Now fetch the SecKeyRef version of the key
	SecKeyRef keyRef = nil;
	status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
	if(status != noErr){
		return nil;
	}
	return keyRef;
}

+ (NSString *)encryptString:(NSString *)string publicKey:(NSString *)publicKey
{
	NSData* data = [string dataUsingEncoding:NSUTF8StringEncoding];
	return [RSA encryptData:data publicKey:publicKey];
}

+ (NSString *)encryptData:(NSData *)data publicKey:(NSString *)publicKey;
{
	if(!data || !publicKey){
		return nil;
	}
	SecKeyRef keyRef = [RSA addPublicKey:publicKey];
    
	if(!keyRef){
		return nil;
	}
	
	const uint8_t *srcbuf = (const uint8_t *)[data bytes];
	size_t srclen = (size_t)data.length;
	
	size_t outlen = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
	if(srclen > outlen - 11){
		CFRelease(keyRef);
		return nil;
	}
	void *outbuf = malloc(outlen);
	
	OSStatus status = noErr;
	status = SecKeyEncrypt(keyRef,
						   kSecPaddingPKCS1,
						   srcbuf,
						   srclen,
						   outbuf,
						   &outlen
						   );
	NSString *ret = nil;
	if (status != 0) {
	}else{
		NSData *data = [NSData dataWithBytes:outbuf length:outlen];
		ret = base64_encode_data(data);
	}
	free(outbuf);
	CFRelease(keyRef);
	return ret;
}

/**********************************以下是解密方法***********************************/

+ (NSString *)X509PublicHeader
{
    return @"-----BEGIN PUBLIC KEY-----";
}


+(NSString *)X509PublicFooter
{
    return @"-----END PUBLIC KEY-----";
}


+(NSString *)PKCS1PublicHeader
{
    return  @"-----BEGIN RSA PUBLIC KEY-----";
}


+(NSString *)PKCS1PublicFooter
{
    return @"-----END RSA PUBLIC KEY-----";
}


+(NSString *)PEMPrivateHeader
{
    return @"-----BEGIN RSA PRIVATE KEY-----";
}


+(NSString *)PEMPrivateFooter
{
    return @"-----END RSA PRIVATE KEY-----";
}

+(NSMutableDictionary *)keyQueryDictionary:(NSString *)tag
{
    NSData *keyTag = [tag dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary *result = [[NSMutableDictionary alloc] init];
    [result setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [result setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [result setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [result setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked forKey:(__bridge id)kSecAttrAccessible];
    
    return result;
}

+(void)removeKey:(NSString *)tag
{
    NSDictionary *queryKey = [RSA  keyQueryDictionary:tag];
    SecItemDelete((__bridge CFDictionaryRef)queryKey);
}

+(BOOL)isPrivateKey:(NSString *)key
{
    if (([key rangeOfString:[RSA PEMPrivateHeader]].location != NSNotFound) && ([key rangeOfString:[RSA PEMPrivateFooter]].location != NSNotFound))
    {
        return YES;
    }
    
    return NO;
}

+(NSString *)strippedKey:(NSString *)key
                   header:(NSString *)header
                   footer:(NSString *)footer
{
    NSString *result = [[key stringByReplacingOccurrencesOfString:header
                                                       withString:@""] stringByReplacingOccurrencesOfString:footer withString:@""];
    
    return [[result stringByReplacingOccurrencesOfString:@"\n"
                                              withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
}

+(void)setPrivateKey:(NSString *)key
                  tag:(NSString *)tag
{
    [RSA removeKey:tag];
    
    NSString *strippedKey = nil;
    if ([RSA isPrivateKey:key])
    {
        strippedKey = [RSA strippedKey:key
                                 header:[RSA PEMPrivateHeader]
                                 footer:[RSA PEMPrivateFooter]];
    }
    
    NSData *strippedPrivateKeyData = base64_decode(strippedKey);
    
    NSMutableDictionary *keyQueryDictionary = [RSA keyQueryDictionary:tag];
    [keyQueryDictionary setObject:strippedPrivateKeyData forKey:(__bridge id)kSecValueData];
    [keyQueryDictionary setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [keyQueryDictionary setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    SecItemAdd((__bridge CFDictionaryRef)keyQueryDictionary, &persistKey);
    
    if (persistKey != nil)
    {
        CFRelease(persistKey);
    }

    return;
}

+(NSString *)privateKeyIdentifierWithTag:(NSString *)additionalTag
{
    NSString *identifier = [NSString stringWithFormat:@"%@.privateKey", [[NSBundle mainBundle] bundleIdentifier]];
    
    if (additionalTag)
    {
        identifier = [identifier stringByAppendingFormat:@".%@", additionalTag];
    }
    
    return identifier;
}

+(NSString *)privateKeyIdentifier
{
    return [self privateKeyIdentifierWithTag:nil];
}

+(SecKeyRef)keyRefWithTag:(NSString *)tag
{
    NSMutableDictionary *queryKey = [RSA keyQueryDictionary:tag];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    SecKeyRef key = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&key);
    return key;
}

+(NSString *)decryptString:(NSString *)cipherString privateKey:(NSString *)privateKey ;
{
    [RSA setPrivateKey:privateKey
                    tag:[RSA privateKeyIdentifier]];
    
    NSMutableDictionary *keyQueryDictionary = [RSA keyQueryDictionary:[RSA privateKeyIdentifier]];
    [keyQueryDictionary setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef privateKeyRef = [self keyRefWithTag:[self privateKeyIdentifier]];
    
    size_t plainBufferSize = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *plainBuffer = malloc(plainBufferSize);
    
    NSData *incomingData = base64_decode(cipherString);
    uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKeyRef);
    
    if (plainBufferSize < cipherBufferSize)
    {
        if (privateKey)
        {
            CFRelease(privateKeyRef);
        }
        
        free(plainBuffer);
        
        return nil;
    }
    
    SecKeyDecrypt(privateKeyRef,
                                       kSecPaddingPKCS1,
                                       cipherBuffer,
                                       cipherBufferSize,
                                       plainBuffer,
                                       &plainBufferSize);
    
    NSString *decryptedString = [[NSString alloc] initWithBytes:plainBuffer
                                                         length:plainBufferSize
                                                       encoding:NSUTF8StringEncoding];
    
    free(plainBuffer);
    
    if (privateKey)
    {
        CFRelease(privateKeyRef);
    }
    return decryptedString;
}

@end
