
#include <v8.h>
#include <node.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <stdio.h>
#include <node_buffer.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <sstream>


namespace node {

	class RsaEncrypter : ObjectWrap {
	  private:
	  	
	  	static unsigned char * encrypt(char* publicKey, char * plainMesg,int &size);
	  	static unsigned char * decrypt( char* privateKey, unsigned char * encryptedMesg);
	  	static v8::Persistent<v8::FunctionTemplate> s_ct;
	  
	  public:

	    RsaEncrypter(): ObjectWrap(){}
	    ~RsaEncrypter(){}
	    static void Init(v8::Handle<v8::Object> target);
	    static v8::Handle<v8::Value> New(const v8::Arguments& args);
	    static v8::Handle<v8::Value> EncryptSync(const v8::Arguments& args);
	    static v8::Handle<v8::Value> EncryptAsync(const v8::Arguments& args);
	    static void EncryptAsyncWork(uv_work_t* req);
	    static void AfterEncryptAsync(uv_work_t* req);
	    static v8::Handle<v8::Value> DecryptSync(const v8::Arguments& args);
	    static v8::Handle<v8::Value> DecryptAsync(const v8::Arguments& args);
	    static void DecryptAsyncWork(uv_work_t* req);
	    static void AfterDecryptAsync(uv_work_t* req);
struct Baton {
    
    uv_work_t request;
    
    v8::Persistent<v8::Function> callback;

    Baton(){
        error_message=NULL;
        publicKey=NULL;
        privateKey=NULL;
        mesgEncrypted=NULL;
        mesgDecrypted=NULL;
        mesgPlain=NULL;
        size=0;
    }
    bool error;
    char* error_message;
    char* publicKey;
    char* privateKey;
    unsigned char* mesgEncrypted;
    unsigned char* mesgDecrypted;
    char* mesgPlain;    
    int size;
    
};
	};
}