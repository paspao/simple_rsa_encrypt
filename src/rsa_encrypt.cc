#include <v8.h>
#include <node.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <stdio.h>
#include <node_buffer.h>
#include <unistd.h>
//#define  debug 1;


using namespace node;
using namespace v8;

class RsaEncrypter : ObjectWrap {
  private:
  public:
  	static Persistent<FunctionTemplate> s_ct;
    RsaEncrypter() {}
    ~RsaEncrypter() {}
    static void Init(Handle<Object> target) {
 Local<FunctionTemplate> local_function_template = FunctionTemplate::New(New);
 s_ct = Persistent<FunctionTemplate>::New(local_function_template);
 s_ct->InstanceTemplate()->SetInternalFieldCount(1); // 1 since a constructor function only references 1 object
 s_ct->SetClassName(String::NewSymbol("RsaEncrypter"));

 NODE_SET_PROTOTYPE_METHOD(s_ct, "encrypt", Encrypt);

 NODE_SET_PROTOTYPE_METHOD(s_ct, "decrypt", Decrypt);

 target->Set(String::NewSymbol("RsaEncrypter"),s_ct->GetFunction());
}


static Handle<Value> New(const Arguments& args) {
  HandleScope scope;
  RsaEncrypter* rsaencrypter_instance = new RsaEncrypter();
  rsaencrypter_instance->Wrap(args.This());

  return args.This();
}

static Handle<Value> Encrypt(const Arguments& args) {
  HandleScope scope;

  String::Utf8Value pubKey(args[0]->ToString());
  String::Utf8Value mesg(args[1]->ToString());
  #ifdef debug
  printf("C_Mesg: %s\n",*mesg);
  printf("C_Public Key:\n%s\n",*pubKey);
  #endif
  Local<Value> outString;
  outString=encrypt(*pubKey,*mesg); // *v8str points to the C string it wraps
  return outString;
}

static Handle<Value> Decrypt(const Arguments& args) {
  HandleScope scope;
  String::Utf8Value privKey(args[0]->ToString());
  String::Utf8Value encMesg(args[1]->ToString());
  
  ssize_t len = DecodeBytes(args[1], BINARY);
  unsigned char* buf = new unsigned char[len];
  (void)DecodeWrite((char *)buf, len, args[1], BINARY);
  
  Local<Value> outString;
  outString=decrypt(*privKey,buf);
  
 return outString;
}





static Local<Value> encrypt(char* publicKey, char * plainMesg)
{
	unsigned char *encrypted;
	RSA *rsaPublic;
	BIO *bmemPublic;

	bmemPublic = BIO_new(BIO_s_mem());

	int sizePublic=strlen(publicKey);

	BIO_write(bmemPublic, publicKey, sizePublic);

	//BIO_flush(bmemPublic);

	rsaPublic=RSA_new();

	PEM_read_bio_RSA_PUBKEY(bmemPublic, &rsaPublic, NULL, NULL);

#ifdef debug
	PEM_write_RSAPublicKey(stdout, rsaPublic);
#endif

	int size = RSA_size((const RSA*)rsaPublic);
	encrypted=(unsigned char*)malloc(size);
	RSA_public_encrypt(size,(unsigned char*) plainMesg, encrypted, rsaPublic, RSA_NO_PADDING);

	BIO_free(bmemPublic);

	RSA_free(rsaPublic);

	Local<Value> outString;
	outString=Encode(encrypted, size, BINARY);
    free(encrypted);
    #ifdef debug
	printf("C_Encrypted_Encoded\n%s\n",*outString);
	#endif
	return outString;
}


static Local<Value> decrypt( char* privateKey, unsigned char * encryptedMesg)
{
	RSA *rsaPrivate;
	BIO *bmemPrivate;
	int size;
	unsigned char *decrypted;


	bmemPrivate = BIO_new(BIO_s_mem());

	//BIO_flush(bmemPrivate);

	size=strlen( privateKey);

	BIO_write(bmemPrivate, privateKey, size);

	rsaPrivate=RSA_new();

	PEM_read_bio_RSAPrivateKey(bmemPrivate, &rsaPrivate, NULL, NULL);

#ifdef debug
		PEM_write_RSAPrivateKey(stdout, rsaPrivate,NULL,NULL,0,0,NULL);
#endif

		BIO_free(bmemPrivate);

#ifdef debug
		printf("Encrypt:%s\n",encryptedMesg);
#endif
		int size_ = RSA_size(rsaPrivate);
		decrypted=(unsigned char*)malloc(size_);
		RSA_private_decrypt(size_, (unsigned char*)encryptedMesg, decrypted, rsaPrivate, RSA_NO_PADDING);

#ifdef debug
		printf("Decrypted:%s\n",decrypted);
#endif

		RSA_free(rsaPrivate);
		int newsize=strlen((char*)decrypted);
		Local<Value> outString;

		outString=String::New((const char*)decrypted,newsize);
		free(decrypted);
 #ifdef debug
	printf("C_Decrit_encoded mesg:\n%s\n",*outString);
	#endif

		return outString;

}


};

Persistent<FunctionTemplate> RsaEncrypter::s_ct;
extern "C" { 
  static void init(Handle<Object> target) {
    RsaEncrypter::Init(target);
  }

  NODE_MODULE(simple_rsa_encrypt, init);
}
