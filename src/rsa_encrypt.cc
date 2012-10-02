
#include "rsa_encrypt.h"
//#define  debug 1;


using namespace node;
using namespace v8;

 

void RsaEncrypter::Init(Handle<Object> target) {
  Local<FunctionTemplate> local_function_template = FunctionTemplate::New(New);
  s_ct = Persistent<FunctionTemplate>::New(local_function_template);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1); // 1 since a constructor function only references 1 object
  s_ct->SetClassName(String::NewSymbol("RsaEncrypter"));

  NODE_SET_PROTOTYPE_METHOD(s_ct, "encryptSync", EncryptSync);

  NODE_SET_PROTOTYPE_METHOD(s_ct, "decryptSync", DecryptSync);

  NODE_SET_PROTOTYPE_METHOD(s_ct, "encrypt", EncryptAsync);

  NODE_SET_PROTOTYPE_METHOD(s_ct, "decrypt", DecryptAsync);

  target->Set(String::NewSymbol("RsaEncrypter"),s_ct->GetFunction());
}


Handle<Value> RsaEncrypter::New(const Arguments& args) {
  HandleScope scope;
  RsaEncrypter* rsaencrypter_instance = new RsaEncrypter();
  rsaencrypter_instance->Wrap(args.This());

  return args.This();
}

Handle<Value> RsaEncrypter::EncryptSync(const Arguments& args) {
  HandleScope scope;

  String::Utf8Value pubKey(args[0]->ToString());
  String::Utf8Value mesg(args[1]->ToString());
  #ifdef debug
  printf("C_Mesg: \n%s\n",*mesg);
  printf("C_Public Key:\n%s\n",*pubKey);
  #endif
  unsigned char *encrypted =NULL;
  int size=0;
  encrypted =encrypt(*pubKey,*mesg,size);
  #ifdef debug
  printf("\nC_Encrypted\n%s\n",encrypted);
  #endif
  Local<Value> outString;
  
  outString=Encode(encrypted, size, BINARY);
    free(encrypted);
  #ifdef debug
  printf("C_Encrypted_Encoded\n%s\n",*outString);
  #endif
  return outString;
}

Handle<Value> RsaEncrypter::DecryptSync(const Arguments& args) {
  HandleScope scope;
  String::Utf8Value privKey(args[0]->ToString());
  
  
  ssize_t len = DecodeBytes(args[1], BINARY);
  unsigned char* buf=NULL;
  buf = (unsigned char*)malloc(sizeof(unsigned char)*len);
  DecodeWrite((char *)buf, len, args[1], BINARY);
  #ifdef debug
  printf("\nBefore decrypt\n%s\n",buf);
  #endif
  
  unsigned char* result=NULL;
  result=decrypt(*privKey,buf);
  #ifdef debug
  printf("\nC_Decrypted\n%s\n",result);
  #endif
  int newsize=strlen((char*)result);
  Local<Value> outString;

  outString=Encode(result, newsize, BINARY);
  free(buf);
  free(result);
#ifdef debug
  printf("C_Decrit_encoded mesg:\n%s\n",*outString);
#endif

  
  
  return outString;
}



Handle<Value> RsaEncrypter::EncryptAsync(const Arguments& args)
  {

    if (!args[2]->IsFunction()) {
        return ThrowException(Exception::TypeError(
            String::New("Third argument must be a callback function")));
    }
    // There's no ToFunction(), use a Cast instead.
    Local<Function> callback = Local<Function>::Cast(args[2]);

    v8::String::Utf8Value publicKey(args[0]->ToString());
    v8::String::Utf8Value msg(args[1]->ToString());
    // This creates our work request, including the libuv struct.
    Baton* baton = new Baton();
    baton->error = false;//******************************************
    baton->publicKey=(char*)malloc(sizeof(char)*publicKey.length());
    baton->mesgPlain=(char*)malloc(sizeof(char)*msg.length());
    
    strcpy(baton->publicKey,*publicKey);

    strcpy(baton->mesgPlain,*msg);

    baton->request.data = baton;
    baton->callback = Persistent<Function>::New(callback);

    // Schedule our work request with libuv. Here you can specify the functions
    // that should be executed in the threadpool and back in the main thread
    // after the threadpool function completed.
    int status = uv_queue_work(uv_default_loop(), &baton->request, EncryptAsyncWork, AfterEncryptAsync);
    assert(status == 0);

    return Undefined();
  }


void RsaEncrypter::EncryptAsyncWork(uv_work_t* req)
  {
    Baton* baton = static_cast<Baton*>(req->data);

    // Do work in threadpool here.
    
    
    
    baton->mesgEncrypted =RsaEncrypter::encrypt(baton->publicKey, baton->mesgPlain,baton->size);
    #ifdef debug
    printf("Baton encrypted\n%s\n", baton->mesgEncrypted);
    #endif
  }

void RsaEncrypter::AfterEncryptAsync(uv_work_t* req)
  {
    HandleScope scope;
    Baton* baton = static_cast<Baton*>(req->data);

    if (baton->error) {
        Local<Value> err = Exception::Error(String::New(baton->error_message));

        // Prepare the parameters for the callback function.
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };

        // Wrap the callback function call in a TryCatch so that we can call
        // node's FatalException afterwards. This makes it possible to catch
        // the exception from JavaScript land using the
        // process.on('uncaughtException') event.
        TryCatch try_catch;
        baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    } else {
        // In case the operation succeeded, convention is to pass null as the
        // first argument before the result arguments.
        // In case you produced more complex data, this is the place to convert
        // your plain C++ data structures into JavaScript/V8 data structures.
        
        Local<Value> outString=Encode(baton->mesgEncrypted, baton->size, BINARY);
        const unsigned argc = 2;
        Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            outString
        };

        // Wrap the callback function call in a TryCatch so that we can call
        // node's FatalException afterwards. This makes it possible to catch
        // the exception from JavaScript land using the
        // process.on('uncaughtException') event.
        TryCatch try_catch;
        baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    }

    // The callback is a permanent handle, so we have to dispose of it manually.
    baton->callback.Dispose();
    delete baton;
  }


  Handle<Value> RsaEncrypter::DecryptAsync(const Arguments& args)
  {

    if (!args[2]->IsFunction()) {
        return ThrowException(Exception::TypeError(
            String::New("Third argument must be a callback function")));
    }
    // There's no ToFunction(), use a Cast instead.
    Local<Function> callback = Local<Function>::Cast(args[2]);
    
    v8::String::Utf8Value privateKey(args[0]->ToString());
    
    
    ssize_t len = DecodeBytes(args[1], BINARY);
    unsigned char* buf = new unsigned char[len];
    DecodeWrite((char*)buf, len, args[1], BINARY);
    
    // This creates our work request, including the libuv struct.
    Baton* baton = new Baton();
    baton->error = false;
    baton->privateKey=(char*)malloc(sizeof(char)*privateKey.length());
    //baton->mesgEncrypted=(unsigned char*)malloc(sizeof(unsigned char)*len);
    baton->mesgEncrypted=buf;
    strcpy(baton->privateKey,*privateKey);

    //strcpy((char*)baton->mesgEncrypted,buf);
    


    baton->request.data = baton;
    baton->callback = Persistent<Function>::New(callback);

    // Schedule our work request with libuv. Here you can specify the functions
    // that should be executed in the threadpool and back in the main thread
    // after the threadpool function completed.
    int status = uv_queue_work(uv_default_loop(), &baton->request, DecryptAsyncWork, AfterDecryptAsync);
    assert(status == 0);

    return Undefined();
  }


void RsaEncrypter::DecryptAsyncWork(uv_work_t* req)
  {
    Baton* baton = static_cast<Baton*>(req->data);

    // Do work in threadpool here.
    
    unsigned char* result=decrypt(baton->privateKey,baton->mesgEncrypted);
  
    
    
    baton->mesgDecrypted=result;
    // If the work we do fails, set baton->error_message to the error string
    // and baton->error to true.
  }

void RsaEncrypter::AfterDecryptAsync(uv_work_t* req)
  {
    HandleScope scope;
    Baton* baton = static_cast<Baton*>(req->data);

    if (baton->error) {
        Local<Value> err = Exception::Error(String::New(baton->error_message));

        // Prepare the parameters for the callback function.
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };

        // Wrap the callback function call in a TryCatch so that we can call
        // node's FatalException afterwards. This makes it possible to catch
        // the exception from JavaScript land using the
        // process.on('uncaughtException') event.
        TryCatch try_catch;
        baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    } else {
        // In case the operation succeeded, convention is to pass null as the
        // first argument before the result arguments.
        // In case you produced more complex data, this is the place to convert
        // your plain C++ data structures into JavaScript/V8 data structures.
        const unsigned argc = 2;
        int newsize=strlen((char*)baton->mesgDecrypted);
        //printf("\nlos loso\n%s\n",baton->mesgDecrypted);
        Local<Value> outString;

        outString=Encode(baton->mesgDecrypted, newsize, BINARY);
        Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            outString
        };

        // Wrap the callback function call in a TryCatch so that we can call
        // node's FatalException afterwards. This makes it possible to catch
        // the exception from JavaScript land using the
        // process.on('uncaughtException') event.
        TryCatch try_catch;
        baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    }

    // The callback is a permanent handle, so we have to dispose of it manually.
    baton->callback.Dispose();
    delete baton;
  }





unsigned char * RsaEncrypter::encrypt(char* publicKey, char * plainMesg,int &size)
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

  size = RSA_size((const RSA*)rsaPublic);
  encrypted=(unsigned char*)malloc(sizeof(unsigned char)*size);
  RSA_public_encrypt(size,(unsigned char*) plainMesg, encrypted, rsaPublic, RSA_NO_PADDING);

  BIO_free(bmemPublic);

  RSA_free(rsaPublic);

  return encrypted;

}


unsigned char * RsaEncrypter::decrypt( char* privateKey, unsigned char * encryptedMesg)
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

	

#ifdef debug
	printf("\nEncrypt:\n%s\n",encryptedMesg);
  printf("\nPrivate key:\n%s\n",privateKey);
#endif
	int size_ = RSA_size(rsaPrivate);
	decrypted=(unsigned char*)malloc(sizeof(unsigned char)*size_);
	RSA_private_decrypt(size_, encryptedMesg, decrypted, rsaPrivate, RSA_NO_PADDING);

#ifdef debug
	printf("\nDecrypted:\n%s\n",decrypted);
#endif
BIO_free(bmemPrivate);
	RSA_free(rsaPrivate);
	
  return decrypted;
	
}


Persistent<FunctionTemplate> RsaEncrypter::s_ct;
extern "C" { 
  static void init(Handle<Object> target) {
    RsaEncrypter::Init(target);
  }

  NODE_MODULE(simple_rsa_encrypt, init);
}
