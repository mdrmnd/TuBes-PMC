#include <MFRC522.h> //library responsible for communicating with the module RFID-RC522
#include <SPI.h> //library responsible for communicating of SPI bus
#define SS_PIN    21
#define RST_PIN   22
#define SIZE_BUFFER     18
#define MAX_SIZE_BLOCK  16
#define greenPin     12
#define redPin       32
//used in authentication
MFRC522::MIFARE_Key key;
//authentication return status code
MFRC522::StatusCode status;
// Defined pins to module RC522
MFRC522 mfrc522(SS_PIN, RST_PIN);

#define CRYPTO_BYTES 16
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 8
#define CRYPTO_ABYTES 0



#include <Arduino.h>
#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include <string.h> //for memcpy
#include <stdio.h>


#if !ASCON_INLINE_MODE
#undef forceinline
#define forceinline
#endif

void string2hexString(unsigned char* input, int clen, char* output);
void *hextobyte(char *hexstring, unsigned char* bytearray );




#include <stdio.h>
#include <string.h>
#include "crypto_aead.h"

#define CRYPTO_BYTES 16
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16

unsigned long long mlen;
unsigned long long clen;
unsigned char plaintext[CRYPTO_BYTES];
byte cipher[CRYPTO_BYTES]; 
unsigned char npub[CRYPTO_NPUBBYTES]="";
unsigned char ad[CRYPTO_ABYTES]="";
unsigned char nsec[CRYPTO_ABYTES]="";  
unsigned char keycrypt[CRYPTO_KEYBYTES] = {0xFF,0xEA,0x00,0xAB,0x13,0x12,0xFF,0xEA,0x00,0xAB,0x13,0x12};
char pl[CRYPTO_BYTES]="hello";
char chex[CRYPTO_BYTES]="";
char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
char add[CRYPTO_ABYTES]="";


// void setup() {
//   Serial.begin(9600);

// }

// void loop() {


//   unsigned long long mlen;
//   unsigned long long clen;

//   unsigned char plaintext[CRYPTO_BYTES];
//   unsigned char cipher[CRYPTO_BYTES];
//   unsigned char npub[CRYPTO_NPUBBYTES] = {0};
//   unsigned char ad[CRYPTO_ABYTES] = {0};
//   unsigned char nsec[CRYPTO_ABYTES] = {0};

//   unsigned char key[CRYPTO_KEYBYTES];

//   char pl[CRYPTO_BYTES] = "hello";
//   char keyhex[2 * CRYPTO_KEYBYTES + 1] = "0123456789ABCDEF0123456789ABCDEF";
//   char nonce[2 * CRYPTO_NPUBBYTES + 1] = "000000000000111111111111";
//   char add[CRYPTO_ABYTES] = {0};

//   if (strlen(keyhex) != 32) {
//     Serial.println("Key length needs to be 16 bytes");
//     return;
//   }

//   strcpy((char *)plaintext, pl);
//   strcpy((char *)ad, add);
//   hextobyte(keyhex, key);
//   hextobyte(nonce, npub);

//   Serial.println("ASCON light-weight cipher");
//   Serial.print("Plaintext: ");
//   Serial.println((char *)plaintext);
//   Serial.print("Key: ");
//   Serial.println(keyhex); 
//   Serial.print("Nonce: ");
//   Serial.println(nonce);
//   Serial.print("Additional Information: ");
//   Serial.println((char *)ad);

//   Serial.print("Plaintext: ");
//   Serial.println((char *)plaintext);

//   int ret = crypto_aead_encrypt(cipher, &clen, plaintext, strlen((char *)plaintext), ad, strlen((char *)ad), nsec, npub, key);

//   Serial.print("Cipher: ");
//   for (int i = 0; i < clen; i++) {
//     Serial.print(cipher[i], HEX);
//   }
//   Serial.print(", Len: ");
//   Serial.println(clen);

//   ret = crypto_aead_decrypt(plaintext, &mlen, nsec, cipher, clen, ad, strlen((char *)ad), npub, key);

//   plaintext[mlen] = '\0';
//   Serial.print("Plaintext: ");
//   Serial.print((char *)plaintext);
//   Serial.print(", Len: ");
//   Serial.println(mlen);

//   if (ret == 0) {
//     Serial.println("Success!");
//   }
//   // do nothing
// }



void setup() {
  // initialize serial communication at 9600 bits per second:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
  Serial.println("Approach your reader card...");
  Serial.println();

  SPI.begin(); // Init SPI bus
  pinMode(greenPin, OUTPUT);
  pinMode(redPin, OUTPUT);
  
  // Init MFRC522
  mfrc522.PCD_Init();
}

void loop(){
   // Aguarda a aproximacao do cartao
   //waiting the card approach
  if ( ! mfrc522.PICC_IsNewCardPresent()) 
  {
    return;
  }
  // Select a card
  if ( ! mfrc522.PICC_ReadCardSerial()) 
  {
    return;
  }
  // Dump debug info about the card; PICC_HaltA() is automatically called
  //  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));</p><p>  
  //call menu function and retrieve the desired option
  
  //    Serial.println("OK...");
  int op = menu();
  if(op == 0){ 
    readingData();
  }
  else if(op == 1){ 
    writingData();
  }
  else {
    Serial.println(F("Incorrect Option!"));
    return;
  }
  // if( argc > 1 ) {
  //     strcpy(pl,argv[1]);
  // }
  // if( argc > 2 ) {
  //     strcpy(keyhex,argv[2]);
  // }
  //   if( argc > 3 ) {
  //     strcpy(nonce,argv[3]);
  // }
  //    if( argc > 4 ) {
  //     strcpy(add,argv[4]);
  // }
  // if (strlen(keyhex)!=32) {
  // printf("Key length needs to be 16 bytes");
  // return(0);
  // }
  //instructs the PICC when in the ACTIVE state to go to a "STOP" state
  mfrc522.PICC_HaltA(); 
  // "stop" the encryption of the PCD, it must be called after communication with authentication, otherwise new communications can not be initiated
  mfrc522.PCD_StopCrypto1();  
}

forceinline void ascon_loadkey(word_t* K0, word_t* K1, word_t* K2,
                               const uint8_t* k) {
  KINIT(K0, K1, K2);
  if (CRYPTO_KEYBYTES == 20) {
    *K0 = XOR(*K0, KEYROT(WORD_T(0), LOAD(k, 4)));
    k += 4;
  }
  *K1 = XOR(*K1, LOAD(k, 8));
  *K2 = XOR(*K2, LOAD(k + 8, 8));
}

forceinline void ascon_init(state_t* s, const uint8_t* npub, const uint8_t* k) {
  /* load nonce */
  word_t N0 = LOAD(npub, 8);
  word_t N1 = LOAD(npub + 8, 8);
  /* load key */
  word_t K0, K1, K2;
  ascon_loadkey(&K0, &K1, &K2, k);
  /* initialize */
  PINIT(s);
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 8)
    s->x0 = XOR(s->x0, ASCON_128_IV);
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 16)
    s->x0 = XOR(s->x0, ASCON_128A_IV);
  if (CRYPTO_KEYBYTES == 20) s->x0 = XOR(s->x0, ASCON_80PQ_IV);
  if (CRYPTO_KEYBYTES == 20) s->x0 = XOR(s->x0, K0);
  s->x1 = XOR(s->x1, K1);
  s->x2 = XOR(s->x2, K2);
  s->x3 = XOR(s->x3, N0);
  s->x4 = XOR(s->x4, N1);
  P(s, 12);
  if (CRYPTO_KEYBYTES == 20) s->x2 = XOR(s->x2, K0);
  s->x3 = XOR(s->x3, K1);
  s->x4 = XOR(s->x4, K2);
  printstate("initialization", s);
}

forceinline void ascon_adata(state_t* s, const uint8_t* ad, uint64_t adlen) {
  const int nr = (ASCON_RATE == 8) ? 6 : 8;
  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_RATE) {
      s->x0 = XOR(s->x0, LOAD(ad, 8));
      if (ASCON_RATE == 16) s->x1 = XOR(s->x1, LOAD(ad + 8, 8));
      P(s, nr);
      ad += ASCON_RATE;
      adlen -= ASCON_RATE;
    }
    /* final associated data block */
    word_t* px = &s->x0;
    if (ASCON_RATE == 16 && adlen >= 8) {
      s->x0 = XOR(s->x0, LOAD(ad, 8));
      px = &s->x1;
      ad += 8;
      adlen -= 8;
    }
    *px = XOR(*px, PAD(adlen));
    if (adlen) *px = XOR(*px, LOAD(ad, adlen));
    P(s, nr);
  }
  /* domain separation */
  s->x4 = XOR(s->x4, WORD_T(1));
  printstate("process associated data", s);
}

forceinline void ascon_encrypt(state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen) {
  const int nr = (ASCON_RATE == 8) ? 6 : 8;
  /* full plaintext blocks */
  while (mlen >= ASCON_RATE) {
    s->x0 = XOR(s->x0, LOAD(m, 8));
    STORE(c, s->x0, 8);
    if (ASCON_RATE == 16) {
      s->x1 = XOR(s->x1, LOAD(m + 8, 8));
      STORE(c + 8, s->x1, 8);
    }
    P(s, nr);
    m += ASCON_RATE;
    c += ASCON_RATE;
    mlen -= ASCON_RATE;
  }
  /* final plaintext block */
  word_t* px = &s->x0;
  if (ASCON_RATE == 16 && mlen >= 8) {
    s->x0 = XOR(s->x0, LOAD(m, 8));
    STORE(c, s->x0, 8);
    px = &s->x1;
    m += 8;
    c += 8;
    mlen -= 8;
  }
  *px = XOR(*px, PAD(mlen));
  if (mlen) {
    *px = XOR(*px, LOAD(m, mlen));
    STORE(c, *px, mlen);
  }
  printstate("process plaintext", s);
}

forceinline void ascon_decrypt(state_t* s, uint8_t* m, const uint8_t* c,
                               uint64_t clen) {
  const int nr = (ASCON_RATE == 8) ? 6 : 8;
  /* full ciphertext blocks */
  while (clen >= ASCON_RATE) {
    word_t cx = LOAD(c, 8);
    s->x0 = XOR(s->x0, cx);
    STORE(m, s->x0, 8);
    s->x0 = cx;
    if (ASCON_RATE == 16) {
      cx = LOAD(c + 8, 8);
      s->x1 = XOR(s->x1, cx);
      STORE(m + 8, s->x1, 8);
      s->x1 = cx;
    }
    P(s, nr);
    m += ASCON_RATE;
    c += ASCON_RATE;
    clen -= ASCON_RATE;
  }
  /* final ciphertext block */
  word_t* px = &s->x0;
  if (ASCON_RATE == 16 && clen >= 8) {
    word_t cx = LOAD(c, 8);
    s->x0 = XOR(s->x0, cx);
    STORE(m, s->x0, 8);
    s->x0 = cx;
    px = &s->x1;
    m += 8;
    c += 8;
    clen -= 8;
  }
  *px = XOR(*px, PAD(clen));
  if (clen) {
    word_t cx = LOAD(c, clen);
    *px = XOR(*px, cx);
    STORE(m, *px, clen);
    *px = CLEAR(*px, clen);
    *px = XOR(*px, cx);
  }
  printstate("process ciphertext", s);
}

forceinline void ascon_final(state_t* s, const uint8_t* k) {
  /* load key */
  word_t K0, K1, K2;
  ascon_loadkey(&K0, &K1, &K2, k);
  /* finalize */
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 8) {
    s->x1 = XOR(s->x1, K1);
    s->x2 = XOR(s->x2, K2);
  }
  if (CRYPTO_KEYBYTES == 16 && ASCON_RATE == 16) {
    s->x2 = XOR(s->x2, K1);
    s->x3 = XOR(s->x3, K2);
  }
  if (CRYPTO_KEYBYTES == 20) {
    s->x1 = XOR(s->x1, KEYROT(K0, K1));
    s->x2 = XOR(s->x2, KEYROT(K1, K2));
    s->x3 = XOR(s->x3, KEYROT(K2, WORD_T(0)));
  }
  P(s, 12);
  s->x3 = XOR(s->x3, K1);
  s->x4 = XOR(s->x4, K2);
  printstate("finalization", s);
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  state_t s;
  (void)nsec;
  *clen = mlen + CRYPTO_ABYTES;
  /* perform ascon computation */
  ascon_init(&s, npub, k);
  ascon_adata(&s, ad, adlen);
  ascon_encrypt(&s, c, m, mlen);
  ascon_final(&s, k);
  /* set tag */
  STOREBYTES(c + mlen, s.x3, 8);
  STOREBYTES(c + mlen + 8, s.x4, 8);
  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  state_t s;
  (void)nsec;
  if (clen < CRYPTO_ABYTES) return -1;
  *mlen = clen = clen - CRYPTO_ABYTES;
  /* perform ascon computation */
  ascon_init(&s, npub, k);
  ascon_adata(&s, ad, adlen);
  ascon_decrypt(&s, m, c, clen);
  ascon_final(&s, k);
  /* verify tag (should be constant time, check compiler output) */
  s.x3 = XOR(s.x3, LOADBYTES(c + clen, 8));
  s.x4 = XOR(s.x4, LOADBYTES(c + clen + 8, 8));
  return NOTZERO(s.x3, s.x4);
}

void string2hexString(unsigned char* input, int clen, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    for (i=0;i<clen;i+=2){
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;

    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}
void *hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02x", &bytearray[i]);
    }

}

//reads data from card/tag
void readingData()
{
  //prints the technical details of the card/tag
  mfrc522.PICC_DumpDetailsToSerial(&(mfrc522.uid)); 
  
  //prepare the key - all keys are set to FFFFFFFFFFFFh
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
  
  //buffer for read data
  byte buffer1[SIZE_BUFFER] = {0};
  byte buffer2[SIZE_BUFFER] = {0};
  unsigned char buffer[2*SIZE_BUFFER];
  unsigned char bullet[2*SIZE_BUFFER];
  //the block-1 to operate
  byte block = 8;
  byte size = SIZE_BUFFER;  //authenticates the block-1 to operate
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid)); //line 834 of MFRC522.cpp file
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    digitalWrite(redPin, HIGH);
    delay(1000);
    digitalWrite(redPin, LOW);
    return;
  }
  //read data from block-1
  status = mfrc522.MIFARE_Read(block, buffer1, &size);
  //the block-2 to operate
  byte block2 = 9;
  // block-2 authentication
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block2, &key, &(mfrc522.uid)); //line 834 of MFRC522.cpp file
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    digitalWrite(redPin, HIGH);
    delay(1000);
    digitalWrite(redPin, LOW);
    return;
  }  
  status = mfrc522.MIFARE_Read(block2, buffer2, &size);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Reading failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    digitalWrite(redPin, HIGH);
    delay(1000);
    digitalWrite(redPin, LOW);
    return;
  }
  else{
      digitalWrite(greenPin, HIGH);
      delay(1000);
      digitalWrite(greenPin, LOW);
  }
  memcpy(buffer, buffer1, 16);
  memcpy(&buffer[16], buffer2, sizeof(buffer2));
  Serial.print(F("\nData from RFID\n"));
  String str = String((char*)buffer);
  // for(int i = 0; i<2*SIZE_BUFFER; ++i){
  //   bullet[i] = buffer[i];
  // }
  //string2hexString(bullet,32,str);
  Serial.print(str);
  //decrypt process
  int ret = crypto_aead_decrypt(plaintext,&mlen,nsec,buffer,32,ad,0,npub,keycrypt);
 //prints read data
  for (uint8_t i = 0; i < MAX_SIZE_BLOCK; i++)
  {
      Serial.write(plaintext[i]);
  }
  Serial.println(" ");
}


void writingData(){
//prints thecnical details from of the card/tag
  mfrc522.PICC_DumpDetailsToSerial(&(mfrc522.uid)); 
  
  // waits 30 seconds dor data entry via Serial 
  Serial.setTimeout(30000L) ;     
  Serial.println(F("Enter the data to be written with the '#' character at the end \n[maximum of 16 characters]:"));

  //prepare the key - all keys are set to FFFFFFFFFFFFh
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  //buffer para armazenamento dos dados que iremos gravar
  //buffer for storing data to write
  byte buffer[MAX_SIZE_BLOCK] = "";
  byte block; //the block to operate
  byte dataSize; //size of data (bytes)
  byte cipher1[16] = {0};
  byte cipher2[16] = {0};
  //recover on buffer the data from Serial
  //all characters before chacactere '#'
  dataSize = Serial.readBytesUntil('#', (char*)buffer, MAX_SIZE_BLOCK);
  //void positions that are left in the buffer will be filled with whitespace
  for(byte i=dataSize; i < MAX_SIZE_BLOCK; i++)
  {
    buffer[i] = '\0';
  }
 
  block = 8; //the block to operate
  String str = String((char*)buffer); //transforms the buffer data in String
  Serial.println(str);
  // Encrypt Proccess
  int ret = crypto_aead_encrypt((unsigned char*)cipher,&clen,(unsigned char*)buffer,MAX_SIZE_BLOCK,ad,0,nsec,npub,keycrypt);
  string2hexString((unsigned char*)cipher,clen,chex);
  for(int i=0; i < 32; i++)
  {
    if(i<16){
      cipher1[i] = cipher[i];
    }
    else{
      cipher2[i-16] = cipher[i];
    }
  }
  Serial.print(chex);
  //slicing ciphertext
  // byte cipher1[16] = {0};
  // byte cipher2[16] = {0};
  // str = (char*) chex;
  // Serial.print(chex);
  // String str1 = str.substring(0,16);
  // String str2 = str.substring(16,32);
  // str1.getBytes(cipher1, 16);
  // str2.getBytes(cipher2, 16);
  //authenticates the block to operate
  //Authenticate is a command to hability a secure communication
  // block-1 authentication
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                    block, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    digitalWrite(redPin, HIGH);
    delay(1000);
    digitalWrite(redPin, LOW);
    return;
  }
  //else Serial.println(F("PCD_Authenticate() success: "));
  //Writes in the block
  status = mfrc522.MIFARE_Write(block, cipher1, MAX_SIZE_BLOCK);

  //block-2
  byte block2 = 9;
  // block-2 authentication  
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                    block2, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    digitalWrite(redPin, HIGH);
    delay(1000);
    digitalWrite(redPin, LOW);
    return;
  }
  status = mfrc522.MIFARE_Write(block2, cipher2, MAX_SIZE_BLOCK);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("\nMIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    digitalWrite(redPin, HIGH);
    delay(1000);
    digitalWrite(redPin, LOW);
    return;
  }
  else{
    Serial.println(F("\nMIFARE_Write() success: "));
    digitalWrite(greenPin, HIGH);
    delay(1000);
    digitalWrite(greenPin, LOW);
  } 
}


//menu to operation choice
int menu()
{
  Serial.println(("\nChoose an option:"));
  Serial.println(("0 - Reading data"));
  Serial.println(("1 - Writing data\n"));

  //waits while the user does not start data
  while(!Serial.available()){};
  
  //retrieves the chosen option
  int op = (int)Serial.read();
  
  //remove all characters after option (as \n per example)
  while(Serial.available()) {
    if(Serial.read() == '\n') break; 
    Serial.read();
  }
  return (op-48);//subtract 48 from read value, 48 is the zero from ascii table
}