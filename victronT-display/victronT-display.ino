// Some understanding of this stuff might be found by digging around in the ESP32 library's
// file BLEAdvertisedDevice.h

/*
  Initial BLE code adapted from Examples->BLE->Beacon_Scanner.
  Victron decryption code snippets from:
  
    https://github.com/Fabian-Schmidt/esphome-victron_ble

  Information on the "extra manufacturer data" that we're picking up from Victron SmartSolar
  BLE advertising beacons can be found at:
  
    https://community.victronenergy.com/storage/attachments/48745-extra-manufacturer-data-2022-12-14.pdf
  
  Thanks, Victron, for providing both the beacon and the documentation on its contents!
*/ 

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <TFT_eSPI.h>
TFT_eSPI tft = TFT_eSPI();
TFT_eSprite sprite = TFT_eSprite(&tft);

float batVol;
float powIn=0;
int readings=0;
long nread=0;
int yeTod=0;
int deState=-1;

#include <aes/esp_aes.h>        // AES library for decrypting the Victron manufacturer data.
BLEScan *pBLEScan;


uint8_t key[16]={
    0x2b, 0xaa, 0xb6, 0x36, 0x0a, 0x89, 0x0b, 0x2e,
    0x1f, 0x11, 0xef, 0x77, 0x43, 0xb5, 0x8c, 0xcb
};

int keyBits=128;  // Number of bits for AES-CTR decrypt.
int scanTime = 1; // BLE scan time (seconds)

char savedDeviceName[32];   // cached copy of the device name (31 chars max) + \0


typedef struct {
  uint16_t vendorID;                    // vendor ID
  uint8_t beaconType;                   // Should be 0x10 (Product Advertisement) for the packets we want
  uint8_t unknownData1[3];              // Unknown data
  uint8_t victronRecordType;            // Should be 0x01 (Solar Charger) for the packets we want
  uint16_t nonceDataCounter;            // Nonce
  uint8_t encryptKeyMatch;              // Should match pre-shared encryption key byte 0
  uint8_t victronEncryptedData[21];     // (31 bytes max per BLE spec - size of previous elements)
  uint8_t nullPad;                      // extra byte because toCharArray() adds a \0 byte.
} __attribute__((packed)) victronManufacturerData;


// Must use the "packed" attribute to make sure the compiler doesn't add any padding to deal with
// word alignment.
typedef struct {
   uint8_t deviceState;
   uint8_t errorCode;
   int16_t batteryVoltage;
   int16_t batteryCurrent;
   uint16_t todayYield;
   uint16_t inputPower;
   uint8_t outputCurrentLo;             // Low 8 bits of output current (in 0.1 Amp increments)
   uint8_t outputCurrentHi;             // High 1 bit of output current (must mask off unused bits)
   uint8_t  unused[4];                  // Not currently used by Vistron, but it could be in the future.
} __attribute__((packed)) victronPanelData;


void draw()
  {
     
    sprite.fillSprite(TFT_BLACK); 
    sprite.drawString("POW W: "+String(powIn),6,40,4);
    sprite.drawString("BAT V: "+String(batVol),6,70,4);
    sprite.drawString("TOD Wh: "+String(yeTod),6,100,4);
    sprite.drawString("read: "+String(nread),6,130,4);
    sprite.drawString("state: "+String(deState),6,160,4);
    for(int i=0;i<readings;i++)
    sprite.fillRect(7+(i*10),10,7,4,TFT_WHITE);
    sprite.pushSprite(0,0);
  }


class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {

      #define manDataSizeMax 31     // BLE specs say no more than 31 bytes, but see comments below!


      // See if we have manufacturer data and then look to see if it's coming from a Victron device.
      if (advertisedDevice.haveManufacturerData() == true) {

        // Note: This comment (and maybe some code?) needs to be adjusted so it's not so
        // specific to String-vs-std:string. I'll leave it as-is for now so you at least
        // understand why I have an extra byte added to the manCharBuf array.
        //
        // Here's the thing: BLE specs say our manufacturer data can be a max of 31 bytes.
        // But: The library code puts this data into a String, which we will then copy to
        // a character (i.e., byte) buffer using String.toCharArray(). Assuming we have the
        // full 31 bytes of manufacturer data allowed by the BLE spec, we'll need to size our
        // buffer with an extra byte for a null terminator. Our toCharArray() call will need
        // to specify *32* bytes so it will copy 31 bytes of data with a null terminator
        // at the end.
        uint8_t manCharBuf[manDataSizeMax+1];

        #ifdef USE_String
          String manData = advertisedDevice.getManufacturerData();      // lib code returns String.
        #else
          std::string manData = advertisedDevice.getManufacturerData(); // lib code returns std::string
        #endif
        int manDataSize=manData.length(); // This does not count the null at the end.

        // Copy the data from the String to a byte array. Must have the +1 so we
        // don't lose the last character to the null terminator.
        #ifdef USE_String
          manData.toCharArray((char *)manCharBuf,manDataSize+1);
        #else
          manData.copy((char *)manCharBuf, manDataSize+1);
        #endif

        // Now let's setup a pointer to a struct to get to the data more cleanly.
        victronManufacturerData * vicData=(victronManufacturerData *)manCharBuf;

        // ignore this packet if the Vendor ID isn't Victron.
        if (vicData->vendorID!=0x02e1) {
          return;
        }

        // ignore this packet if it isn't type 0x01 (Solar Charger).
        if (vicData->victronRecordType != 0x01) {
          return;
        }

        // Not all packets contain a device name, so if we get one we'll save it and use it from now on.
        if (advertisedDevice.haveName()) {
          // This works the same whether getName() returns String or std::string.
          strcpy(savedDeviceName,advertisedDevice.getName().c_str());
        }
        
        if (vicData->encryptKeyMatch != key[0]) {
          Serial.printf("Packet encryption key byte 0x%2.2x doesn't match configured key[0] byte 0x%2.2x\n",
              vicData->encryptKeyMatch, key[0]);
          return;
        }

        uint8_t inputData[16];
        uint8_t outputData[16]={0};  // i don't really need to initialize the output.

        // The number of encrypted bytes is given by the number of bytes in the manufacturer
        // data as a whole minus the number of bytes (10) in the header part of the data.
        int encrDataSize=manDataSize-10;
        for (int i=0; i<encrDataSize; i++) {
          inputData[i]=vicData->victronEncryptedData[i];   // copy for our decrypt below while I figure this out.
        }

        esp_aes_context ctx;
        esp_aes_init(&ctx);

        auto status = esp_aes_setkey(&ctx, key, keyBits);
        if (status != 0) {
          Serial.printf("  Error during esp_aes_setkey operation (%i).\n",status);
          esp_aes_free(&ctx);
          return;
        }
        
        // construct the 16-byte nonce counter array by piecing it together byte-by-byte.
        uint8_t data_counter_lsb=(vicData->nonceDataCounter) & 0xff;
        uint8_t data_counter_msb=((vicData->nonceDataCounter) >> 8) & 0xff;
        u_int8_t nonce_counter[16] = {data_counter_lsb, data_counter_msb, 0};
        
        u_int8_t stream_block[16] = {0};

        size_t nonce_offset=0;
        status = esp_aes_crypt_ctr(&ctx, encrDataSize, &nonce_offset, nonce_counter, stream_block, inputData, outputData);
        if (status != 0) {
          Serial.printf("Error during esp_aes_crypt_ctr operation (%i).",status);
          esp_aes_free(&ctx);
          return;
        }
        esp_aes_free(&ctx);

        // Now do our same struct magic so we can get to the data more easily.
        victronPanelData * victronData = (victronPanelData *) outputData;

        // Getting to these elements is easier using the struct instead of
        // hacking around with outputData[x] references.
        uint8_t deviceState=victronData->deviceState;
        uint8_t errorCode=victronData->errorCode;
        float batteryVoltage=float(victronData->batteryVoltage)*0.01;
        float batteryCurrent=float(victronData->batteryCurrent)*0.1;
        float todayYield=float(victronData->todayYield)*0.01*1000;
        uint16_t inputPower=victronData->inputPower;  // this is in watts; no conversion needed

        // Getting the output current takes some magic because of the way they have the
        // 9-bit value packed into two bytes. The first byte has the low 8 bits of the count
        // and the second byte has the upper (most significant) bit of the 9-bit value plus some
        // There's some other junk in the remaining 7 bits - i'm not sure if it's useful for
        // anything else but we can't use it here! - so we will mask them off. Then combine the
        // two bye components to get an integer value in 0.1 Amp increments.
        int integerOutputCurrent=((victronData->outputCurrentHi & 0x01)<<9) | victronData->outputCurrentLo;
        float outputCurrent=float(integerOutputCurrent)*0.1;

        // I don't know why, but every so often we'll get half-corrupted data from the Victron. As
        // far as I can tell it's not a decryption issue because we (usually) get voltage data that
        // agrees with non-corrupted records.
        //
        // Towards the goal of filtering out this noise, I've found that I've rarely (or never) seen
        // corrupted data when the 'unused' bits of the outputCurrent MSB equal 0xfe. We'll use this
        // as a litmus test here.
        uint8_t unusedBits=victronData->outputCurrentHi & 0xfe;
        if (unusedBits != 0xfe) {
          return;
        }


        batVol=batteryVoltage;
        powIn=inputPower;
        yeTod=todayYield;
        deState=deviceState;
        readings++;
        if(readings==16) readings=0;

        nread++;

        Serial.printf("%-31s  Battery: %6.2f Volts %6.2f Amps  Solar: %6d Watts Yield: %6.0f Wh  Load: %6.1f Amps  State: %3d\n",
          savedDeviceName,
          batteryVoltage, batteryCurrent,
          inputPower, todayYield,
          outputCurrent, deviceState
        );

        draw();
      }
    }
};




void setup()
{

  pinMode(15,OUTPUT);
  digitalWrite(15,1);

  Serial.begin(115200);
  delay(1000);
  Serial.println();
  Serial.println();
  Serial.println("Reset.");
  Serial.println();
  Serial.printf("Source file: %s\n",__FILE__);
  Serial.printf(" Build time: %s\n",__TIMESTAMP__);
  Serial.println();
  delay(1000);

  Serial.printf("Using encryption key: ");
  for (int i=0; i<16; i++) {
    Serial.printf(" %2.2x",key[i]);
  }
  Serial.println();
  Serial.println();
  Serial.println();
  
  strcpy(savedDeviceName,"(unknown device name)");

  // Code from Examples->BLE->Beacon_Scanner. This sets up a timed scan watching for BLE beacons.
  // During a scan the receipt of a beacon will trigger a call to MyAdvertisedDeviceCallbacks().
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan(); //create new scan
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true); //active scan uses more power, but get results faster
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99); // less or equal setInterval value

  Serial.println("setup() complete.");

  tft.init();
  tft.fillScreen(TFT_BLACK);
  sprite.createSprite(170,320);
  analogWrite(38,100);
}




void loop() {
  //Serial.println("Scanning...");

  BLEScanResults foundDevices = pBLEScan->start(scanTime, false);
  
  pBLEScan->clearResults(); // delete results fromBLEScan buffer to release memory
  
}




