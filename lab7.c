// lab7.c
// bchasnov@hmc.edu, david_harris@hmc.edu 15 October 2015
//
// Send data to encryption accelerator over SPI


////////////////////////////////////////////////
// #includes
////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include "easypio.h"

////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////

#define LOAD_PIN 23
#define DONE_PIN 24

// Test Case from Appendix A.1, B
char key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

char plaintext[16] = {0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34};

char ct[16] = {0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
               0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32};

/* 
// Another test case from Appendix C.1

char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

char plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

char ct[16] = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
               0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A};
*/

////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////

void encrypt(char*, char*, char*);
void print16(char*);
void printall(char*, char*, char*);

////////////////////////////////////////////////
// Main
////////////////////////////////////////////////

void main(void) {
  char cyphertext[16];

  pioInit();
  spiInit(244000, 0);

  // Load and done pins
  pinMode(LOAD_PIN, OUTPUT);
  pinMode(DONE_PIN, INPUT);

  // hardware accelerated encryption
  encrypt(key, plaintext, cyphertext);
  printall(key, plaintext, cyphertext);
}

////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////

void printall(char *key, char *plaintext, char *cyphertext) {
  printf("Key:        ");  print16(key);
  printf("Plaintext:  ");  print16(plaintext);  printf("\n");
  printf("Ciphertext: ");  print16(cyphertext);
  printf("Expected:   ");  print16(ct);

  if(strcmp(cyphertext, ct) == 0) {
    printf("\nSuccess!\n");
  } else {
    printf("\nBummer.  Test failed\n");
  }
}

void encrypt(char *key, char *plaintext, char *cyphertext) {
  int i;
  int ready;

  digitalWrite(LOAD_PIN, 1);

  for(i = 0; i < 16; i++) {
    spiSendReceive(plaintext[i]);
  }

  for(i = 0; i < 16; i++) {
    spiSendReceive(key[i]);
  }

  digitalWrite(LOAD_PIN, 0);

  while (!digitalRead(DONE_PIN));

  for(i = 0; i < 16; i++) {
    cyphertext[i] = spiSendReceive(0);
  }
}

void print16(char *text) {
  int i;

  for(i = 0; i < 16; i++) {
    printf("%02x ",text[i]);
  }
  printf("\n");
}