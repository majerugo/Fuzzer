#include <stdio.h>
#include <unistd.h> 

void print_secret(){
  FILE *secret = fopen("flag.txt", "rt");
  char buffer[32];
  fgets(buffer, sizeof(buffer), secret);
  printf("Secret: %s\n", buffer);
  fclose(secret);
}

int main(void){
  printf("What's your name?\n");
  char buffer[64];
  fgets(buffer, sizeof(buffer), stdin);

  printf("Hello ");
  printf(buffer);
  printf("!\n");

  printf("Try to exploit me!\n");
  return 0;
}

