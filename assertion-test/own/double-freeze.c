#include <stdlib.h>

__attribute__((mem_freeze(0, 1)))
void i_send_memory(int* buf, int* has_finished) {
  int x = 3;
  buf[31] = 666;
}

__attribute__((mem_unfreeze(0)))
void i_wait(int* has_finished) {
  int y = 4;
}

int main(int argc, char *argv[]) {
  int has_finished = 0;
  int* buf = malloc(128);
  i_send_memory(buf, &has_finished);
  i_send_memory(buf, &has_finished);

  // do some work in the mean time 
  
  i_wait(&has_finished);

  free(buf);

  return 0;
}
