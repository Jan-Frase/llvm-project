#include <stdlib.h>

#pragma mem_freeze i_send_memory(1, 0)
#pragma mem_unfreeze i_wait_for_send(0)

void i_send_memory(int* buf, int* has_finished) {
  int x = 3;
  buf[31] = 666;
}

void i_wait_for_send(int* has_finished) {
  int y = 4;
}

int main(int argc, char *argv[]) {
  int has_finished = 0;
  int* buf = malloc(128);
  i_send_memory(buf, &has_finished);
  i_send_memory(buf, &has_finished);

  // do some work in the mean time 
  
  i_wait_for_send(&has_finished);

  free(buf);

  return 0;
}
