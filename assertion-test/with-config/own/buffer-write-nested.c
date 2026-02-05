#include <stdlib.h>

__attribute__((mem_unfreeze(0)))
void i_wait(int* has_finished) {
  *has_finished = 1;
}

__attribute__((mem_freeze(0, 1)))
void i_run_a_long_calculation(int* buf_1, int* has_finished_2) {
  int x = 3;
  buf_1[32] = 666;
}

__attribute__((mem_freeze(0, 1)))
void i_send_memory(int* buf_1, int* has_finished_1, int* has_finished_2) {
  int x = 3;
  i_run_a_long_calculation(buf_1, has_finished_2);

  buf_1[31] = 666;
  i_wait(has_finished_2);
}

int main(int argc, char *argv[]) {
  int has_finished_1 = 0;
  int has_finished_2 = 0;
  int* buf_1 = malloc(128);
  i_send_memory(buf_1, &has_finished_1, &has_finished_2);

  // do some work in the mean time 
  
  i_wait(&has_finished_1);

  free(buf_1);

  return 0;
}
