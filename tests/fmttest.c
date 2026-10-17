#include <stdio.h>
int main(void) {
  size_t s = 5;
  int r = 5, w = 0;
  size_t total = 1960;
  long ev = 3905;
  printf("A %zu B %d C %d D %zu E %ld\n", s, r, w, total, ev);
  printf("llu %llu\n", (unsigned long long)total);
  return 0;
}
