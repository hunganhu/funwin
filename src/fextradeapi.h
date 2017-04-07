#include <stdio.h>

class CompressUtil {
  public:
  static int Zerocompress(unsigned char const*, unsigned long, unsigned char*, unsigned long &);
  static int Zerodecompress(unsigned char const*, unsigned long, unsigned char*, unsigned long &);
  CompressUtil();
  ~CompressUtil();
};

