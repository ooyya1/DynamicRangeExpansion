#ifndef DREX_H
#define DREX_H
#include "datatypes.hpp"
#include <ctime>
#include <map>
#include <iostream>
#include <algorithm>
#include <cmath>
extern "C"
{
    #include "hash.h"
}
class DREX
{
private:
    int round = 0;
    // unsigned char * bmp;
    int * bmp;
    unsigned hash;
    unsigned hash1;
    int bitnum;
    int onenum = 0;
    int maxnum;
    int cmax;
public:
    DREX(int bitnum, double ratio, int cmax);
    ~DREX();
    void Update(tuple_t t);
    uint64_t Query();
    void nextRound();
    void merge_union(DREX * tmp);
    void merge_intersec(DREX * tmp);
};



#endif