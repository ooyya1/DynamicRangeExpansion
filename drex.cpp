#include "drex.hpp"


DREX::DREX(int bitnum, double ratio, int cmax)
{  
    srand((int)time(0));
    bmp = new int [bitnum]();
    this->bitnum = bitnum;
    char name[] = "DREX";
    unsigned long seed = AwareHash((unsigned char*)name, strlen(name), 13091204281, 228204732751, 6620830889);
    hash = GenHashSeed(seed++);
    hash1 = GenHashSeed(seed++);
    maxnum = bitnum * ratio;
    this->cmax = cmax;
}

DREX::~DREX()
{
    delete bmp;
}

void DREX::Update(tuple_t t) {
    int level = 0;
    uint32_t p = MurmurHash2((unsigned char *)(&t), 13, hash);
    while ((p&0x00000001) == 1) {
        p >>= 1;
        level++;
    }
    if(level >= round) {
        uint32_t hv = MurmurHash2((unsigned char *)(&t), 13, hash1);
        int bucket = ((uint64_t)hv * (uint64_t)bitnum) >> 32;
        if(bmp[bucket] == 0) onenum ++;
        if(level - round >= cmax - 1) {
            bmp[bucket] = std::max(cmax, bmp[bucket]);
        } else{
            bmp[bucket] = std::max(level - round + 1, bmp[bucket]);
        }
        if(onenum >= maxnum) {
            nextRound();
        }
    }
}

void DREX::nextRound() {
    for(int i = 0; i < bitnum; i++) {
        if(bmp[i] == cmax) {
            if(rand()%2 == 0) bmp[i] --; 
        }
        else if(bmp[i]) {
            bmp[i] -= 1;
            if(!bmp[i]) onenum --;
        }

    }
    round ++;
}

uint64_t DREX::Query() {
    double est = (1 << round) * 1.0 * bitnum * log(1.0 * bitnum / (bitnum - onenum));
    return est;
}

void DREX::merge_union(DREX * tmp) {
    int r = this->round, tr = tmp->round;
    if(r >= tr) {
        for(int i = 0; i < bitnum; i++) {
            if(r + this->bmp[i] < tr + tmp->bmp[i]) {
                if(this->bmp[i] == 0) {
                    onenum ++;
                }
                this->bmp[i] = tr + tmp->bmp[i] - r;
            }
        }       
    } else {
        onenum = 0;
        for(int i = 0; i < bitnum; i++) {
            int toset;
            if(r + this->bmp[i] > tr + tmp->bmp[i]) {
                toset = r + this->bmp[i] - tr;
            } else {
                toset = tmp->bmp[i];
            }
            this->bmp[i] = toset;
            if(toset) onenum ++;
        }
        this->round = tr;
    }
    if(onenum >= maxnum) {
        nextRound();
    }
}

void DREX::merge_intersec(DREX * tmp) {
    int r = this->round, tr = tmp->round;
    if(r < tr) {
        for(int i = 0; i < bitnum; i++) {
            if(r + this->bmp[i] > tr + tmp->bmp[i]) {
                this->bmp[i] = tr + tmp->bmp[i] - r;
                if(this->bmp[i] < 0) this->bmp[i] = 0;
                if(this->bmp[i] == 0) {
                    onenum --;
                }
            }
        }       
    } else {
        onenum = 0;
        for(int i = 0; i < bitnum; i++) {
            int toset;
            if(r + this->bmp[i] < tr + tmp->bmp[i]) {
                toset = r + this->bmp[i] - tr;
            } else {
                toset = tmp->bmp[i];
            }
            this->bmp[i] = toset;
            if(toset) onenum ++;
        }
        this->round = tr;
    }
    if(onenum >= maxnum) {
        nextRound();
    }
}
