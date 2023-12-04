#include "drex.hpp"
#include "adaptor.hpp"
#include <utility>
#include "datatypes.hpp"
#include "util.h"
#include <fstream>
#include <iomanip>
#include <set>
int main(int argc, char* argv[]) {
    // pcap traces
    const char* filenames = "iptraces.txt";
    // buffer size
    unsigned long long buf_size = 500000000;
    int memory = atoi(argv[1]);
    double ratio = 0.9;
    int q = 2;
    std::ifstream tracefiles(filenames);
    if (!tracefiles.is_open()) {
        std::cout << "Error opening file" << std::endl;
        return -1;
    }
    for (std::string file; getline(tracefiles, file);) {
        Adaptor* adaptor =  new Adaptor(file, buf_size);
        std::cout << "[Dataset]: " << file << std::endl;
        std::cout << "[Message] Finish read data." << std::endl;

        // Get the ground truth
        std::set<tuple_t> ground;
        tuple_t t;
        adaptor->Reset();
        while(adaptor->GetNext(&t) == 1) {
            ground.insert(t);
        }
        std::cout << "[Message] Finish Insert hash table" << std::endl;

        // Create DREX instance
        DREX * drex = new DREX(memory, ratio, q);

        // Update DREX
        double t1=0, t2=0;
        double datasize = adaptor->GetDataSize();
        t1 = now_us();
        adaptor->Reset();
        while(adaptor->GetNext(&t) == 1) {
            drex->Update(t);
        }
        t2 = now_us();
        double throughput = datasize/(double)(t2-t1)*1000000;

        // Query the result
        t1=0, t2=0;
        myvector results;
        results.clear();
        t1 = now_us();
        uint64_t estimate = drex->Query();
        t2 = now_us();
        double dtime = (double)(t2-t1)/1000000;

        // Calculate accuracy
        double re = abs((int)estimate - (int)ground.size())*1.0/ground.size();
        
        //Output to standard output
        std::cout << std::setfill(' ');
        std::cout << std::setw(20) << std::left << "Memory(bit)" << std::setw(20) << std::left << 
         "Relative Error" << std::setw(20) << std::left << "Update Throughput" << std::setw(20)
            << std::left << "Query time" << std::endl;
        std::cout << std::setw(20) << std::left << memory << std::setw(20) << std::left << re 
        << std::setw(20) << std::left << throughput << std::setw(20) << std::left << dtime << std::endl;
    }
}

