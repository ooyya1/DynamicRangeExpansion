# Dynamic Range Expansion (DREX)

#### Requirements

- Ensure __g++__ and __make__ are installed.  Our experimental platform is
  equipped with Ubuntu 18.04, g++ 7.5.0 and make 4.1.
- Ensure the necessary library libpcap is installed.
  - It can be installed in most Linux distributions (e.g., apt-get install
    libpcap-dev in Ubuntu).
- Prepare the pcap files.
  - We provide two small pcap files
    [here](https://drive.google.com/file/d/1WLEjB-w4ZlNshl1vUMb98rrowFuMBWuJ/view?usp=sharing).
    You can download and put them in the "traces" folder for testing.  
  - Specify the path of each pcap file in "iptraces.txt". 

#### Compile

- Compile examples with make

```
    $ make main
```

#### Run

- Run the examples, and the program will output some statistics about the accuracy. 

```
$ ./main $memory (in bits)$
```

- Note that you can change the configuration of DREX, e.g. the value of q in the example source code for testing.

