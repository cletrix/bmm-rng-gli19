# Dependencies

* Ubuntu 18.04 LTS
* CivetWeb Release 1.11 - https://github.com/civetweb/civetweb
* cJSON Release 1.7.5 - https://github.com/DaveGamble/cJSON
* cmake 3.10

# Compilation

    # mkdir build
    # cd build
    # cmake ..
    # make
   
# Usage

    curl "localhost:8085/random?min=0&max=15&rep=0&num=16"
 
 where
  
    min - minimum value, inclusive
    max - maximum value, inclusive
    rep - 0 if numbers don't repeat, 1 if numbers can repeat
    num - number of random numbers to be generated