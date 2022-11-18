# Proofpoint Safe/Block List Analyzer

This tool was created to answer a common question from Proofpoint on Demand administrators, "Which global block or
safelist entry fired the most or never?" This normally happens after years of these lists being poorly maintained. These
global lists can grow massive and ultimately map back to "blocked" or "safe" classifiers associated with the core
filtering module.

### Requirements:

* Linux or Windows + WSL
* pthreads
* libre2-dev
* cmake
* g++ (C++20 is required)

The global safe and block entries have the following match fields.

```
### MatchFields
$hfrom - Header From: email address only.  
$from  - Envelope sender address.  
$helo  - SMTP Helo string presented at time of connction.  
$host  - Hostname associated with the connecting IP.  
$ip    - Connecting IP address.  
$rcpt  - Recipient email address.  
```

Every match field has an associated match type, these types can be partial matches, literal matches, and pattern
matches. The match types are shown below:

```
### MatchTypes
equal            - String matches the entire match field.  
not_equal        - String matches match fields that don't match the entire field.  
match            - String matches the match field partially or completely.  
not_match        - String matches the match fields that don't match partially or completely.  
regex            - Regular expression matches the match fields.  
not_regex        - Regular expression matches the match fields that don't match.  
in_ip_net        - Matches a CIDR block for $ip match field only.  
ip_not_in_net    - Matches ip that are not in the CIDR block, for $ip match field only.
if_in_domain_set - Matches addresses that match entries contained in a domainset. (Not Yet Implemented)
```

### Getting Started

```
# Install necessary packages for the build 
sudo apt install update
sudo apt install cmake
sudo apt install g++
sudo apt install libre2-dev
sudo apt-get install gdb

# Ubuntu 20.04 (requires GCC 10.1 or greater) you will need to install the following
sudo apt install update
sudo apt install -y gcc-10 g++-10 cpp-10
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100 --slave /usr/bin/g++ g++ /usr/bin/g++-10 --slave /usr/bin/gcov gcov /usr/bin/gcov-10

# Download slparser via Git or Zip
git clone https://github.com/pfptcommunity/slanalyzer

# Change directory into slanalyzer source directory
cd slanalyzer

# Create the Release build profile
cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Release

# Compile the code
cmake --build build/
```

![image](https://user-images.githubusercontent.com/83429267/201535586-b20249fd-b122-4446-8a80-500a95f4d942.png)

## Processing Global Block / Safe Lists 

You may need to export multiple 1M record chunks from smart search for a 30 day window. You can filter safelisted messages based on the direction of the flow.
![image](https://user-images.githubusercontent.com/83429267/201682040-29d83ebc-3a3d-4231-8768-a3c8f4f9d879.png)

Export the results to a CSV(s) and pass them to the tool as the last parameter. 
![image](https://user-images.githubusercontent.com/83429267/202054937-9e37a468-a4b6-4929-823a-8b6cbe694b2f.png)

Export the block / safe list you want to compare.
![image](https://user-images.githubusercontent.com/83429267/202720435-3b27e154-6702-4b11-94d7-559a0f2484f4.png)

### Reviewing the Data

The below output is limited, but ever match conditon is annotated with the number of messages that triggered the blocked
or safe list. This is provides a good heatmap to see which safelist entry is excessive or inactive.

```
"FieldType","MatchType","Pattern","Comment","Inbound","Outbound"
"$from","match","@indeed.com","","155","0"
"$from","match","@pluralsight.com","","82","0"
"$hfrom","match","trystoryboard.com","","2","0"
"$from","match","em8330.trystoryboard.com","","2","1"
"$ip","equal","192.89.112.126","","2","0"
```

### Performance
During testing analyzer was able to process 10,000(10K) safelist entries and 10,000,000(10M) row smart search in ~74 seconds that would be 10,000,000,000(10B)  permutations. 
```
Status                    Microseconds              Seconds                   Records                   Filename
SL Load Completed         2726                      0.002726                  10000                     /home/ljerabek/megasafe.csv
SS Processing Completed   73874963                  73.874963                 10000000                  /home/ljerabek/mega_smart_search.csv
SL Save Completed         4314                      0.004314                  10000                     /home/ljerabek/safelist_annotated.csv
SL Load Completed         73913884                  73.913884
```

### Limitations

Safe and Block list entries using domain sets are not currently supported.
RE2 doesn't support all PCRE expressions, future release will implement hybrid method to process expressions.
