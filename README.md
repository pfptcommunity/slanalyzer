# Proofpoint Safe/Block List Parser

This tool was created to answer a common question from Proofpoint on Demand administraotrs, "Which global block or safelist entry fired the most or never?" This normally happens after years of these lists being poorly maintained. These global lists can grow massive and ultimately map back to "blocked" or "safe" classifiers associated with the core filtering module. 

### Requirements:

* Linux or Windows + WSL
* pthreads
* libre2
* cmake

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

Every match field has an associated match type, these types can be partial matches, literal matches, and pattern matches. The match types are shown beloe:

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
# Download slparser via Git or Zip
git clone https://github.com/pfptcommunity/slparser

# Change directory into slparser source directory
cd slparser

# Create the Release build profile
cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Release

# Compile the code
cmake --build build/
```
![slparser_binary](https://user-images.githubusercontent.com/83429267/201460299-0bc98973-433f-4c46-91af-639d21dc0d34.png)

### Running the Tool

![slparser_execution](https://user-images.githubusercontent.com/83429267/201460641-66ad9637-01e5-41a6-81f1-92004f5d8e65.png)

### Reviewing the Data
The below output is limited, but ever match conditon is annotated with the number of messages that triggered the blocked or safe list. This is provides a good heatmap to see which safelist entry is excessive or inactive. 
```
"FieldType","MatchType","Pattern","Comment","Matches"
$from,match,@indeed.com,,155
$from,match,@pluralsight.com,,82
$hfrom,match,trystoryboard.com,,2
$from,match,em8330.trystoryboard.com,,2
$ip,equal,192.89.112.126,,2
```
