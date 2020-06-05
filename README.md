# OSS Android apps and insecure dependencies

An independent research, by a Software Engineer.

## What is this?

## Methodology

- santa-tracker
- plaid
- uamp
- iosched
- sunflower
- k9mail
- protonmail
- duckduckgo
- signal
- corona-warn-app
- immuni-app
- freeotp
- haven
- mozilla-lockwise
- wireguard
- termux
- connectbot
- kickstarter
- wordpress
- wikipedia

## Generating the results (DIY)

Ensure you have Python 3.8+ in your machine and install [Gradle Bodyguard](https://github.com/dotanuki-labs/gradle-bodyguard)

```bash
→ pip install gradle-bodyguard
```

Clone this project and run the collector script

```
→ git clone git@github.com:dotanuki-labs/android-oss-cves-research.git
→ cd android-oss-cves-research
→ ./collector.sh
```

Aggregate the results into a JSON file:

```
→ python aggregator.py
```



## Filtering meaningful CVEs

From the `aggregated-results.json` file, we have a complete list of CVEs found. Let's go briefly through the most important ones :

#### [CVE-2015-5237](https://nvd.nist.gov/vuln/detail/CVE-2015-5237) (Protobuf)


> protobuf allows remote authenticated attackers to cause a heap-based buffer overflow.

Well ... This one looks quite bad.

 
#### [CVE-2015-5262](https://nvd.nist.gov/vuln/detail/CVE-2015-5262) (Apache HttpClient)


> http/conn/ssl/SSLConnectionSocketFactory.java in Apache HttpComponents HttpClient before 4.3.6 ignores the http.socket.timeout configuration setting during an SSL handshake, which allows remote attackers to cause a denial of service (HTTPS call hang) via unspecified vectors.

Well ... This one looks quite bad.

#### Why was the CVEs not considered critical at all?

Discarded            | Justification 
----------------     | -----------------------------------  
**CVE-2015-5237**    |
**CVE-2015-5262**    |
**CVE-2016-1000340** |
**CVE-2016-2402**    |
**CVE-2016-7051**    |
**CVE-2017-1000487** |
**CVE-2017-13098**   |
**CVE-2017-7957**    |
**CVE-2018-1000613** |
**CVE-2018-10237**   |
**CVE-2018-1324**    |
**CVE-2018-20200**   |
**CVE-2018-7489**    |
**CVE-2019-17531**   |  


## Asserting supply-chain attacks

Also from `aggregated-results.json` we can compute the number of CVEs found in directly declared and/or transitive dependencies used per project, filtering the meanigful ones based in the aforementioned analysis of relevance .


OSS App             | Found | Relevant CVEs
------------------- | ----  | --------------------------------------
santa-tracker       | 8     | 
haven               | 8     | 
mozilla-lockwise    | 8     | 
signal              | 7     | 
uamp                | 6     | 
iosched             | 5     | 
corona-warn-app     | 5     | 
plaid               | 4     | 
immuni-app          | 4     | 
sunflower           | 3     | 
duckduckgo          | 3     | 
freeotp             | 3     | 
k9mail              | 0     | None
protonmail          | 0     | None
wire                | 0     | None
wireguard           | 3     | None
termux              | 0     | None
connectbot          | 0     | None
kickstarter         | 0     | None
wordpress           | 0     | None
wikipedia           | 0     | None



## Conclusions


## Credits


## Author

Coded by Ubiratan Soares (follow me on [Twitter](https://twitter.com/ubiratanfsoares))

## License

```
The MIT License (MIT)

Copyright (c) 2020 Dotanuki Labs

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
