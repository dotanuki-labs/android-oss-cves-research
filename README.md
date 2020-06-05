# OSS Android apps and insecure dependencies

An independent study by a curious Software Engineer.

## What is this?

## Methodology

- [santa-tracker](https://github.com/google/santa-tracker-android), a Christmas game for kids (**Google**)
- [plaid](https://github.com/android/plaid), a showcase for Material Design (**Google**)
- [uamp](https://github.com/android/uamp), a demo for simple universal audio player (**Google**) 
- [iosched](https://github.com/google/iosched), the official app for Google I/O conference (**Google**)
- [sunflower](https://github.com/android/sunflower), a showcase for Android Jetpack libraries (**Google**)
- [duckduckgo](https://github.com/duckduckgo/Android), privacy-first search engine for the Web (**DuckDuckGo**)
- [signal](https://github.com/signalapp/Signal-Android), a private messenger (**Signal Foundation**)
- [corona-warn-app](https://github.com/corona-warn-app/cwa-app-android), official contact tracer app in Germany (**German government**)
- [immuni-app](https://github.com/immuni-app/immuni-app-android), official contact tracer app in Italy (**Italian government**)
- [freeotp](https://github.com/freeotp/freeotp-android), an open-source 2FA app (**community driven**)
- [haven](https://github.com/guardianproject/haven), an app that helps to protect exposed people, like journalists (**The Guardian Project**)
- [mozilla-lockwise](https://github.com/mozilla-lockwise/lockwise-android), password manager integrated into Firefox ecosystem (**Mozilla**)
- [wireguard](https://github.com/WireGuard/wireguard-android), official client for a new VPN cabalities provided by Linux kernel (**Jason Donenfeld**)


## Generating the results (DIY)

Ensure you have Python 3.8+ in your machine and install [Gradle Bodyguard](https://github.com/dotanuki-labs/gradle-bodyguard)

```bash
→ pip install gradle-bodyguard
```

Clone this project and run the collector script

```
→ git clone git@github.com:dotanuki-labs/android-oss-cves-research.git
→ cd android-oss-cves-research
```

Run the collector script. It will fetch all the 21 projects and execute `gradle-bodyguard` against them. Note : it might take a while ...😴

```
→ ./collector.sh
``` 

Aggregate the results into a JSON file:

```
→ python aggregator.py
```



## Filtering meaningful CVEs

From the `aggregated-results.json` file, we have a complete list of CVEs found. Let's go briefly through the meangiful ones :


#### [CVE-2016-2402](https://nvd.nist.gov/vuln/detail/CVE-2016-2402) (OkHttp)

> OkHttp before 2.7.4 and 3.x before 3.1.2 allows man-in-the-middle attackers to bypass certificate pinning by sending a certificate chain with a certificate from a non-pinned trusted CA and the pinned certificate.

Well ... This one looks quite bad. You can read more on Jesse Wilson's related [blog post](https://publicobject.com/2016/02/11/okhttp-certificate-pinning-vulnerability/). If the app ships with this code, then user's data might be easily compromised with trivial network attacks.

#### [CVE-2017-13098](https://nvd.nist.gov/vuln/detail/CVE-2017-13098) (BouncyCastle)

> BouncyCastle TLS prior to version 1.0.3, when configured to use the JCE (Java Cryptography Extension) for cryptographic functions, provides a weak Bleichenbacher oracle when any TLS cipher suite using RSA key exchange is negotiated. An attacker can recover the private key from a vulnerable application."

Well ... This one looks quite bad. You can read more on Jesse Wilson's related [blog post](https://publicobject.com/2016/02/11/okhttp-certificate-pinning-vulnerability/)

#### [CVE-2018-1000613](https://nvd.nist.gov/vuln/detail/CVE-2018-1000613) (BouncyCastle)

> A handcrafted private key can include references to unexpected classes which will be picked up from the class path for the executing application. This vulnerability appears to have been fixed in 1.60 and later.

Well ... 


#### [CVE-2018-7489](https://nvd.nist.gov/vuln/detail/CVE-2018-7489) (FasterXML Jackson)

> FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper.

Well ... 

#### Why was the other CVEs not considered critical at all in our context?

Discarded            | Rational 
----------------     | -----------------------------------  
**CVE-2015-5262**    | DDoS attack == servers
**CVE-2015-5237**    | Serialization of gigantic protobuf payloads (4Gb) is unlikely on Mobile
**CVE-2016-1000340** | A bug too specific and with *"rare"* chance of exploit (CVE says that)
**CVE-2016-7051**    | *"Server-side request forgery"* needs servers!
**CVE-2017-1000487** | CLI related, probably is used by some Gradle plugin and so it won't ship
**CVE-2017-7957**    | xStream crash when parsing bad XML. Nothing more.
**CVE-2018-10237**   | GWT related and therefore only meanigful for server apps
**CVE-2018-1324**    | DDoS attack == servers
**CVE-2018-20200**   | Disputed by OkHttp authors (I actually agree with them here)
**CVE-2019-17531**   | Needs **apache-log4j-extra** in the classpath to work. Unlike on Android apps 


## Asserting supply-chain attacks

Also from `aggregated-results.json` we can compute the number of CVEs found either with declared dependencies or transitive ones used per project, filtering the meanigful ones based in the aforementioned analysis of relevance .


OSS App              | Found | Relevant CVEs
-------------------  | ----- | -----------------------------------------------
**santa-tracker**    | 8     | **CVE-2017-13098**
**haven**            | 8     | **CVE-2017-13098**, **CVE-2018-1000613**, **CVE-2018-7489**
**mozilla-lockwise** | 8     | **CVE-2017-13098**,
**signal**           | 7     | **CVE-2017-13098**
**uamp**             | 6     | **CVE-2017-13098**
**iosched**          | 5     | **CVE-2017-13098**, **CVE-2016-2402** 
**corona-warn-app**  | 5     | **CVE-2017-13098**
**plaid**            | 4     | **CVE-2017-13098**
**immuni-app**       | 4     | **CVE-2017-13098**
**sunflower**        | 3     | **CVE-2017-13098**
**duckduckgo**       | 3     | **CVE-2017-13098**
**freeotp**          | 3     | **CVE-2017-13098**
**wireguard**        | 3     | **CVE-2017-13098**



### 🔥 Hunting OkHttp < 3.1.2 (CVE-2016-2402)

Only applicable for IOSched, [it is explicitely declared](https://github.com/google/iosched/blob/4054aa3f8934b8b1208d5823fdbf531a8eb367af/build.gradle#L77) by app developers. Note that this CVE is from 2016, while the latest release of IOSched dates from 2019 (circa one year ago) 😞. 

Unfortunately here, users might be exposed here.


### 🔥 Hunting BouncyCastle < 1.59 (CVE-2017-13098)

Seems that this version of BouncyCastle is brought to the build by the Android Gradle Plugin as parting of the tooling. Here an evidence of it being brought transitively by `com.android.tools:sdk-common`

```

lintClassPath - The lint embedded classpath
\--- com.android.tools.lint:lint-gradle:26.6.1
     +--- com.android.tools:sdk-common:26.6.1
     |    +--- com.android.tools:sdklib:26.6.1
     |    |    +--- com.android.tools.layoutlib:layoutlib-api:26.6.1
     |    |    |    +--- com.android.tools:common:26.6.1
     |    |    |    |    +--- com.android.tools:annotations:26.6.1
     .    .    .    .
     .    .    .    .
     .    .    .     
     |    |    \--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.3.61 (*)
     |    +--- org.bouncycastle:bcprov-jdk15on:1.56 👈
     |    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.3.61 (*)
     |    +--- org.jetbrains.kotlin:kotlin-reflect:1.3.61
     .    .
     .    .
```

Also a dependency of `com.android.tools.build:apkzlib`

```
     .    .
     .    .  
     +--- com.android.tools.build:builder:3.6.1
     |    +--- com.android.tools.build:builder-model:3.6.1 (*)
     |    +--- com.android.tools.build:apksig:3.6.1
     |    +--- com.android.tools.build:apkzlib:3.6.1
     |    |    +--- com.google.code.findbugs:jsr305:1.3.9 -> 3.0.2
     |    |    +--- com.google.guava:guava:23.0 -> 27.1-jre (*)
     |    |    +--- org.bouncycastle:bcpkix-jdk15on:1.56 (*)
     |    |    +--- org.bouncycastle:bcprov-jdk15on:1.56
     |    |    \--- com.android.tools.build:apksig:3.6.1
     |    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.3.61 (*)
     |    +--- com.squareup:javawriter:2.5.0
     |    +--- org.bouncycastle:bcpkix-jdk15on:1.56 (*)
     |    +--- org.bouncycastle:bcprov-jdk15on:1.56 👈
     |    +--- org.ow2.asm:asm:7.0
     |    +--- org.ow2.asm:asm-tree:7.0
     |    |    \--- org.ow2.asm:asm:7.0
     |    | 
     .    .
     .    .   
```

To be honest, this was quite expected, since the CVE apperead in all reports generated by **gradle-bodyguard**. It is quite safe to say that we can ignore the warning, since code used by AGP does not ship to users.

### 🔥 Hunting BouncyCastle < 1.60 (CVE-2018-1000613)

In this, I've manage to search **haven** project's history to figure out how this dependency is consumed. I learned the it is also present in `releaseCompileClasspath` configure - which is actually bad since it ships to users.


The issue happens because `com.github.turasa:signal-service-java` brings a vulnerable version of BouncyCastle transitively at version `2.7.5_unofficial_1`.

```
.        
.    
+--- com.github.guardianproject:signal-cli-android:v0.6.0-android-beta-1
|    +--- com.github.turasa:signal-service-java:2.7.5_unofficial_1
|    |    |  
.    .    .
.    .    .
|    |    |  
|    |    \--- com.madgag.spongycastle:prov:1.51.0.0
|    |         \--- com.madgag.spongycastle:core:1.51.0.0
|    +--- org.bouncycastle:bcprov-jdk15on:1.59 👈
.
.
```

So, unless Proguard is removing the vulnerable code somehow, users might be exposed.

### 🔥 Hunting Jackson Databind < 2.7.9.3  (CVE-2018-7489)

The issue also happens only at **haven** and again because `com.github.turasa:signal-service-java` brings a vulnerable version of Jackson DataBind transitively at version `2.7.5_unofficial_1`.

```
.    .    
.    .
|    +--- com.github.turasa:signal-service-java:2.7.5_unofficial_1
|    |    +--- com.google.protobuf:protobuf-java:2.5.0
.    .    .
.    .    .
|    |    +--- com.fasterxml.jackson.core:jackson-databind:2.5.0 👈
|    |    |    +--- com.fasterxml.jackson.core:jackson-annotations:2.5.0
|    |    |    \--- com.fasterxml.jackson.core:jackson-core:2.5.0
.    .    .
.    .    .
```

So, unless Proguard is removing the vulnerable code somehow, users might be exposed again via other attack vector.

## Conclusions


## Show your love

- Did you find an error or bug? Fill an issue, please! 🐛

- Did you enjoy this article? Honor me with your star ⭐️

Thanks for reading!

## Author

Coded and written by Ubiratan Soares (follow me on [Twitter](https://twitter.com/ubiratanfsoares))

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
