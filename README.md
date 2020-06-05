# OSS Android apps and insecure dependencies


An experiment intended to demonstrate the value you can get from [gradle-bodyguard](https://github.com/dotanuki-labs/gradle-bodyguard). Also, a small and independent security study about Android open-source apps, by a curious Software Engineer.


## Goals

In order to share with you why I wrote **gradle-bodyguard**, I chose 13 open-source Android apps - from several players in the industry - and our goal here is figure out if they are eventually consuming **vulnerable dependencies** as part of the Gradle build; or worse than that, if they are **shipping code assured to be vulnerable** to users.

I picked up the following projects as targets of our experiment. All of them build with Gradle without any custom setup :

- [santa-tracker](https://github.com/google/santa-tracker-android), a Christmas game for kids (**Google**)
- [plaid](https://github.com/android/plaid), a showcase for Material Design (**Google**)
- [uamp](https://github.com/android/uamp), a demo for simple universal audio player (**Google**) 
- [iosched](https://github.com/google/iosched), the official app for Google I/O conference (**Google**)
- [sunflower](https://github.com/android/sunflower), a showcase for Android Jetpack libraries (**Google**)
- [duckduckgo](https://github.com/duckduckgo/Android), privacy-first search engine (**DuckDuckGo**)
- [signal](https://github.com/signalapp/Signal-Android), a private messenger (**Signal Foundation**)
- [corona-warn-app](https://github.com/corona-warn-app/cwa-app-android), official contact tracer app in Germany (**German government**)
- [immuni-app](https://github.com/immuni-app/immuni-app-android), official contact tracer app in Italy (**Italian government**)
- [freeotp](https://github.com/freeotp/freeotp-android), an open-source 2FA app (**community driven**)
- [haven](https://github.com/guardianproject/haven), an app that helps to protect exposed people, like journalists (**The Guardian Project**)
- [mozilla-lockwise](https://github.com/mozilla-lockwise/lockwise-android), password manager integrated into Firefox ecosystem (**Mozilla**)
- [wireguard](https://github.com/WireGuard/wireguard-android), official client for a new VPN cabalities provided by Linux kernel (**Jason Donenfeld**)

For us, **vulnerability** will mean a security issue or bug tracked as a [Commom Vulnerability and Exposure](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures), as know as CVE.

There are several databases that index CVEs out there. In this demo, our reference will be the one offered by **National Institute of Standards and Technologies** of United States, also know as [NIST](https://nvd.nist.gov/). 

Using `gradle-bodyguard`, we will demonstrate that several dependencies that actually are used by the aforementioned projects actually have security issues tracked by CVEs. Then, we will evaluate CVEs that actually are meanigful to our context, and figure out which of them actually might be harming users in production.

## Getting Started

In order to start, we need to install [Gradle Bodyguard](https://github.com/dotanuki-labs/gradle-bodyguard). Requires Python 3.8.x and Pip

```bash
→ pip install gradle-bodyguard
```

After that, we can run the `collector.sh` script. This script will fetch all the 13 projects and execute `gradle-bodyguard` against them. Note that it might take a while to finish.

```
→ cd android-oss-cves-research
→ ./collector.sh
```

When it is done, we can aggregate the results into a JSON report with `aggregator.py`

```
→ python aggregator.py
```

which writes the `aggregated-results.json` file at our **android-oss-cves-research** folder.


After that we are ready to interpret the results. The criteria here is quite simple : we want to figure out if some vulnerable dependency harms user in the end, ie it :

- opens security breaches at network level of the Android app
- fails at cryptography operations
- messes with user's privacy
- allows remote code execution
- allows *runtime* corruptions
- etc


## Filtering meaningful CVEs

From the `aggregated-results.json` file we got a complete list of CVEs found accross all the 13 OSS projects. All the heavy work was actually done by `gradle-bodyguard`, since it exercised the Gradle build of all projects we want to examine and evaluated which dependencies - direct or transitive ones - eventually contain issues tracked by CVEs. 

The first thing we need to realize is that not all CVEs we found actually represent the vulnerabilities that we are insterested in. We need to go through them, learn about what they mean and figure out if this is actually something applicable to a Mobile application. 

Supported by the [NIST](https://nvd.nist.gov/) website, we can realize that the following CVEs can be ignored, since the security flaws are out of the scope of Mobile apps 

Discarded            | Rationale 
----------------     | -----------------------------------  
**CVE-2015-5262**    | DDoS attack == servers
**CVE-2015-5237**    | Serialization of gigantic protobuf payloads (4Gb) is unlikely on Mobile
**CVE-2016-1000340** | A bug too specific and with *"rare"* chance of exploit (CVE says that)
**CVE-2016-7051**    | *"Server-side request forgery"* needs servers!
**CVE-2017-1000487** | CLI related, probably is used by some Gradle plugin and so it won't ship
**CVE-2017-7957**    | xStream crash when parsing bad XML. Nothing more.
**CVE-2018-10237**   | GWT related and therefore only meanigful for server apps
**CVE-2018-1324**    | DDoS attack == servers
**CVE-2018-20200**   | Disputed by OkHttp authors (and I actually agree with them)
**CVE-2019-17531**   | Needs **apache-log4j-extra** in the classpath to work. Unlike on Android apps 

With this decision, now we reduced the scope of potential vulnerabilities to investigate to **3 dependencies**, tracked by 4 CVEs. We can aggregate the remaining ones in the following table 

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


The next step is dig into them, one by one, inspecting the Gradle projects. But first, a quick overview about what such vulnerabilities represent.


#### [CVE-2016-2402](https://nvd.nist.gov/vuln/detail/CVE-2016-2402) (OkHttp)

> OkHttp before 2.7.4 and 3.x before 3.1.2 allows man-in-the-middle attackers to bypass certificate pinning by sending a certificate chain with a certificate from a non-pinned trusted CA and the pinned certificate.

Well ... This one looks quite bad. You can read more at Jesse Wilson's related [blog post](https://publicobject.com/2016/02/11/okhttp-certificate-pinning-vulnerability/). If the app ships with this code, then user's data can be easily compromised with trivial network attacks.

#### [CVE-2017-13098](https://nvd.nist.gov/vuln/detail/CVE-2017-13098) (BouncyCastle)

> BouncyCastle TLS prior to version 1.0.3, when configured to use the JCE (Java Cryptography Extension) for cryptographic functions, provides a weak Bleichenbacher oracle when any TLS cipher suite using RSA key exchange is negotiated. An attacker can recover the private key from a vulnerable application."

The last statement *"recover the private key"* is enough to realise that such CVE can actually impact badly an application and its users. We don't have an idea on how client code will leverage BouncyCastle to generate keys, but if they are recoverable, most likely we are just doomed.

#### [CVE-2018-1000613](https://nvd.nist.gov/vuln/detail/CVE-2018-1000613) (BouncyCastle)

> A handcrafted private key can include references to unexpected classes which will be picked up from the class path for the executing application. This vulnerability appears to have been fixed in 1.60 and later.

Another issue around private keys generated with BouncyCastle, fair enough to consider this as critical as well.

#### [CVE-2018-7489](https://nvd.nist.gov/vuln/detail/CVE-2018-7489) (FasterXML Jackson)

> FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper.

Remote code execution is definetely something we can't ignore.


## Asserting vulnerabilities

Now that we know which dependencies we are looking for, we can use Gradle tasks in order to learn about the project dependencies structure :

```
./gradlew <module>:dependencies
```

So, let's check the versions for each vulnerable dependency and figure out if they are transitive or not.

### 🔥 Hunting OkHttp < 3.1.2 (CVE-2016-2402)

Our target here is IOSched, and it is easy to see that the vulnerable version OkHttp was [explicitely declared](https://github.com/google/iosched/blob/4054aa3f8934b8b1208d5823fdbf531a8eb367af/build.gradle#L77) by app developers. Note that this CVE dates from 2016, while the latest release of IOSched dates from 2019 😞. 

Unfortunately here, users might be exposed.


### 🔥 Hunting BouncyCastle < 1.59 (CVE-2017-13098)

Seems that this version of BouncyCastle is brought to the build of all project above by the Android Gradle Plugin as parting of the tooling. Here an evidence of it being brought transitively by `com.android.tools:sdk-common`, that I found when inspecting `plaid` project

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
     |    +--- org.bouncycastle:bcprov-jdk15on:1.56 🆘🆘🆘
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
     |    +--- org.bouncycastle:bcprov-jdk15on:1.56 🆘🆘🆘
     |    +--- org.ow2.asm:asm:7.0
     |    +--- org.ow2.asm:asm-tree:7.0
     |    |    \--- org.ow2.asm:asm:7.0
     |    | 
     .    .
     .    .   
```

It is quite safe to say that we can ignore this CVE, since code used by AGP does not ship to users.

### 🔥 Hunting BouncyCastle < 1.60 (CVE-2018-1000613)

In this case,`haven` project is our target and can manage to learn that BouncyCastle is present in `releaseCompileClasspath` configuration - which is actually bad since it will ship to final users.


Digging more into the problem, we can see that the issue happens because `com.github.turasa:signal-service-java` dependency brings a vulnerable version of BouncyCastle transitively :

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
|    +--- org.bouncycastle:bcprov-jdk15on:1.59 🆘🆘🆘
.
.
```

**This is exactly what we were aiming to discover : an example of a security issue introduced in the dependencies chain by a thirdy party !!!**

So, unless Proguard is removing the vulnerable code somehow, users might be exposed.

### 🔥 Hunting Jackson Databind < 2.7.9.3  (CVE-2018-7489)

Last, but not least, the target here is `haven` project and again `com.github.turasa:signal-service-java` brings a vulnerable dependency to the chain, this time a version of Jackson DataBind grabbed transitively by `2.7.5_unofficial_1` version

```
.    .    
.    .
|    +--- com.github.turasa:signal-service-java:2.7.5_unofficial_1
|    |    +--- com.google.protobuf:protobuf-java:2.5.0
.    .    .
.    .    .
|    |    +--- com.fasterxml.jackson.core:jackson-databind:2.5.0 🆘🆘🆘
|    |    |    +--- com.fasterxml.jackson.core:jackson-annotations:2.5.0
|    |    |    \--- com.fasterxml.jackson.core:jackson-core:2.5.0
.    .    .
.    .    .
```

So, here we have another example of compromised dependency chain. Unless Proguard is removing the vulnerable code somehow, users might be exposed again via other attack vector.

## Conclusions

When using `gradle-bodyguard` for the first time, one might get the impression that his/hers Gradle project is actually totally broken from the security perspective; this study demonstrates that we can go a bit easier on that, since a deep analysis over the overall vulnerabilities is needed and since the right criteria is needed in order to realize if we were pawned (or not).

[Supply chain attacks](https://arstechnica.com/information-technology/2020/04/725-bitcoin-stealing-apps-snuck-into-ruby-repository/) are a thing, and as exposed in the motivations of **Gradle Bodyguard**, we should have better - and free ways - to learn about then. 

As Software Engineers, we usually run checkers for code style in our Continous Integration workflows and pipelines; but let's speak the truth here : *bad* code style and *good* style mean the same thing to final users, unlike **good security** and **bad security**. We will never see a business bankrupt due to warnings from Linters, but we might see that due to serious security breaches.

We can do the best effort regarding the libraries we own inside our projects; but the work to validate the entire dependencies chain from a security standpoint has to be automated somehow. This is reason why I wrote **Gradle Bodyguard** for my Android and JVM projects. 

For sure it is not perfect, but at least we have something in place.🙂


I'm not a Security Engineer, neither a Security Researcher. Maybe I made mistakes on my security analysis; if so, please let me know about and learn from them. Feel free to reach me out.


## Show your love

- Did you find an error or bug? Fill an issue, please! 🐛

- Did you enjoy this article? Honor me with your star ⭐️


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
