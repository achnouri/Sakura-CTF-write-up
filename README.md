
---

# Write-up : 

- **Author:** achnouri
- **Platform:**  Tryhackme   
- **Challenge Gategory:** Open Source Intellingece    
- **Challenge Level:** Beginner  
- **Challenge Name:** Sakura
- **Challenge Link:** [[challenge link](https://tryhackme.com/room/sakura)]   

<br>

---

As the OSINT team, we found ourselves victims of a cyber attack. however due to the mistake of attacker he left an image that our forensic team discovered, and now we must to determine who the attacker is?

The attacker left a pictiure at [website](https://raw.githubusercontent.com/OsintDojo/public/3f178408909bc1aae7ea2f51126984a8813b0901/sakurapwnedletter.svg) 

My objective is to analyze the website’s source code and the picture to gather information about the attacker

At First, i visited the [website](https://raw.githubusercontent.com/OsintDojo/public/3f178408909bc1aae7ea2f51126984a8813b0901/sakurapwnedletter.svg), i saw a picture with pink and white colors, containing the text "You've Been Pwned" and binaries in the background


![The picture that the attacker left behind](./sakurapwnedletter.svg)

---

<br>

# Extracted and Obtained Data : 


**After analyzing the website source code and using exiftool, i obtained the following information:**

1-

```bash
exiftool sakurapwnedletter.svg

ExifTool Version Number         : 12.52
File Name                       : sakurapwnedletter.svg
File Size                       : 850 kB
MIME Type                       : image/svg+xml
Xmlns                           : http://www.w3.org/2000/svg
SVG Version                     : 1.1
ID                              : svg8
Version                         : 0.92.5 (2060ec1f9f, 2020-04-08)
Docname                         : pwnedletter.svg
Export-filename                 : /home/SakuraSnowAngelAiko/Desktop/pwnedletter.png
Metadata ID                     : metadata5
Work Format                     : image/svg+xml
Work Type                       : http://purl.org/dc/dcmitype/StillImage
```

<br>

---

1-

```bash
    inkscape:export-filename="/home/SakuraSnowAngelAiko/Desktop/pwnedletter.png"
```
- The name/nickname that attacker uses :  `SakuraSnowAngelAiko`

2-

- **Extracted binaries : (2 blocks) :**

```bash
11010110101101111101    |   01000001 00100000 01110000
10101101111110110101    |   01101001 01100011 01110100
01111011000001010101    |   01110101 01110010 01100101
01101110010111010110    |   00100000 01101001 01110011
11011011011011110111    |   00100000 01110111 01101111
01101111000011010101    |   01110010 01110100 01101000
01101011010110101011    |   00100000 00110001 00110000
00011010101011011110    |   00110000 00110000 00100000
10101101010101101101    |   01110111 01101111 01110010
01101101010101101011    |   01100100 01110011 00100000
01101011101101101101    |   01100010 01110101 01110100
01101101101011110111    |   00100000 01101101 01100101
11010110101101111101    |   01110100 01100001 01100100
10101101111110110101    |   01100001 01110100 01100001
01111011000001010101    |   00100000 01101001 01110011
01101110010111010110    |   00100000 01110111 01101111
11011011011011110111    |   01110010 01110100 01101000
01101111000011010101    |   00100000 01100110 01100001
01101011010110101011    |   01110010 00100000 01101101
00011010101011011110    |   01101111 01110010 01100101
10101101010101101101    |
01101101010101101011    |
01101011101101101101    |
01101101101011110111    |
```
---

<br>

I analyzed the `binaries` from the background of picture (these binaries found at two places : in the image’s background and in the website’s source code) By translating them to text using this online [`tool`](https://www.rapidtables.com/convert/number/binary-to-ascii.html), I obtained the following message:

```bash
01000001 00100000 01110000 : A p
01101001 01100011 01110100 : ict
01110101 01110010 01100101 : ure
00100000 01101001 01110011 :  is
00100000 01110111 01101111 :  wo
01110010 01110100 01101000 : rth
00100000 00110001 00110000 :  10
00110000 00110000 00100000 : 00 
01110111 01101111 01110010 : wor
01100100 01110011 00100000 : ds 
01100010 01110101 01110100 : but
00100000 01101101 01100101 :  me
01110100 01100001 01100100 : tad
01100001 01110100 01100001 : ata
00100000 01101001 01110011 :  is
00100000 01110111 01101111 :  wo
01110010 01110100 01101000 : rth
00100000 01100110 01100001 :  fa
01110010 00100000 01101101 : r m
01101111 01110010 01100101 : ore
```

```bash
A picture is worth 1000 words but metadata is worth far more
```

3 -

- **Search for abtained name/nickname**

```bash
    inkscape:export-filename="/home/SakuraSnowAngelAiko/Desktop/pwnedletter.png"
```
- From this path obtained from the website’s source code, i searched the name/nickname SakuraSnowAngelAiko in a web browser and found :<br><br>

- Attacker Twitter [account](https://x.com/SakuraLoverAiko)<br>
- Attacker Github [account](https://github.com/sakurasnowangelaiko)<br>
- Attacker Linkedin [account](https://www.linkedin.com/in/sakuraaiko/)<br>

<br>

---

4 -

- **Twitter username     :** `SakuraLoverAiko` <br>
- **Twitter profile name :** `Aiko`<br>
- **Twitter profile picture** : [picture](https://x.com/SakuraLoverAiko/photo)<br>
- **Date joined twitter :** Joined January 2021<br>
- **Following : (one) :** micorosoft account<br>
- **Twitter-2 username  :** `AiKOABE3`<br>
- **Twitter-2 profile name :** Ai<br>
- **Twitter-2 profile picture :** [picture](https://x.com/AiKOABE3/photo)<br>
- **Date joined twitter-2  :** on October 2022<br>
- **Date joined github :** on January 23, 2021<br>
- **Programming language :** Assembly, C, C++, Java, Python<br>

---

5 -
- **Real name and second twitter account:** A post at `4:56 AM · Jan 30, 2021` the attacker said "Hi there! I'm 
@AikoAbe3!" was the second twitter account
    - With the highest probability, the real name is: `AikoAbe3`

6 -

- **location 1 :**<br>

    - The post shared at `3:54 PM · Jan 25, 2021` contains a picture that is easy to search for
    - <img src="./sakutra_relaxing_place.png" alt="sakura_map" width="350" height="470"/><br><br><br>

    - I searched in map and i found the place `JAL Sakura Lounge, Kawasaki, Japan` besides `Haneda Airport `<br><br>
    - <img src="./sakura_relaxing_place_airport_map.png" alt="sakura_map" width="750" height="550"/><br><br>

---

7 -

- **location 2  :** <br><br> The post shared at `4:57 PM · Jan 25, 2021` it has an anonymous map :<br><br>

    - <img src="./sakura_anounymous_map.jpeg" alt="sakura_map" width="800" height="300"/><br><br>
    - <img src="./sakura_lake.png" alt="sakura_map" width="800" height="300"/><br><br>

    - After searching i found the location : `Sado, Niigata, Japan` and the name of lake `lake inawashiro`<br><br>

---

8 -

- **location 3  :** <br><br> The post shared at `11:33 PM · Jan 24, 2021` contains a picture with a message `Checking out some last minute cherry blossoms before heading home!` :<br><br>

    - <img src="./sakura_travel.jpeg" alt="sakura_map" width="800" height="500"/><br><br>
    
    - <img src="./sakura_check1.png" alt="sakura_map" width="250" height="180"/>
    - [first_check](https://en.wikipedia.org/wiki/Washington_Monument) : Washington Monument<br><br>
    
    - <img src="./sakura_check2.png" alt="sakura_map" width="250" height="180"/>
    - [second_check](https://en.wikipedia.org/wiki/Washington,_D.C.) : Washington, D.C<br><br>

    - Places: (USA) (Washington) (Washington Monument) (Washington, D.C)
    - The closest airport of Washington Monument and Washington, D.C is : `Ronald Reagan Washington National Airport (DCA)`

<br><br>

---

9 -

- **MD5 hashes :** 
    
    <br>

    - New hash : the post shared at `2:47 AM · Jan 24, 2021` contains a md5-hash : `0a5c6e136a98a60b8a21643ce8c15a74`

    - <img src="./Old_hash_.png" width="600" height="200"><br><br>

    
    - I used [my-md5-hasing-tool](https://github.com/achnouri/md5_hashing/blob/main/md5_hashing/hasingtool1.py) which I developed in Python last year to check and decrypt the hash<br><br>
    - My [my-md5-hasing-tool](https://github.com/achnouri/md5_hashing/blob/main/md5_hashing/hasingtool1.py) can compare two hashes, check hash length and type, and perform encryption and decryption <br><br>

        - After using the hashing tool to decrypt the hash, i obtained the following result : <br><br>

            - Hash  `0a5c6e136a98a60b8a21643ce8c15a74` :

            - The type of hash   : MD5 hash
            
            - The lenght of hash : 32 characters
            
            - Result  of the decryption : `0a5c6e136a98a60b8a21643ce8c15a74` : : 
                ```bash
                ------------------------------------------------------------------------------
                    School WiFi Computer Lab:      GTRI-Device              GTgfettt4422!@
                    Mcdonalds:                     Buffalo-G-19D0-1         Macdonalds2020
                    School WiFi:                   GTvisitor                GTFree123
                    City Free WiFi:                HIROSAKI_Free_Wi-Fi      H_Free934!
                    Home WiFi:                     DK1F-G                   Fsdf324T@@
                ------------------------------------------------------------------------------

    - Then i located him  : <br>

    - Based on these outputs, i extracted the `SSIDs` and their `passwords`.

    - And by using [Wigle](https://wigle.net/), i found the `BSSID` for this `SSID: DK1F-G`, which corresponds to the `home Wi-Fi` 
    
    <br>

    - <img src="./wigle_map_bssid_search.png" width="900" height="350"><br><br>

    - **I found its location :** `hirosaki city`<br><br>

    - <img src="./found_.png" width="900" height="350"><br><br>

<br><br>

---

10 -

- **Crypto Wallet [Ethereum]:**

    - MRO : `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`<br>
    - BTC :`139QWoktddChHsZMWZFxmBva4FM96X2dhE`<br>
    
    - Repo link : https://github.com/sakurasnowangelaiko/ETH.git

    - Repo content : Stratum mining URL : `stratum://ethwallet.workerid:password@miningpool:port`<br>

    - But this repo has two commits and i must to check them both : 

        - Last commit content : `stratum://ethwallet.workerid:password@miningpool:port`<br>
        - First commit content : `stratum://0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.Aiko:pswd@eu1.ethermine.org:4444`<br><br>

```bash
    git clone https://github.com/sakurasnowangelaiko/ETH.git
    
    cd ETH
    
    cat miningscript
    stratum://ethwallet.workerid:password@miningpool:port
    
    git log
        commit d507757d5d2208d0124783a8a670239ce19b806c (HEAD -> main, origin/main, origin/HEAD)
        Author: sakurasnowangel <77871458+sakurasnowangel@users.noreply.github.com>
        Date:   Sat Jan 23 12:45:39 2021 -0800

            Update miningscript

        commit 5d83f7bb37c2048bb5b9eb29bb95ec1603c40135
        Author: sakurasnowangel <77871458+sakurasnowangel@users.noreply.github.com>
        Date:   Sat Jan 23 12:44:57 2021 -0800

        Create miningscript
    

    git checkout 5d83f7bb37c2048bb5b9eb29bb95ec1603c40135
    
    cat miningscript
    stratum://0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.Aiko:pswd@eu1.ethermine.org:4444

    git switch  main
```
- Cryptocurrency wallet address of attacker is : `0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef` <br> And by this crypto wallet address i go to : [etherscan_wesite](https://etherscan.io/) for gather more infomartions<br><br>
    
- <img src="./eth_website.png" width="900" height="350"><br><br>

- By know wallet addresse i can see more info about this crypto wallet :

    - Balance : how much ETH or ERC‑20 tokens it currently holds

    - Transaction history : incoming and outgoing transactions (amount, timestamp, addresses interacted with)

    - contract interactions : any interactions with contracts (DEXs, NFTs, DeFi)

    - Token holdings : ERC‑20 or ERC‑721 (NFT) tokens associated with the address

    - Publicly linked addresses : i can see other addresses this wallet has sent to or received from<br><br>

- <img src="./wallet.png" width="900" height="350"><br><br><br>

- I imported a `csv` file of this wallet transactions (42 Transactions) : [`FULL_TRANSACTIONS_CSV_FILE`](./Full_export-0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.csv)

- Mining pool from which the attacker received payments on January 23, 2021 (UTC):

- <img src="./scrreen_vscode_csv.png" width="900" height="350"><br><br>
- <img src="./see_more_details.png" width="900" height="350"><br><br>
- <img src="./details_.png" width="900" height="350"><br><br>

- Mining pool from which the attacker received payments on January 23, 2021 : `Ethermine` 

<br>

- <img src="./tether_crypto.png" width="900" height="250"><br><br>
- The attacker exchanged cryptocurrency with other wallets using this wallet : `Tether`

<br><br>

---

11 -

- **Public Key / PGP repo :**

```bash
    git https://github.com/sakurasnowangelaiko/PGP.git

    cd PGP

    cat publickey

        -----BEGIN PGP PUBLIC KEY BLOCK-----
    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
    23pRnPKc+41cwL3oq8yb/Fhj+biohgIp=grbk
    -----END PGP PUBLIC KEY BLOCK-----</details><br>
    
```

- From this public key I extracted the name/nickname SakuraSnowAngel83 (the key owner) and the associated email domain protonmail.com

- What is PGP ? scroll down to [read more] part

- A tool like gpg can decode the key and display the User ID, key type, key size, fingerprint, and signatures : <br><br>

```bash
gpg --import publickey

    gpg: key ECDD0FD294110450: public key "SakuraSnowAngel83@protonmail.com" imported
        gpg: Total number processed: 1
        gpg:               imported: 1

```

```bash
gpg --list-keys       
    
    /home/achnouri/.gnupg/pubring.kbx
    ---------------------------------
    pub   rsa3072 2021-01-23 [SC] [expired: 2023-01-22]
        A6519F273BF88E9126B0F4C5ECDD0FD294110450
    uid           [expired] SakuraSnowAngel83@protonmail.com

```

```bash
gpg --list-key --keyid-format LONG --fingerprint  

    /home/achnouri/.gnupg/pubring.kbx
    ---------------------------------
    pub   rsa3072/ECDD0FD294110450 2021-01-23 [SC] [expired: 2023-01-22]
        Key fingerprint = A651 9F27 3BF8 8E91 26B0  F4C5 ECDD 0FD2 9411 0450
    uid                 [expired] SakuraSnowAngel83@protonmail.com
```

```bash
gpg --show-key publickey                         
    
    pub   rsa3072 2021-01-23 [SC] [expired: 2023-01-22]
        A6519F273BF88E9126B0F4C5ECDD0FD294110450
    uid                      SakuraSnowAngel83@protonmail.com
    sub   rsa3072 2021-01-23 [E] [expired: 2023-01-22]
```

<br><br>

---

<br><br><br>


## TASK 1 : INTODUCTION :
**nothing, just rewrite the given word**

<br><br>

---

## TASK 2 : TIP OFF

**Background** 
The OSINT Dojo recently found themselves the victim of a cyber attack. It seems that there is no major damage, and there does not appear to be any other significant indicators of compromise on any of our systems. However during forensic analysis our admins found an image left behind by the cybercriminals. Perhaps it contains some clues that could allow us to determine who the attackers were?

We've copied the image left by the attacker, you can view it in your browser [here].

**Instructions**
Images can contain a treasure trove of information, both on the surface as well as embedded within the file itself. You might find information such as when a photo was created, what software was used, author and copyright information, as well as other metadata significant to an investigation. In order to answer the following question, you will need to thoroughly analyze the image found by the OSINT Dojo administrators in order to obtain basic information on the attacker.

Answer the questions below
What username does the attacker go by?

<br>

### TASK-2-QUESTION-ANSWER :

What username does the attacker go by?

<details><summary>ANSWER</summary>SakuraSnowAngel83</details>

<BR>

---

## TASK 3 : RECONNAISSANCE

**Background**


It appears that our attacker made a fatal mistake in their operational security. They seem to have reused their username across other social media platforms as well. This should make it far easier for us to gather additional information on them by locating their other social media accounts. 

**Instructions**
Most digital platforms have some sort of username field. Many people become attached to their usernames, and may therefore use it across a number of platforms, making it easy to find other accounts owned by the same person when the username is unique enough. This can be especially helpful on platforms such as on job hunting sites where a user is more likely to provide real information about themselves, such as their full name or location information.

A quick search on a reputable search engine can help find matching usernames on other platforms, and there are also a large number of specialty tools that exist for that very same purpose. Keep in mind, that sometimes a platform will not show up in either the search engine results or in the specialized username searches due to false negatives. In some cases you need to manually check the site yourself to be 100% positive if the account exists or not. In order to answer the following questions, use the attacker's username found in Task 2 to expand the OSINT investigation onto other platforms in order to gather additional identifying information on the attacker. Be wary of any false positives!

<br>

### TASK-3-QUESTION-ANSWER :

What is the full email address used by the attacker?
<details><summary>ANSWER</summary>SakuraSnowAngel83@protonmail.com</details>

<br>

What is the attacker's full real name?
<details><summary>ANSWER</summary>Aiko Abe</details>

<BR>

---

## TASK 4 : UNVEIL

**Background**
It seems the cybercriminal is aware that we are on to them. As we were investigating into their Github account we observed indicators that the account owner had already begun editing and deleting information in order to throw us off their trail. It is likely that they were removing this information because it contained some sort of data that would add to our investigation. Perhaps there is a way to retrieve the original information that they provided? 

**Instructions**
On some platforms, the edited or removed content may be unrecoverable unless the page was cached or archived on another platform. However, other platforms may possess built-in functionality to view the history of edits, deletions, or insertions. When available this audit history allows investigators to locate information that was once included, possibly by mistake or oversight, and then removed by the user. Such content is often quite valuable in the course of an investigation. In order to answer the below questions, you will need to perform a deeper dive into the attacker's Github account for any additional information that may have been altered or removed. You will then utilize this information to trace some of the attacker's cryptocurrency transactions.

<br>

### TASK-4-QUESTION-ANSWER :

What cryptocurrency does the attacker own a cryptocurrency wallet for?
<details><summary>ANSWER</summary>Ethereum</details>

<br>

What is the attacker's cryptocurrency wallet address?
<details><summary>ANSWER</summary>0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef</details>

<br>

What mining pool did the attacker receive payments from on January 23, 2021 UTC?
<details><summary>ANSWER</summary>Ethermine</details>

<br>

What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet?
<details><summary>ANSWER</summary>Tether</details>

<br><br>

---

## TASK 5 : TAUNT

**Background**
Just as we thought, the cybercriminal is fully aware that we are gathering information about them after their attack. They were even so brazen as to message the OSINT Dojo on Twitter and taunt us for our efforts. The Twitter account which they used appears to use a different username than what we were previously tracking, maybe there is some additional information we can locate to get an idea of where they are heading to next?

We've taken a screenshot of the message sent to us by the attacker, you can view it in your browser here.

**Instructions**

Although many users share their username across different platforms, it isn't uncommon for users to also have alternative accounts that they keep entirely separate, such as for investigations, trolling, or just as a way to separate their personal and public lives. These alternative accounts might contain information not seen in their other accounts, and should also be investigated thoroughly. In order to answer the following questions, you will need to view the screenshot of the message sent by the attacker to the OSINT Dojo on Twitter and use it to locate additional information on the attacker's Twitter account. You will then need to follow the leads from the Twitter account to the Dark Web and other platforms in order to discover additional information.

<br>

### TASK-5-QUESTION-ANSWER :

What is the attacker's current Twitter handle?
<details><summary>ANSWER</summary>SakuraLoverAiko</details>

<br>

What is the BSSID for the attacker's Home WiFi?
<details><summary>ANSWER</summary>84:af:ec:34:fc:f8</details>

<br>

---

## TASK 6 : HOMEBOUND

**Background**
Based on their tweets, it appears our cybercriminal is indeed heading home as they claimed. Their Twitter account seems to have plenty of photos which should allow us to piece together their route back home. If we follow the trail of breadcrumbs they left behind, we should be able to track their movements from one location to the next back all the way to their final destination. Once we can identify their final stops, we can identify which law enforcement organization we should forward our findings to.

**Instructions**
In OSINT, there is oftentimes no "smoking gun" that points to a clear and definitive answer. Instead, an OSINT analyst must learn to synthesize multiple pieces of intelligence in order to make a conclusion of what is likely, unlikely, or possible. By leveraging all available data, an analyst can make more informed decisions and perhaps even minimize the size of data gaps. In order to answer the following questions, use the information collected from the attacker's Twitter account, as well as information obtained from previous parts of the investigation to track the attacker back to the place they call home.

<br>

### TASK-6-QUESTION-ANSWER :

What airport is closest to the location the attacker shared a photo from prior to getting on their flight?
<details><summary>ANSWER</summary>DCA</details>

<br>

What airport did the attacker have their last layover in?
<details><summary>ANSWER</summary>HND</details>

<br>

What lake can be seen in the map shared by the attacker as they were on their final flight home?
<details><summary>ANSWER</summary>lake inawashiro</details>

<br>

What city does the attacker likely consider "home"?
<details><summary>ANSWER</summary></details>

<br>

## [+] Read More :

PGP (Pretty Good Privacy):

    Purpose: 
        Encrypts messages/files and verifies signatures to ensure privacy and authenticity.

    Key system: 
        Uses public/private key pairs:
            Public key: Share with others so they can encrypt messages to you or verify your signatures.
            Private key: Keep secret; used to decrypt messages and sign data.
    Common uses:
        Sending encrypted emails
        Signing software or documents
        Securing communications
    Safety:
        Sharing your public key is safe; only the private key must be protected.


SSID (Service Set Identifier) :
    
    The network name broadcast by a wifi access point

BSSID (Basic Service Set Identifier) :
    
    The access point’s unique MAC address (hardware identifier) for that SSID

for example at this challenge : `SSID: DK1F-G` and `BSSID: 00:11:22:33:44:55`

<br><br>

**SKILLS : (in this challenge)**

    - Search and discovery
    - Social media investigation
    - Metadata & file analysis
    - Geolocation and mapping
    - Cryptocurrency tracing (basic level)
    - PGP / key analysis
    - Inscpecting source code
    ...

**Tools & services (in this challenge)**

    (exiftool, gpg, hash-tool, strings, Google Maps, OpenStreetMap, Wigle, SunCalc, Google lens, etherscan ...)

<br><br>

---

## Disclaimer

This write-up is for educational purposes only. All techniques, tools, and methods demonstrated here were used in a legal training environment (CTF/OSINT challenge)
The author assumes no liability for misuse
<br>

###### This write-up was created by [`@achnouri`](https://github.com/achnouri)

---