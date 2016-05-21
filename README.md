# ggitm
Good guy in the middle - transparent HTTPS redirection 

### WARNING:This project is currently under development and testing,there are bugs and incomplete feautres.

## Description

Often users visit a HTTP website while that website is also offered in HTTPS.

There are browser plugins that automatically attempt to use HTTPS on all sites and they work just fine.

However there are plenty of non-browser applications that access resources of HTTP 
(example: automated scripts,wget,curl,non-graphical browsers mobile apps to name a few). 
And the burden of effectively deploying HTTPS redirection browser plugins on all browsers 
on all workstations is not simple. 

This project aims to develope a application that transparently intercepts HTTP connections,
checks if the server offers content over HTTPS,if so sends a 301 redirect to the client,
masquerdaing as the server and pointing to the HTTPS url of the server and subsequently terminating the 
HTTP TCP session.

## FAQ

  - Why C?
  
     Because a) C is fabulous and we(the developers) like it. b) we would like the deployment of this program
     to be as simple as possible,without requiring the admin to interact with iptables or manage interpreter
     versions(if had we used an interpreted language).
     
  - Why transparent?
  
     Because it's a pain to setup proxies on browsers and some applications are not written with proxy support.
  - IPV6?
  
     Definetly,but not at this time. 
  - What are modes of operations?
  
     ggitm has 2 modes of operation, inline and out of line. 
     
     With inline mode, ggitm sits between clients and servers acting as a transparent network bridge device.
     Inline mode can more effectively guarantee redierctions and block non-http traffic as needed. 
     Inline mode is deployed similar to how an IPS(intrusion prevention system) might be deployed.
     
     Inline mode is currently not supported. 
     
     With out of line mode, ggitm is attached to the network,however it is not responsible for forwarding traffic.
     it passively sniffs network traffic that is copied to it by some other network device and responds 
     with appropriate 301 redirect packets.ool mode is less effective for servers that have less latency to the client
     than the ggitm device does and is unable to drop server response packets. 
     
     In addition to that, with out of line mode redirects never happen on first try unless the host is part of
     the whitelist. for urls outside the whitelisted domains,it will check whether or not HTTPS is supported on the server,
     it will attempt to fetch the url over HTTPS,provided HTTPS certificate validation passes and the server does not respond
     with a 301 or 302 redirect back to an http url, ggitm will start redirecting future requests for this url to it's https
     alternative. this means users willl hve to maintain a good blacklist of sites that break as a result of this.
    
     That being said, network performance is least impacted with out of line deployment.
     
     The default mode of operation is out of line and it should be deployed much like how an IDS (intrusion detection system)
     might be deployed.
  - Why not configure a transparent proxy and mash it up with apache or use squid and see if it works,etc...?
  
    A few problems - you need to whitelist sites,check if https is supported before redirection,
    preload some sites and there are deployment issues.
    
    Do you (as a user) really want to configure apache,iptables or some other OS firewall,write a script
    to keep up with it all,white list stuff,etc...(assuming that approach actually works)?
    
    This application is meant to be as much "point and click" as possible,you do not need to change any OS
    configuration, just point it at an interface that sees the target traffic (could be a copy) and allow it to responds
    to the originator of the traffic. some users may not be able to configure ggitm on a device that forwards
    their traffic, but they are able to copy the traffic to a box running ggitm.
    
    There is the question of simplicity as well,there is no reason to run a full-fledged web server or http proxy
    for this simple task.
    
    Another concern might be performance - proxies or other "in line" network applications process traffic,usually all traffic.
    adding a proxy or any other inline device will decrease performance to some degree which becomes highly unacceptable
    for users expecting low latency and/or high bandwidth out of their network. the out of line mode of ggitm addresses
    this concern, we want to minimize HTTP usage in our networks but we don't want that to come at a heavy price.
    
    
  - How can I help?/ I still have questions:
  
     Join #ggitm on freenode and let's chat :)
     
## Usage:

```C
Usage:
ggitm  <-i interface> [-d <0-7>] [-h] [-m <il,ol,outofline,inline>] [-T https_port] [-H http_port] 
-h                           Display this help
-d <0-7>                     Enable verbose debugging,0 is quiet,7 is noisy
-i <interface>               specify the input interface  the application will listen on,this is a mandatory option.
-o <interface>               specify the output interface for inline mode (mandatory for inline mode of operation)
-m {inline,il,outofline,ol}  specify the mode of operation,only one mode of operation allowed.
-T <1-65535>                 Specify the HTTPS port it will attempt to redirect to
-H <1-65535>                 Specify the HTTP port it will attempt to intercept for redirection

```

## Compile

```
make
````


