# ggitm
Good guy in the middle - transparent HTTPS redirection 

This project is currently  under initial development.

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
     Because a) C is fabulous and we(the developers) like it. b) we would like the deoployment of this program
     to be as simple as possible,without requiring the admin to interact with iptables or manage interpreter
     versions(if had we used an interpreted language).
  - Why transparent?
     Because it's a pain to setup proxies on browsers and some applications are not written with proxy support.
  - IPV6?
     Definetly,but not at this time. 
  - How can I help?
     Join #ggitm on freenode and let's chat :)
## Usage:

```C
ggitm [-d] [-h] <-i interface> 
-h        Display this help
-d        Enable verbose debugging
-i  interface      specify the interface the application will listen on,this is a mandatory option.
```

## Compile

```
make
````


