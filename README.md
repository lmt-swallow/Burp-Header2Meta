# What does this extender do ?
1. Intercept responses and put specified HTTP headers to the response body as meta tags.

# How to use

1. Install and enable this script with your Burp Suite Professional.
2. Set the scope in which you want to extract HTTP headers to the response body right-clicking in the some tabs or directly inputting regexp. (e.g. ```^https://shift-js.info:433/*``` . please make sure every scope includes a port.)
3. Set the regexp which specifies which HTTP headers to be extracted.
4. If necessary, set the custom position to which you want to insert meta tags.
5. Have happy testing :-)
   
# Environment
I checked it works in the following environment:

- Burp 1.7.30
- Mac OS Sierra
- Jython 2.7.0
- java version "1.8.0_144"
- Java(TM) SE Runtime Environment (build 1.8.0_144-b01)
- Java HotSpot(TM) 64-Bit Server VM (build 25.144-b01, mixed mode)
