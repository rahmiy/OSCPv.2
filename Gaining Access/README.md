# Tips on getting quicker exploits
## With Searchsploit
```
nmap -sC -sV -p- --open -v --min-rate 5000 -oN scan.nmap $target
```
```
cat scan.nmap | grep open
```

```
searchsploit $(cat scan.nmap | grep open | awk '{print $3}')`
```
```
grep open scan.nmap | awk '{print $3}' | xargs searchsploit
```

## Recon Script
```
chmod +x recon.sh
./recon.sh 10.10.10.10
```
## Tools
https://www.revshells.com/#bind --> Gains shells and payloads


## Link on CTF enumeration and tips 
https://medium.com/@aaronashley466/oscp-ctf-tips-and-tricks-835e7c2ab96a
