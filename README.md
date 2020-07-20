# Scytode Web Identification Scanner
(scytode.py)
<img align="center" src="https://github.com/becrevex/Scytode/blob/master/scytode.JPG"/> 

# Examples
<b>Assess a single target:</b><br>
$ python3 scytode.py -t 10.21.12.21

<b>Assess a CIDR notation network range:</b><br>
$ python3 scytode.py -r 10.21.12.0/24

<b>Assess a list of targets in a file</b><br>
$ python3 scytode.py -iL hosts.txt

# Output
When Scytode is ran using a range or a collection from a file, it will automagically create an output.csv
file of all IPs assessed and their respective server/platform types.  In addition, Scytode will also create a 
./targets/ directory with all IPs listed by type in corresponding textfiles.  

------------------------------------------------------------------------------------------------------

# Installation
git clone https://github.com/becrevex/Scytode.git


