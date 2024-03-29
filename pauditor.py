'''
------------------------------------------------------------------------
********documentation*********
------------------------------------------------------------------------
This is python tool meant to audit weak SSH and Telnet password in the network
NB:only if these services are using standard ports 
------------------------------------------------------------------------
author:plast1k

'''



#imports

import getopt 
import sys
import socket
from IPy import IP
from datetime import datetime
import paramiko
import time
import threading

#kinda global variables

check_vulns='no'
remote_address=''
remote_service=''
target_host_list=[]
loot_list=[]
filename='./wordlist'


# define some colors in a class just to be flushy

class color:
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PINK = '\033[96m'
    DEFAULT_COLOR = '\033[0m'

#End of color class

##user interface functions these are
#about()
#usage()

#about function to display more info about the application

def about():
    print color.DEFAULT_COLOR
    print color.BLUE +"\t###################################################################"
    print color.BLUE +"\t#"+ color.RED +"============++++++"+color.GREEN +" pauditor.py ver 0.1 "+color.RED +"++++++++++================"+color.RED +color.BLUE+"#"
    color.DEFAULT_COLOR
    print color.BLUE +"\t#"+ color.PINK +"------------------------- by plast1k ----------------------------"+color.BLUE +"#"
    print color.BLUE +"\t#"+ color.PINK +"=============++++++++++++++++++++++++++++++++++++++=============="+color.BLUE +"#"
    print color.BLUE +"\t###################################################################"
    print color.DEFAULT_COLOR

#custom strings for failure,success and infomational messages
success=color.GREEN + "[+] "
fail=color.RED + "[-] "
info=color.BLUE + "[*] "

#usage function
def usage ():
    print"Usage:./pauditor.py <options>"
    print"./pauditor.py -i <address> -s <service> -c <Enable check ? give yes | no>"
    print"               -i          The remote address to audit (can be CIDR format)"
    print"               -s          The remote service to audit i.e SSH(22),Telnet(23)"
    print"               -c          Enable check for common vulnerabilities (default is No)"
    print"               -h          Simply print this help menu and exit for "
    print"                Example:./pauditor.py -i 127.0.0.1 -s 22 -c yes"
    print"                 (this will check 127.0.0.1 ssh server on localhost for weak passwords \n \t\t and common Vulns)" 
    print"                or ./pauditor.py -h for help"
    print"                please make sure you give all the options"
#END of of user interface functions

#here goes main application fuctions they include
#network_scanner()
#ssh_brute()
#telnet_brute()
#shell_shock_check()


#start of network_scanner()
def network_scanner():
	
	start_time=datetime.now()
	print color.DEFAULT_COLOR +"_" * 48 ,"\n"
	print "Scan started at  " + str(start_time)
	print color.RED +"Use CTRL+Z anytime to stop the scanner and exit"
	print color.DEFAULT_COLOR +"_" * 48 ,"\n"
	for ip in IP(remote_address):
        	try:
                	print info +"Testing "+ str(ip) +" ...."
                	connection_socket=socket.socket()
                	connection_socket.connect((str(ip),int(remote_service)))
                	banner=connection_socket.recv(1024)
                	connection_socket.close()
                	if connection_socket:
                		print success + " Port "+str(remote_service) +" is open on " + str(ip) +color.PURPLE +" Running :----> " +color.RED+banner
				target_host_list.append(str(ip))
				print success + color.PURPLE +"\'"+ str(ip) + "\' Added to the DB"
        	except:
                	pass
		stop_time=datetime.now()
		time_taken=stop_time - start_time
	if len(target_host_list)==0:
		print fail + "No hosts were found with open port " +remote_service
	else:
		print success + str(len(target_host_list))+ " Total hosts added to the DB ready for auditing.."
	print color.BLUE+"\n Scanning finished in "+ str(time_taken) +"\n"
	
#END of network_scanner()

#start of ssh_brute()

def ssh_brute(IP_address,Password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(IP_address, username='root', password=Password)
    except paramiko.AuthenticationException:
	pass
    else:
        print success+"Password found for " +color.PURPLE+"'root@"+ IP_address +"'"
	#add this host to loot DB
	db_entry= "Host:"+ IP_address +"--->Username:'root'---->Password:" + Password
	loot_list.append(db_entry)
    ssh.close()

#END of ssh_brute()





#start of telnet_brute()



#start of shell_shock_check()










#program entry!!
#this is the MAIN

#get option from the user
if __name__=='__main__':
    if len(sys.argv)<3:
        color.DEFAULT_COLOR
        print color.PURPLE +"you need atleast three arguments"
        color.DEFAULT_COLOR
        about()
        usage()
        sys.exit(0)
    try:
        opts,args=getopt.getopt(sys.argv[1:], 'i:s:c:k,h')
    except getopt.GetoptError, e:
        print e
        usage()
        sys.exit(0)
    try:
        for option,argument in opts:
            if option=='-i':
                address=argument
                remote_address=address
            elif option=='-s':
                service=argument
                remote_service=service
            elif option=='-c':
                vulns_check=argument
                check_vulns=vulns_check
            elif option=='-h':
		about()
                usage()
                sys.exit(0)
    except:
        exit(0)
 
#sanitize user unput first to make sure they don't give gabbage
##check IP address formart first,check the service next and vulnerability scan last but first we fire up the about()
about()

#ip
try:
	IP(remote_address)
	print success + "IP address looks fine....."
	print info + "Checking the service....."

except:
	print fail + "Error! check the IP address you gave ..."
	print info + "Try -h option for help"
	exit(0)
#services
#exit if service not set
if remote_service == '':
	print fail + "You have not provided the service try -h for help..."
	exit(0)
#exit if port number not valid
try:
	int(remote_service)
	
except:
	print fail + "Invalid service port number try -h Nkt!"
	exit(0)

if int(remote_service) == 22:
	print success + "Choosen service is SSH will use port 22....."
	print info + "Checking if vulnerability scan is enabled...."
elif int(remote_service) == 23:
	print success + "Choosen service is Telnet will be using port 23 ...."
	print info + "Checking if vulnerability scan is enabled...."

else :
	print fail + "The service should be either 22 or 23....."
	exit(0)
	
#vulncheck
if check_vulns == 'yes' :
	print success + "Light vulnerability check is enabled ......"
 
if check_vulns == 'no' :
	print success + "Light vulnerability check has been disabled....."

print "\n"
#END of validations
#call the scanner
network_scanner()	
		
'''
#with the network scan done we now have a list with all potential targets for bruteforce
#if the service selected is SSH then we do an SSH brute force else we do telnet an shellshock check
'''
if int(remote_service) == 22 :
	print "[+] Brute forcing below hosts for weak 'root' passwords...."
	print info +"Please be patient...\n"
	print color.RED+"-" * 48
	for every_target_host in target_host_list :
		print color.BLUE + every_target_host
	print color.RED+ "." * 48
	#load and open the wordlist start bruteforcing
	fd = open(filename, "r")
	for line in fd.readlines():
		for host in target_host_list :
    			password = line.strip()
    			t = threading.Thread(target=ssh_brute, args=(host,password))
    			t.start()
    			time.sleep(0.3)
   
	fd.close()


if len(loot_list)== 0:
	print fail +"No weak passwords found! The networks seems a bit secure\n"
else :
	print "\n[Below hosts have weak SSH passwords change them.]"
	print color.BLUE +"-" * 48
	for every_exploited_host in loot_list :
		print color.GREEN+every_exploited_host

	print color.BLUE+ "-" * 48
