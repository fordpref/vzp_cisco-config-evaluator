#Parsing Cisco configuration files
#


#modules to import
import sys


#global variables
cfile = sys.argv[1]
cfile_obj = ""
users = {}
interfaces = {}
config = []
inboundacls = {}
outboundacls = {}
routes = {}
connectednetworks = {}
routerprotocol = {}



def evalsysargv():
	"""
	Function to evaluate the command line arguments and 
	read in the cisco config file to a global list
	called config[].
	"""

	global cfile
	global cfile_obj
	global config
	i = 0
	line = ""

	if len(sys.argv) < 2:
		cfile = raw_input("Enter config file path and name: ");
	cfile_obj = open(cfile,'r')
	for line in cfile_obj:
		config.append(line)
	return

def printfile():
	"""
	Just a test function, can be removed
	"""

	global cfile_obj
	for line in cfile_obj:
		print line,
	return

def printstuff(obj):
	"""
	Just a test function, can be removed
	"""

	print obj,"\ntest print\n\n"
	return


def find_users():
	"""
	-The purpose of this function is to identify the users defined
	in the cisco config.  
	-The function stores a global variable called users
	in which username as a key and stores two values as a list.  The
	first value is the privilege level of the user, the second is
	the encryption type.
	<key> = username
	Format:  users['<key>'][0] = privilege
	Format:  users['<key>'][1] = encryption type
	"""

	global config
	global users

	for line in config:
		if line.startswith("username") == 1:
			parse = line.split(" ")
			if parse[2] == "privilege":
				users[parse[1]] = [parse[3],parse[5]]
			else:
				users[parse[1]] = ["1",parse[3]]

	#for key in users.iteritems():
	#	print "user=",key[0],"\tprivilege:",users[key[0]][0],"\tencryption:",users[key[0]][1]
					
	return

def find_interfaces():
	"""
	-This function parses the config file for interfaces.
	It stores each to a local temporary list, evaluates
	that list to determine if the interface is not shutdown
	and that the interface has an IP address.  
	If it meets both criteria, the function then grabs 5
	values that mean something to us fromt the config. 
	We want the description, IP Address and mask, any dhcp helper
	addresses, ACLs in and out of the interface that are applied.
	-We will use a global dictionary list and assign each key another 
	dictionary list with the 4 parameters we need.
	<key> = Interface name
	interfaces['<key>']['description'] = description of interface
	interfaces['<key>']['address'] = IP address and mask
	interfaces['<key>']['helper'] = DHCP Helper address assigned
	interfaces['<key>']['access_in'] = ACL applied inbound to interface
	interfaces['<key>']['access_out'] = ACL applied outbound to interface
	"""

	global config
	global interfaces
	flag = 0
	i_line = []
	shutdown = 0
	ip = 0
	parse = []
	i_face = ""
	iface = ""
	address = ""
	description = ""
	access_in = ""
	access_out = ""
	helper = ""
	t_interface = {}
	temp_interface = {}
	

	#Parse the interface configs
	#We want lines that start with 'interface'
	#and we want the lines after that all the way
	#until the line starts with '!' signifying the end of that config.

	#loop through the config file looking for interfaces
	for line in config:
		if line.startswith("interface") == 1:
			#split the line to isolate the interface name
			parse = line.split(" ")

			#save the interface name for later
			i_face = parse[1]
			i_face = i_face[:-1]

			# Create a dictionary list (associative array) for the interfaces
			t_interface[parse[1]] = []

			# Set flag to let script know you found an interface
			flag = 1

		#After first line save all the others to a temporary list
		if flag == 1 and line.startswith("!") == 0 and line.startswith("interface") == 0:

			# Save the lines to a temporary list so that we can 
			# evaluate the list in the next section
			i_line.append(line[1:])

		# At the end, parse the temporary array to throw out interfaces
		# we don't care about.  We want interfaces that are active and have IP addresses
		elif flag == 1 and line.startswith("!") == 1:
			for iface in i_line:
			
				#if interface is shutdown, flag for tossing
				if iface == "shutdown":
					shutdown = 1

				# else if interface has an IP and is up, keep it.
				elif iface.startswith("ip address"):
					ip = 1

				# get description, ip address, access-group in, 
				# access-group out, and help-address
				if iface.startswith("description") == 1:
					description = iface[12:]
					description = description[:-1]
				elif iface.startswith("ip helper-address") == 1:
					helper = iface[18:]
					helper = helper[:-1]
				elif iface.startswith("ip access-group") == 1 and iface.endswith("in\n") ==1:
					access_in = iface[16:]
					access_in = access_in[:-4]
				elif iface.startswith("ip access-group") == 1 and iface.endswith("out\n") ==1:
					access_out = iface[16:]
					access_out = access_out[:-5]
				elif iface.startswith("ip address") == 1:
					address = iface[11:]
					address = address[:-1]

			#after evaluating, only keep interface configs we need.
			if shutdown == 0 and ip == 1:
				
				# Assign the i_line list to the interfaces dictionary
				temp_interface = {'description': description, 'address': address, 'helper': helper, 'access_in': access_in, 'access_out': access_out}
				interfaces[i_face] = temp_interface
				i_line = []
				ip = 0
				shutdown = 0
				flag = 0
				address = ""
				helper = ""
				description = ""
				access_in = ""
				access_out = ""
				t_interface = {}
				temp_interface = {}
			else:
				i_line = []
				ip = 0
				shutdown = 0
				flag = 0
				address = ""
				helper = ""
				description = ""
				access_in = ""
				access_out = ""
				temp_interface = {}

	return

def inbound_acls():
	"""
	inbound_acls is a dictionary list that has uses interface names as keys.
	each inbound_acls['key'] has two sub dict list keys,['interfaces'] and ['acl']
	['interfaces'] = list of interfaces using the ACL
	['acl'] = list that is the ACL
	"""

	global interfaces, inboundacls, config
	acl_interfaces = {}
	acl_names = []
	acl = []
	acl_name = ""
	acl_flag = 0
	acl_ext = 0
	acl_basic = 0
	acl_ext_name = ""
	acl_basic_name = ""
	
	#loop through interfaces and identify unique inbound ACLs in acl_names[] list
	#and add the interface to the acl_interfaces['<acl_name>'][interface list]

	for key in interfaces:
		if interfaces[key]['access_in'] != "":
			acl_name = interfaces[key]['access_in']
			if acl_name not in acl_names:
				inboundacls[acl_name]={'interfaces': [],'acl': []}
				inboundacls[acl_name]['interfaces'].append(key)
				acl_names.append(acl_name)
			else:
				inboundacls[acl_name]['interfaces'].append(key)
	
	#loop through config and assign ACL to acl[] list	
	for line in config:
		if line.startswith("ip access-list extended") == 1 and acl_ext == 1:
			acl_ext = 0
			for i in acl_names:
				if line.startswith("ip access-list extended "+i) == 1:
					acl_ext = 1
					acl_ext_name = i
		elif line.startswith("!") == 1:
			acl_ext = 0
			acl_basic = 0
			acl_ext_name = ""
			acl_basic_name = ""
		elif line.startswith("access-list") == 1 and acl_basic == 1 and line.startswith("access-list "+acl_basic_name) == 0:
			acl_basic = 0
			for i in acl_names:
				if line.startswith("access-list "+i) == 1:
					acl_basic = 1
					acl_basic_name = i
					drop = 11 + len(i) + 1
					inboundacls[acl_basic_name]['acl'].append(line[drop:])
		elif acl_ext == 1:
                    inboundacls[acl_ext_name]['acl'].append(line[1:])
		elif acl_basic == 1 and line.startswith("access-list "+acl_basic_name) == 1:
			drop = 11 + len(i) + 1
			inboundacls[acl_basic_name]['acl'].append(line[drop:])
		elif line.startswith("ip access-list extended") == 1 and acl_ext == 0:
			for i in acl_names:
				if line.startswith("ip access-list extended "+i) == 1:
					acl_ext = 1
					acl_ext_name = i
		elif line.startswith("access-list") == 1 and acl_basic == 0:
			for i in acl_names:
				if line.startswith("access-list "+i) == 1:
					acl_basic = 1
					acl_basic_name = i
					drop = 11 + len(i) + 1
					inboundacls[acl_basic_name]['acl'].append(line[drop:])

def outbound_acls():
	"""
	outbound_acls is a dictionary list that has uses interface names as keys.
	each outbound_acls['key'] has two sub dict list keys,['interfaces'] and ['acl']
	['interfaces'] = list of interfaces using the ACL
	['acl'] = list that is the ACL
	"""

	global interfaces, outboundacls, config
	acl_interfaces = {}
	acl_names = []
	acl = []
	acl_name = ""
	acl_flag = 0
	acl_ext = 0
	acl_basic = 0
	acl_ext_name = ""
	acl_basic_name = ""
	
	#loop through interfaces and identify unique outbound ACLs in acl_names[] list
	#and add the interface to the acl_interfaces['<acl_name>'][interface list]

	for key in interfaces:
		if interfaces[key]['access_out'] != "":
			acl_name = interfaces[key]['access_out']
			if acl_name not in acl_names:
				outboundacls[acl_name]={'interfaces': [],'acl': []}
				outboundacls[acl_name]['interfaces'].append(key)
				acl_names.append(acl_name)
			else:
				outboundacls[acl_name]['interfaces'].append(key)
	
	#loop through config and assign ACL to acl[] list	
	for line in config:
		if line.startswith("ip access-list extended") == 1 and acl_ext == 1:
			acl_ext = 0
			for i in acl_names:
				if line.startswith("ip access-list extended "+i) == 1:
					acl_ext = 1
					acl_ext_name = i
		elif line.startswith("!") == 1:
			acl_ext = 0
			acl_basic = 0
			acl_ext_name = ""
			acl_basic_name = ""
		elif line.startswith("access-list") == 1 and acl_basic == 1 and line.startswith("access-list "+acl_basic_name) == 0:
			acl_basic = 0
			for i in acl_names:
				if line.startswith("access-list "+i) == 1:
					acl_basic = 1
					acl_basic_name = i
					drop = 11 + len(i) + 1
					outboundacls[acl_basic_name]['acl'].append(line[drop:])
		elif acl_ext == 1:
			outboundacls[acl_ext_name]['acl'].append(line)
		elif acl_basic == 1 and line.startswith("access-list "+acl_basic_name) == 1:
			drop = 11 + len(i) + 1
			outboundacls[acl_basic_name]['acl'].append(line[drop:])
		elif line.startswith("ip access-list extended") == 1 and acl_ext == 0:
			for i in acl_names:
				if line.startswith("ip access-list extended "+i) == 1:
					acl_ext = 1
					acl_ext_name = i
		elif line.startswith("access-list") == 1 and acl_basic == 0:
			for i in acl_names:
				if line.startswith("access-list "+i) == 1:
					acl_basic = 1
					acl_basic_name = i
					drop = 11 + len(i) + 1
					outboundacls[acl_basic_name]['acl'].append(line[drop:])
		
def static_routes():
	"""
	What are the static routes defined in the config?
	What are the connected networks?
	routes{<network>}(<mask>,<gateway>)
	connectednetworks{<network>}(<mask>,<interface>)
	"""

	global config,interfaces,routes,connectednetworks
	
	#Get Static Routes
	for line in config:
		if line.startswith("ip route"):
			line = line[9:]
			parse = line.split(" ")
			routes[parse[0]] = (parse[1],parse[2])

	#Get connected Networks
	for key in interfaces:
		parse = interfaces[key]['address'].split(" ")
		connectednetworks[parse[0]] = (parse[1], key)

	return

def routing_protocols():
	"""
	Are routing protocols defined, what interfaces, what networks will it advertise?
	routerprotocol{<protocol name>}{'metric', <metric>}{'passive-interfaces', [<interface names>]}{'active-interfaces',
	[<interface name>]}{'networks', [<network>,<wildcard mask>,<area #>]}
	"""
	global config, routerprotocol
	flag = 0
	protocol = ""
        area = 0

        #OSPF Routing info
        routerprotocol['ospf'] = {}
	for line in config:
                line = line[:-1]
		if flag == 0 and line.startswith("router ospf") == 1:
			flag = 1
			parse = line.split(" ")
			protocol = parse[1]
                        area = parse[2]
                        routerprotocol[protocol][area] = {}
			routerprotocol[protocol][area]['passive-interfaces'] = []
			routerprotocol[protocol][area]['active-interfaces'] = []
			routerprotocol[protocol][area]['networks'] = []
		elif flag == 1 and line.startswith(" ") == 1:
			line = line[1:]
			if line.startswith("passive-interface ") == 1:
				line = line[18:]
				routerprotocol[protocol][area]['passive-interfaces'].append(line)
			elif line.startswith("no passive-interface ") == 1:
				line = line[21:]
				routerprotocol[protocol][area]['active-interfaces'].append(line)
			elif line.startswith("network ") == 1:
				line = line[8:]
                                routerprotocol[protocol][area]['networks'].append(line)
		elif flag == 1 and line.startswith("!") == 1:
			flag = 0
	flag = 0

        #BGP Routing info
        routerprotocol['bgp'] = {}
	for line in config:
                line = line[:-1]
		if flag == 0 and line.startswith("router bgp") == 1:
			flag = 1
			parse = line.split(" ")
			protocol = parse[1]
                        AS = parse[2]
                        routerprotocol[protocol][AS] = {}
                        routerprotocol[protocol][AS]['router-id'] = ""
			routerprotocol[protocol][AS]['network'] = []
			routerprotocol[protocol][AS]['redistribute'] = []
			routerprotocol[protocol][AS]['neighbor'] = []
                        routerprotocol[protocol][AS]['metric'] = ""
		elif flag == 1 and line.startswith(" ") == 1:
			line = line[1:-1]
                        if line.startswith("bgp router-id"):
                            line = line[14:]
                            routerprotocol[protocol][AS]['router-id'] = line
			elif line.startswith("network ") == 1:
				line = line[8:]
				routerprotocol[protocol][AS]['network'].append(line)
			elif line.startswith("redistribute ") == 1:
				line = line[13:]
				routerprotocol[protocol][AS]['redistribute'].append(line)
			elif line.startswith("neighbor ") == 1:
				line = line[9:]
				routerprotocol[protocol][AS]['neighbor'].append(line)
                        elif line.startswith("default-metric ") == 1:
                            line = line[15:]
                            routerprotocol[protocol][AS]['metric'] = line
		elif flag == 1 and line.startswith("!") == 1:
			flag = 0
	flag = 0
		

def report():
	global interfaces, users, inboundacls, outboundacls, routes, connectednetworks, routerprotocol

        
	filename = raw_input("\n\nReport Name: ")
	csvfile = open(filename+".csv",'w')
	htmfile = open(filename+".htm",'w')
	htmfile.write("<!DOCTYPE html>\n<html>\n<body>\n<p>\n\n\n")
	
	#Write out Header for report
	htmfile.write("<p><font size=""20""><b>"+filename+"</b></font><br><br></p>\n")
	htmfile.write("<font size=""2""><A name=""Summary""><p><br><b>SUMMARY</b></font><br></p></a>\n\n")
	csvfile.write(filename+"\n")

	#Write out the Users section for HTM and CSV
	htmfile.write("<font size=""2""><p><b>USERS</b><br>\n")
	htmfile.write("<table border=""1"">\n<tr>\n<td>USERNAME</td><td>PRIVILEGE</td><td>ENCRYPTION</td>\n</tr>\n")
	csvfile.write("USERS\n")
	csvfile.write("username,privilege,encryption\n")
	for key in users:
		htmfile.write("<tr>\n<td>"+key+"</td><td>"+users[key][0]+"</td><td>"+users[key][1]+"</td>\n</tr>\n")
		csvfile.write(key+","+users[key][0]+","+users[key][1]+"\n")
	htmfile.write("</table><br><br></p>\n\n\n")
	csvfile.write("\n")

	#Write out the Interfaces, first Interfaces with ACLS
	htmfile.write("<p><b>INTERFACES WITH ACLs</b>\n")
	htmfile.write("<table border=""1"">\n<tr>\n<td>Interface Name</td><td>Description</td><td>Address Mask</td><td>DHCP Helper</td><td>ACL Inbound</td><td>ACL Outbound</td>\n</tr>\n")
	csvfile.write("\nINTERFACES WITH ACLS\n")
	csvfile.write("Interface Name,Description,Address Mask,DHCP Helper,ACL Inbound,ACL Outbound\n")

	for key in interfaces:
		if interfaces[key]['access_in'] != "" or interfaces[key]['access_out'] != "":
			description = interfaces[key]['description']
			address = interfaces[key]['address']
			helper = interfaces[key]['helper']
			access_in = interfaces[key]['access_in']
			access_out = interfaces[key]['access_out']
			htmfile.write('<tr>\n<td>'+key+'</td><td>'+description+'</td><td>'+address+'</td><td>'+helper+'</td><td><A href="#'+access_in+'">'+access_in+'</A></td><td><A href="#'+access_out+'">'+access_out+'</A></td>\n</tr>\n')
			csvfile.write(key+","+interfaces[key]['description']+","+interfaces[key]['address']+","+interfaces[key]['helper']+","+interfaces[key]['access_in']+","+interfaces[key]['access_out']+"\n")
	htmfile.write("</table><br><br><br></p>\n\n\n")
	

	htmfile.write("<p><b>INTERFACES WITHOUT ACLs</b>\n")
	htmfile.write("<table border=""1"">\n<tr>\n<td>Interface Name</td><td>Description</td><td>Address Mask</td><td>DHCP Helper</td>\n</tr>\n")
	csvfile.write("\nINTERFACES WITHOUT ACLS\n")
	csvfile.write("Interface Name,Description,Address Mask,DHCP Helper\n")

	for key in interfaces:
		if interfaces[key]['access_in'] == "" and interfaces[key]['access_out'] == "":
			htmfile.write("<tr>\n<td>"+key+"</td><td>"+interfaces[key]['description']+"</td><td>"+interfaces[key]['address']+"</td><td>"+interfaces[key]['helper']+"</td>\n</tr>\n")
			csvfile.write(key+","+interfaces[key]['description']+","+interfaces[key]['address']+","+interfaces[key]['helper']+"\n")
	htmfile.write("</table><br><br><br></p>\n\n\n")
	

	#Write the static routes
	htmfile.write("<p><b>Static Routes</b><br>")
	htmfile.write("<table border=""1"">\n<tr>\n<td>Destination</td><td>Mask</td><td>Gateway</td>\n</tr>\n")
	csvfile.write("Static Routes\n")
	csvfile.write("Destination,Mask,Gateway\n")
	for key in routes:
		htmfile.write("<tr><td>"+key+"</td><td>"+routes[key][0]+"</td><td>"+routes[key][1]+"</td></tr>\n")
		csvfile.write(key+","+routes[key][0]+","+routes[key][1]+"\n")
	htmfile.write("</table><br></p>\n\n\n")
	csvfile.write("\n")	

	#write the connected networks (basically static routes)
	htmfile.write("<p><b>Connected Networks</b> (basically static routes)<br>\n")
	htmfile.write("<table border=""1"">\n<tr>\n<td>Destination</td><td>Mask</td><td>Interface</td>\n</tr>\n")
	csvfile.write("connected Networks\n")
	csvfile.write("Destination,Mask,Interface\n")
	for key in connectednetworks:
		htmfile.write("<tr><td>"+key+"</td><td>"+connectednetworks[key][0]+"</td><td>"+connectednetworks[key][1]+"</td></tr>\n")
		csvfile.write(key+","+connectednetworks[key][0]+","+connectednetworks[key][1]+"\n")
	htmfile.write("</table><br></p>\n\n\n")
	csvfile.write("\n")	

	#write routing protocols in use and active interfaces and networks
	htmfile.write("<p><b>Routing Protocols In Use</b><br>\n")
	csvfile.write("\nRouting Protocols")

        htmfile.write('<table border="1">\n')
        htmfile.write('<th><a name="RPSUM">Routing Protocol Summary</a></th>')
        htmfile.write('<table border="1">\n')
        for key in routerprotocol:
            htmfile.write('<tr><td>' + key + '</td><td><a href="#' + key + 'DET">DETAILS</a></td></tr>')
        htmfile.write('</table><br><br>')     


	#DETAILED SECTION
	htmfile.write("<br><br><br>------------------------------------<br>\n")
	htmfile.write("<b>DETAILED SECTION------------</b><br>\n")
	htmfile.write("------------------------------------<br>\n")


	# Start the Inbound ACL section
	# print the header
	htmfile.write("<p><br><br><br><b>Inbound Access Control Lists</b><br></p>\n")
	csvfile.write("\n\nInbound Access Control Lists")
	
	#if no inbound ACLs, document and return
	if len(inboundacls) == 0:
		htmfile.write("<p>NO INBOUND ACLs FOUND (<A href=""#Summary"">Back to Summary</A>)</p>\n\n")
                csvfile.write("NO INBOUND ACLS FOUND\n")
	else:
		#Write each inbound ACL as a table
		for key in inboundacls:
			htmfile.write('<br><br>\n<b><A name="' + key + '"></A>' + key + ' Access Control List</b> inbound to router interfaces below: (<A href="#Summary">Back to Summary</A>)\n')
			csvfile.write(key + "\n")
			htmfile.write("<table border=""1""><tr><td>Interfaces: " + (", ".join(inboundacls[key]['interfaces'])) + "</td></tr>\n")
			csvfile.write("Interfaces: " + (" ".join(inboundacls[key]['interfaces'])) + "\n")
			
                        for line in inboundacls[key]['acl']:
				htmfile.write("<tr><td>" + line + "</td></tr>\n")
				csvfile.write(line)
    		        htmfile.write("</table>\n")
	htmfile.write("</p>\n\n\n")


	# Start the Outbound ACL section
	# print the header
	htmfile.write("<p><br><br><br><b>Outbound Access Control Lists</b><br>\n")
	csvfile.write("\n\nOutbound Access Control Lists")
	
	#if no outbound ACLs, document and return
	if len(outboundacls) == 0:
		htmfile.write("NO OUTBOUND ACLs FOUND (<A href=""#Summary"">Back to Summary</A>)\n")
	else:
		#Write each outbound ACL as a table
		for key in outboundacls:
			htmfile.write('<br><br><b><A name="'+key+'"></A>'+key+' Access Control List</b> outbound from router interfaces below: (<A href="#Summary">Back to Summary</A>)\n')
			csvfile.write(key+"\n")
		
			htmfile.write("<table border=""1""><tr><td>Interfaces: "+(", ".join(outboundacls[key]['interfaces']))+"</td></tr>\n")
			csvfile.write("Interfaces: "+(" ".join(outboundacls[key]['interfaces'])))
		

			for line in outboundacls[key]['acl']:
				htmfile.write("<tr><td>"+line+"</td></tr>\n")
				csvfile.write(line)
		        htmfile.write("</table>\n")
	htmfile.write("</p></font></body>\n\n\n")
        csvfile.write("\n\n")
	

	#write routing protocols in use and active interfaces and networks
	htmfile.write("<p><b>Routing Protocols</b><br>\n")
	csvfile.write("\nRouting Protocols")

        flag = 0
        flagkey = ""
	for key in routerprotocol:
            if flag == 0 and flagkey != key:
                htmfile.write('<table border="1">\n')
                htmfile.write('<th><a name="' + key + 'DET">' + key + ' DETAILS (<a href="#RPSUM">SUMMARY</a>)</th>\n')
                flag = 1
                flagkey = key
            elif flag == 1 and flagkey != key:
                htmfile.write('</table><br><br>\n')
                htmfile.write('<table border="1">\n')
                htmfile.write('<th><a name="' + key + 'DET">' + key + ' DETAILS (<a href="#RPSUM">SUMMARY</a>)</th>\n')
                flag = 1
                flagkey = key

            if key == "ospf":
                for area in routerprotocol[key]:
                    htmfile.write('<tr><td>&nbsp;</td></tr>')
                    htmfile.write('<tr><b><td>Area: ' + area + '</td></b></tr>\n')
		    htmfile.write('<tr><b><td>Passive Interfaces</td></b></tr><tr>')
		    for x in routerprotocol[key][area]['passive-interfaces']:
			htmfile.write("<td>" + x + "</td>")
                    htmfile.write('</tr>\n')    
		    htmfile.write("<tr><b><td>Active Interfaces</td></b></tr><tr>")
		    for x in routerprotocol[key][area]['active-interfaces']:
			htmfile.write("<td>" + x + "</td>")
		    htmfile.write("</tr>\n")
                    htmfile.write("<tr><b><td>NETWORKS</td></b></tr>")
		    for x in routerprotocol[key][area]['networks']:
			htmfile.write("<tr><td>" + x + "</td></tr>\n")
            elif key == "bgp":
                for AS in routerprotocol[key]:
                    htmfile.write('<tr><td>&nbsp;</td></tr>')
                    htmfile.write('<th>Autonomous System ' + AS + '</th>\n')
                    htmfile.write('<tr><b><td>Router-ID: ' + routerprotocol[key][AS]["router-id"] + '</td></b></tr>\n')
                    htmfile.write('<tr><b><td>Metric ' + routerprotocol[key][AS]["metric"] + '</td></b></tr>\n')
                    htmfile.write("<tr><b><td>Networks</td></b></tr>\n")
                    for network in routerprotocol[key][AS]['network']:
                        htmfile.write("<tr><td>" + network + "</td></tr>\n")
                    htmfile.write("<tr><b><td>Redistribution</td></b></tr>\n")
                    for redistribute in routerprotocol[key][AS]['redistribute']:
                        htmfile.write("<tr><td>" + redistribute + "</td></tr>\n")
                    htmfile.write("<tr><b><td>Neighbor</td></b></tr>\n")
                    for neighbor in routerprotocol[key][AS]['neighbor']:
                        htmfile.write("<tr><td>" + neighbor + "</td></tr>\n")
        htmfile.write('</table><br><br>\n')                
        htmfile.write("</p></body></html>")    
                
	return



# open the config file specified
evalsysargv()
find_users()
find_interfaces()
inbound_acls()
outbound_acls()
static_routes()
routing_protocols()
report()
