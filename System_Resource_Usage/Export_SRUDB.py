# Export_SRUDB.py = Python script to extract the System Resource Usage to a SQLite Database
#
# Copyright (C) 2016 Mark McKinnon (Mark.McKinnon@Gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#
# Version History:
#  Initial Version - Requires pyesedb python binding from the project libyal/libesedb
# 
# Usage Examples:
# python3 export_srudb.py srudb.dat software srudb.db3

from Registry import Registry
from Database import SQLiteDb
import os
import sys
import re
import datetime
import math
import struct
import pyesedb
import codecs


#  'SruDbIdMapTable':'SruDbIdMapTable'
#  '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}':'Application_Resource_Usage'
#  '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}':'Energy_Usage_Data'
#  '{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}':'Energy_Estimation_Provider'
#  '{973F5D5C-1D90-4944-BE8E-24B94231A174}':'Network_Usage',
#  '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}':'Windows_Push_Notification'
#  '{DD6636C4-8929-4683-974E-22C046A43763}':'Network_Connectivity'
#  'SruDbCheckpointTable':'SruDbCheckpointTable'
#  '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT':'Energy_Usage_Provider'
#  '{5C8CF1C7-7257-4F13-B223-970EF5939312}':'App_Timeline_PRovider'
#  '{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}':'vfuprov'
#  '{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}':'Tagged_Energy_Provider'
#  '{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}':'Energy_Estiation_Provider2'


# Setup dictionary for column types
Application_Table_List  = ['Application_Resource_Usage', 'Energy_Usage_Data', 'Energy_Estimation_Provider', \
			               'Network_Usage', 'Windows_Push_Notification', 'Network_Connectivity', 'Energy_Usage_Provider', \
                           'App_Timeline_Provider', 'vfuprov', 'Tagged_Energy_Provider', 'Energy_Estimation_Provider2']

Column_Dict = {0:'NULL', 1:'Text', 2:'Integer', 3:'Integer', 4:'Integer', 5:'Integer', 6:'Real', 7:'Real', 8:'Text', 9:'Blob', \
              10:'Text', 11:'Blob', 12:'Text', 13:'Integer', 14:'Integer', 15:'Integer', 16:'Text', 17:'Integer'}
Table_Dict = {'SruDbIdMapTable':'SruDbIdMapTable','{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}':'Application_Resource_Usage', \
              '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}':'Energy_Usage_Data','{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}':'Energy_Estimation_Provider', \
			  '{973F5D5C-1D90-4944-BE8E-24B94231A174}':'Network_Usage','{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}':'Windows_Push_Notification', \
			  '{DD6636C4-8929-4683-974E-22C046A43763}':'Network_Connectivity', 'MSysObjects':'MSysObjects', \
			  'MSysObjectsShadow':'MSysObjectsShadow', 'MSysObjids':'MSysObjids', 'MSysLocales':'MSysLocales', \
			  'SruDbCheckpointTable':'SruDbCheckpointTable', '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT':'Energy_Usage_Provider', \
              '{5C8CF1C7-7257-4F13-B223-970EF5939312}':'App_Timeline_Provider', '{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}':'vfuprov', \
              '{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}':'Tagged_Energy_Provider', '{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}':'Energy_Estimation_Provider2'}
Table_Rev_Dict = {'SruDbIdMapTable':'SruDbIdMapTable','Application_Resource_Usage':'{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}', \
              'Energy_Usage_Data':'{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}','Energy_Estimation_Provider':'{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}', \
			  'Network_Usage':'{973F5D5C-1D90-4944-BE8E-24B94231A174}','Windows_Push_Notification':'{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}', \
			  'Network_Connectivity':'{DD6636C4-8929-4683-974E-22C046A43763}', 'MSysObjects':'MSysObjects', \
			  'MSysObjectsShadow':'MSysObjectsShadow', 'MSysObjids':'MSysObjids', 'MSysLocales':'MSysLocales', \
			  'SruDbCheckpointTable':'SruDbCheckpointTable','Energy_Usage_Provider':'{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT', \
              'App_Timeline_Provider':'{5C8CF1C7-7257-4F13-B223-970EF5939312}', 'vfuprov':'{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}', \
              'Tagged_Energy_Provider':'{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}', 'Energy_Estimation_Provider2':'{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}'}

knownSids = {"S-1-5-32-545":"Users", "S-1-5-32-544":"Administrators", "S-1-5-32-547":"Power Users", "S-1-5-32-546":"Guests",
             "S-1-5-32-569":"BUILTIN\\Cryptographic Operators", "S-1-16-16384":"System Mandatory Level", "S-1-5-32-551":"Backup Operators",
             "S-1-16-8192":"Medium Mandatory Level", "S-1-5-80":"NT Service", "S-1-5-32-548":"Account Operators",
             "S-1-5-32-561":"BUILTIN\\Terminal Server License Servers", "S-1-5-64-14":"SChannel Authentication",
             "S-1-5-32-562":"BUILTIN\\Distributed COM Users", "S-1-5-64-21":"Digest Authentication", "S-1-5-19":"NT Authority", "S-1-3-0":"Creator Owner",
             "S-1-5-80-0":"All Services", "S-1-5-20":"NT Authority","S-1-5-18":"Local System", "S-1-5-32-552":"Replicators",
             "S-1-5-32-579":"BUILTIN\\Access Control Assistance Operators", "S-1-16-4096":"Low Mandatory Level", "S-1-16-12288":"High Mandatory Level",
             "S-1-2-0":"Local", "S-1-16-0":"Untrusted Mandatory Level", "S-1-5-3":"Batch", "S-1-5-2":"Network", "S-1-5-1":"Dialup", "S-1-5-7":"Anonymous",
             "S-1-5-6":"Service", "S-1-5-4":"Interactive", "S-1-5-9":"Enterprise Domain Controllers", "S-1-5-8":"Proxy", "S-1-5-32-550":"Print Operators",
             "S-1-0-0":"Nobody", "S-1-5-32-559":"BUILTIN\\Performance Log Users", "S-1-5-32-578":"BUILTIN\\Hyper-V Administrators", "S-1-5-32-549":"Server Operators",
             "S-1-2-1":"Console Logon", "S-1-3-1":"Creator Group", "S-1-5-32-575":"BUILTIN\\RDS Remote Access Servers", "S-1-3-3":"Creator Group Server",
             "S-1-3-2":"Creator Owner Server", "S-1-5-32-556":"BUILTIN\\Network Configuration Operators", "S-1-5-32-557":"BUILTIN\\Incoming Forest Trust Builders",
             "S-1-5-32-554":"BUILTIN\\Pre-Windows 2000 Compatible Access", "S-1-5-32-573":"BUILTIN\\Event Log Readers", "S-1-5-32-576":"BUILTIN\\RDS Endpoint Servers",
             "S-1-5-83-0":"NT VIRTUAL MACHINE\\Virtual Machines", "S-1-16-28672":"Secure Process Mandatory Level", "S-1-5-11":"Authenticated Users", "S-1-1-0":"Everyone",
             "S-1-5-32-555":"BUILTIN\\Remote Desktop Users", "S-1-16-8448":"Medium Plus Mandatory Level", "S-1-5-17":"This Organization",
             "S-1-5-32-580":"BUILTIN\\Remote Management Users", "S-1-5-15":"This Organization", "S-1-5-14":"Remote Interactive Logon", "S-1-5-13":"Terminal Server Users",
             "S-1-5-12":"Restricted Code", "S-1-5-32-577":"BUILTIN\\RDS Management Servers", "S-1-5-10":"Principal Self", "S-1-3":"Creator Authority",
             "S-1-2":"Local Authority", "S-1-1":"World Authority", "S-1-0":"Null Authority", "S-1-5-32-574":"BUILTIN\\Certificate Service DCOM Access",
             "S-1-5":"NT Authority", "S-1-4":"Non-unique Authority", "S-1-5-32-560":"BUILTIN\\Windows Authorization Access Group",
             "S-1-16-20480":"Protected Process Mandatory Level", "S-1-5-64-10":"NTLM Authentication", "S-1-5-32-558":"BUILTIN\\Performance Monitor Users"}

LUIDInterfaces = {"133":"IF_TYPE_CES", "132":"IF_TYPE_COFFEE", "131":"IF_TYPE_TUNNEL", "130":"IF_TYPE_A12MPPSWITCH", "137":"IF_TYPE_L3_IPXVLAN", "136":"IF_TYPE_L3_IPVLAN",
                  "135":"IF_TYPE_L2_VLAN", "134":"IF_TYPE_ATM_SUBINTERFACE", "139":"IF_TYPE_MEDIAMAILOVERIP", "138":"IF_TYPE_DIGITALPOWERLINE",
                  "24":"IF_TYPE_SOFTWARE_LOOPBACK", "25":"IF_TYPE_EON", "26":"IF_TYPE_ETHERNET_3MBIT", "27":"IF_TYPE_NSIP", "20":"IF_TYPE_BASIC_ISDN",
                  "21":"IF_TYPE_PRIMARY_ISDN", "22":"IF_TYPE_PROP_POINT2POINT_SERIAL", "23":"IF_TYPE_PPP", "28":"IF_TYPE_SLIP", "29":"IF_TYPE_ULTRA", "4":"IF_TYPE_DDN_X25",
                  "8":"IF_TYPE_ISO88024_TOKENBUS", "119":"IF_TYPE_LAP_F", "120":"IF_TYPE_V37", "121":"IF_TYPE_X25_MLP", "122":"IF_TYPE_X25_HUNTGROUP",
                  "123":"IF_TYPE_TRANSPHDLC", "124":"IF_TYPE_INTERLEAVE", "125":"IF_TYPE_FAST", "126":"IF_TYPE_IP", "127":"IF_TYPE_DOCSCABLE_MACLAYER",
                  "128":"IF_TYPE_DOCSCABLE_DOWNSTREAM", "129":"IF_TYPE_DOCSCABLE_UPSTREAM", "118":"IF_TYPE_HDLC", "59":"IF_TYPE_AFLANE_8023",
                  "58":"IF_TYPE_FRAMERELAY_INTERCONNECT", "55":"IF_TYPE_IEEE80212", "54":"IF_TYPE_PROP_MULTIPLEXOR", "57":"IF_TYPE_HIPPIINTERFACE",
                  "56":"IF_TYPE_FIBRECHANNEL", "51":"IF_TYPE_SONET_VT", "50":"IF_TYPE_SONET_PATH", "53":"IF_TYPE_PROP_VIRTUAL", "52":"IF_TYPE_SMDS_ICIP",
                  "115":"IF_TYPE_ISO88025_FIBER", "114":"IF_TYPE_IPOVER_ATM", "88":"IF_TYPE_ARAP", "89":"IF_TYPE_PROP_CNLS", "111":"IF_TYPE_STACKTOSTACK",
                  "110":"IF_TYPE_IPOVER_CLAW", "113":"IF_TYPE_MPC", "112":"IF_TYPE_VIRTUALIPADDRESS", "82":"IF_TYPE_DS0_BUNDLE", "83":"IF_TYPE_BSC",
                  "80":"IF_TYPE_ATM_LOGICAL", "81":"IF_TYPE_DS0", "86":"IF_TYPE_ISO88025R_DTR", "87":"IF_TYPE_EPLRS", "84":"IF_TYPE_ASYNC", "85":"IF_TYPE_CNR",
                  "3":"IF_TYPE_HDH_1822", "7":"IF_TYPE_IS088023_CSMACD", "108":"IF_TYPE_PPPMULTILINKBUNDLE", "109":"IF_TYPE_IPOVER_CDLC", "102":"IF_TYPE_VOICE_FXS",
                  "103":"IF_TYPE_VOICE_ENCAP", "100":"IF_TYPE_VOICE_EM", "101":"IF_TYPE_VOICE_FXO", "106":"IF_TYPE_ATM_FUNI", "107":"IF_TYPE_ATM_IMA",
                  "104":"IF_TYPE_VOICE_OVERIP", "105":"IF_TYPE_ATM_DXI", "39":"IF_TYPE_SONET", "38":"IF_TYPE_MIO_X25", "33":"IF_TYPE_RS232", "32":"IF_TYPE_FRAMERELAY",
                  "31":"IF_TYPE_SIP", "30":"IF_TYPE_DS3", "37":"IF_TYPE_ATM", "36":"IF_TYPE_ARCNET_PLUS", "35":"IF_TYPE_ARCNET", "34":"IF_TYPE_PARA",
                  "60":"IF_TYPE_AFLANE_8025", "61":"IF_TYPE_CCTEMUL", "62":"IF_TYPE_FASTETHER", "63":"IF_TYPE_ISDN", "64":"IF_TYPE_V11", "65":"IF_TYPE_V36",
                  "66":"IF_TYPE_G703_64K", "67":"IF_TYPE_G703_2MB", "68":"IF_TYPE_QLLC", "69":"IF_TYPE_FASTETHER_FX", "2":"IF_TYPE_REGULAR_1822",
                  "6":"IF_TYPE_ETHERNET_CSMACD", "99":"IF_TYPE_MYRINET", "98":"IF_TYPE_ISO88025_CRFPRINT", "91":"IF_TYPE_TERMPAD", "90":"IF_TYPE_HOSTPAD",
                  "93":"IF_TYPE_X213", "92":"IF_TYPE_FRAMERELAY_MPI", "95":"IF_TYPE_RADSL", "94":"IF_TYPE_ADSL", "97":"IF_TYPE_VDSL", "96":"IF_TYPE_SDSL",
                  "11":"IF_TYPE_STARLAN", "10":"IF_TYPE_ISO88026_MAN", "13":"IF_TYPE_PROTEON_80MBIT", "12":"IF_TYPE_PROTEON_10MBIT", "15":"IF_TYPE_FDDI",
                  "14":"IF_TYPE_HYPERCHANNEL", "17":"IF_TYPE_SDLC", "16":"IF_TYPE_LAP_B", "19":"IF_TYPE_E1", "18":"IF_TYPE_DS1", "117":"IF_TYPE_GIGABITETHERNET",
                  "116":"IF_TYPE_TDLC", "48":"IF_TYPE_MODEM", "49":"IF_TYPE_AAL5", "46":"IF_TYPE_HSSI", "47":"IF_TYPE_HIPPI", "44":"IF_TYPE_FRAMERELAY_SERVICE",
                  "45":"IF_TYPE_V35", "42":"IF_TYPE_LOCALTALK", "43":"IF_TYPE_SMDS_DXI", "40":"IF_TYPE_X25_PLE", "41":"IF_TYPE_ISO88022_LLC", "1":"IF_TYPE_OTHER",
                  "5":"IF_TYPE_RFC877_X25", "9":"IF_TYPE_ISO88025_TOKENRING", "144":"IF_TYPE_IEEE1394", "145":"IF_TYPE_RECEIVE_ONLY", "142":"IF_TYPE_IPFORWARD",
                  "143":"IF_TYPE_MSDSL", "140":"IF_TYPE_DTM", "141":"IF_TYPE_DCN", "77":"IF_TYPE_LAP_D", "76":"IF_TYPE_ISDN_U", "75":"IF_TYPE_ISDN_S", "74":"IF_TYPE_DLSW",
                  "73":"IF_TYPE_ESCON", "72":"IF_TYPE_IBM370PARCHAN", "71":"IF_TYPE_IEEE80211", "70":"IF_TYPE_CHANNEL", "79":"IF_TYPE_RSRB", "78":"IF_TYPE_IPSWITCH"}

def load_registry_sids(reg_file):
    """Given Software hive find SID usernames"""
    sids = {}
    profile_key = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
    tgt_value = "ProfileImagePath"
    try:
        reg_handle = Registry.Registry(reg_file)
        key_handle = reg_handle.open(profile_key)
        for eachsid in key_handle.subkeys():
            sids_path = eachsid.value(tgt_value).value()
            sids[eachsid.name()] = sids_path.split("\\")[-1]
    except Exception as e:
        print(r"I could not open the specified SOFTWARE registry key. It is usually located in \Windows\system32\config.  This is an optional value.  If you cant find it just dont provide one.")
        print(("WARNING : ", str(e)))
        return {}
    return sids

def load_interfaces(reg_file):
    """Loads the names of the wireless networks from the software registry hive"""
#    print (reg_file)#
    try:
        reg_handle = Registry.Registry(reg_file)
    except Exception as e:
        print(r"I could not open the specified SOFTWARE registry key. It is usually located in \Windows\system32\config.  This is an optional value.  If you cant find it just dont provide one.")
        print(("WARNING : ", str(e)))
        return {}
    try:
        int_keys = reg_handle.open('Microsoft\\WlanSvc\\Interfaces')
    except Exception as e:
        print("There doesn't appear to be any wireless interfaces in this registry file.")
        print(("WARNING : ", str(e)))
        return {}
    profile_lookup = {}
    for eachinterface in int_keys.subkeys():
        if len(eachinterface.subkeys())==0:
            continue
        for eachprofile in eachinterface.subkey("Profiles").subkeys():
            profileid = [x.value() for x in list(eachprofile.values()) if x.name()=="ProfileIndex"][0]
            metadata = list(eachprofile.subkey("MetaData").values())
            for eachvalue in metadata:
                if eachvalue.name()=="Channel Hints":
                    channelhintraw = eachvalue.value()
                    hintlength = struct.unpack("I", channelhintraw[0:4])[0]
                    name = channelhintraw[4:hintlength+4]
                    profile_lookup[str(profileid)] = name.decode(encoding="latin1")
    return profile_lookup

def ole_date_bin_to_datetime(ole_date_bin):
    """
        Converts a OLE date from a binary 8 bytes little endian hex form to a datetime
    """
    #Conversion to OLE date float, where:
    # - integer part: days from epoch (1899/12/30 00:00) 
    # - decimal part: percentage of the day, where 0,5 is midday
    date_float = struct.unpack('<d', ole_date_bin)[0]
    date_decimal, date_integer = math.modf(date_float)
    date_decimal = abs(date_decimal)
    date_integer = int(date_integer)

    #Calculate the result
    res = datetime.datetime(1899, 12, 30) + datetime.timedelta(days=date_integer) #adding days to epoch
    res = res + datetime.timedelta(seconds = 86400*date_decimal) #adding percentage of the day
    return res

def blob_to_string(binblob):
    """Takes in a binary blob hex characters and does its best to convert it to a readable string.
       Works great for UTF-16 LE, UTF-16 BE, ASCII like data. Otherwise return it as hex.
    """
    try:
        chrblob = codecs.decode(binblob,"hex")
    except:
        chrblob = binblob
    try:
        if re.match(b'^(?:[^\x00]\x00)+\x00\x00$', chrblob):
            binblob = chrblob.decode("utf-16-le").strip("\x00")
        elif re.match(b'^(?:\x00[^\x00])+\x00\x00$', chrblob):
            binblob = chrblob.decode("utf-16-be").strip("\x00")
        else:
            binblob = chrblob.decode("latin1").strip("\x00")
    except:
        binblob = "" if not binblob else codecs.decode(binblob,"latin-1")
    return binblob
    
def BinarySIDtoStringSID(sid_str):
    #Original form Source: https://github.com/google/grr/blob/master/grr/parsers/wmi_parser.py
    """Converts a binary SID to its string representation.
     https://msdn.microsoft.com/en-us/library/windows/desktop/aa379597.aspx
    The byte representation of an SID is as follows:
      Offset  Length  Description
      00      01      revision
      01      01      sub-authority count
      02      06      authority (big endian)
      08      04      subauthority #1 (little endian)
      0b      04      subauthority #2 (little endian)
      ...
    Args:
      sid: A byte array.
    Returns:
      SID in string form.
    Raises:
      ValueError: If the binary SID is malformed.
    """
    if not sid_str:
        return ""
#    sid = codecs.decode(sid_str,"hex")
    sid = sid_str
    str_sid_components = [sid[0]]
    # Now decode the 48-byte portion
    if len(sid) >= 8:
        subauthority_count = sid[1]
        identifier_authority = struct.unpack(">H", sid[2:4])[0]
        identifier_authority <<= 32
        identifier_authority |= struct.unpack(">L", sid[4:8])[0]
        str_sid_components.append(identifier_authority)
        start = 8
        for i in range(subauthority_count):
            authority = sid[start:start + 4]
            if not authority:
                break
            if len(authority) < 4:
                raise ValueError("In binary SID '%s', component %d has been truncated. "
                         "Expected 4 bytes, found %d: (%s)",
                         ",".join([str(ord(c)) for c in sid]), i,
                         len(authority), authority)
            str_sid_components.append(struct.unpack("<L", authority)[0])
            start += 4
            sid_str = "S-%s" % ("-".join([str(x) for x in str_sid_components]))
    sid_name = sid_str
    return sid_name
#    sid_name = template_lookups.get("Known SIDS",{}).get(sid_str,'unknown')
#    return "{} ({})".format(sid_str,sid_name)

def Check_Column_Type(EsedbTable_Record, Column_Type, Column_Number, Record_List, convertSid):
    if (Column_Type == 0):   # Null
       return "NULL"
    elif (Column_Type == 1): #Boolean
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('NULL')
       else:
          return Record_List.append(str(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore')))	
    elif (Column_Type == 2): #INTEGER_8BIT_UNSIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))
    elif (Column_Type == 3): #INTEGER_16BIT_SIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 4): #INTEGER_32BIT_SIGNED	
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))
    elif (Column_Type == 5): #CURRENCY
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 6): #INTEGER_8BIT_UNSIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_floating_point(Column_Number))
    elif (Column_Type == 7): #DOUBLE_64BIT
       return Record_List.append(EsedbTable_Record.get_value_data_as_floating_point(Column_Number))	
    elif (Column_Type == 8): #DATETIME	
       #return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          #print (EsedbTable_Record.get_value_data(Column_Number))
          return Record_List.append(ole_date_bin_to_datetime(EsedbTable_Record.get_value_data(Column_Number)))
    elif (Column_Type == 9): #BINARY_DATA
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append("Blob Record that is not supported at this time")
          return Record_List.append(EsedbTable_Record.get_value_data(Column_Number))
    elif (Column_Type == 10): #TEXT	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          if convertSid:
              binString3 = EsedbTable_Record.get_value_data(Column_Number)
              binString2 = BinarySIDtoStringSID(EsedbTable_Record.get_value_data(Column_Number))
              return Record_List.append(BinarySIDtoStringSID(EsedbTable_Record.get_value_data(Column_Number)))
          else:
              return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
#          if (type(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore')) == unicode):
              #return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
    elif (Column_Type == 11): #LARGE_BINARY_DATA
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(EsedbTable_Record.get_value_data(Column_Number))
    elif (Column_Type == 12): #LARGE_TEXT	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          compressed_text = EsedbTable_Record.get_value_data(Column_Number)
          comp_text = compressed_text[1]
          if comp_text == 24:
             #print ("This text is EXPRESS Compressed")
             return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
          if comp_text >= 23:
              compressed_data_index = 0
              compressed_data = compressed_text
              uncompressed_data_index = 0
              compressed_data_size = len(compressed_data)
              value_16bit = 0
              bit_index = 0
              compressed_data_index = 1
              comp_data = 0
              uncompressed_data = []
              while compressed_data_index < compressed_data_size:
                  comp_data = compressed_data[compressed_data_index]
                  value_16bit |= comp_data << bit_index
                  uncompressed_data_index = uncompressed_data_index + 1
                  uncompressed_data.append(chr(value_16bit & 127))
                  value_16bit >>= 7
                  bit_index += 1
                  if bit_index == 7:
                      uncompressed_data_index = uncompressed_data_index + 1
                      uncompressed_data.append(chr(value_16bit & 127))
                      value_16bit >>= 7
                      bit_index = 0
                  compressed_data_index += 1

              last_char = uncompressed_data.pop()
              out = ('').join(uncompressed_data)
              return Record_List.append(out)
          return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
          # elif comp_text >= 23:
             #print ("This text is compressed using 7-bit")
             # compressed_data_index = 0
             # compressed_data = compressed_text
             # uncompressed_data_index = 0
             # compressed_data_size = len(compressed_data)
             # value_16bit = 0
             # bit_index = 0
             # compressed_data_index = 1
             # comp_data = 0
             # uncompressed_data = []
             # while compressed_data_index < compressed_data_size:
                # comp_data = (compressed_data[compressed_data_index])
                # value_16bit |= comp_data << bit_index
                # uncompressed_data_index = uncompressed_data_index + 1
                # uncompressed_data.append(chr(value_16bit & 0x7f))
                # value_16bit >>= 7
                # bit_index += 1
                # if bit_index == 7:
                   # uncompressed_data_index = uncompressed_data_index + 1
                   # uncompressed_data.append(chr(value_16bit & 0x7f))
                   # value_16bit >>= 7
                   # bit_index = 0
                # compressed_data_index += 1
             # last_char = uncompressed_data.pop()
             # out = "".join(uncompressed_data)
             # return Record_List.append(out) 
          # else:	
             # print ("This text is not compressed")
             # return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
    elif (Column_Type == 13): #SUPER_LARGE_VALUE
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 14): #INTEGER_32BIT_UNSIGNED	
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 15): #INTEGER_64BIT_SIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 16): #GUID	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(str(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore')))
    elif (Column_Type == 17): #INTEGER_16BIT_UNSIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
 
			  
def Parse_ESEDB_File(File_To_Parse):
   file_object = open(File_To_Parse, "rb")
   esedb_file = pyesedb.file()
   esedb_file.open_file_object(file_object)
   Num_Of_tables = esedb_file.get_number_of_tables()
   print ("The number of tables is ==> ", Num_Of_tables)
   SQLitedb.CreateTable('ESEDB_Master_Table','Tab_Name text')
   SQLitedb.CreateTable('ESEDB_Empty_Tables', 'Tab_Name Text')
   for i in range (0, Num_Of_tables):
       SQL_Statement = ''
       Table = esedb_file.get_table(i)
       Table_name = Table_Dict[Table.get_name()]
       Template_Name = Table. get_template_name()
       Table_Num_Columns = Table.get_number_of_columns()
       Table_Num_Records = Table.get_number_of_records()
       print ("Table Name is ==> ", Table_name)
       if (Table_Num_Records > 0):
          SQLitedb.InsertValues('ESEDB_Master_Table','Tab_Name', "'" + Table_name + "'")
          SQL_Statement = 'Create Temp Table '+ Table_name + '_Temp ('
          Table_Record = Table.get_record(0)
          Column_Name = Table_Record.get_column_name(0)
          Column_Type = Table_Record.get_column_type(0)
          SQLitedb.CreateTempTable(Table_name + '_Temp', SQLitedb.Check_SQL_Reserved_Word(Column_Name) + ' ' + Column_Dict[Column_Type])
          for x in range(1, Table_Num_Columns):
            Column_Name = Table_Record.get_column_name(x)
            Column_Type = Table_Record.get_column_type(x)
            SQL_Statement = SQL_Statement + ', ' + SQLitedb.Check_SQL_Reserved_Word(Column_Name) + '    ' + Column_Dict[Column_Type]
            SQLitedb.AddColumn(Table_name + '_Temp', SQLitedb.Check_SQL_Reserved_Word(Column_Name) + ' ' + Column_Dict[Column_Type])
          SQL_Statement = SQL_Statement + ');'
       else:
          SQLitedb.InsertValues('ESEDB_Empty_Tables','Tab_Name', "'" + Table_name + "'")
   esedb_file.close()

def Create_Permanent_Tables():

   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables)")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        print ("creating permanent " + str(Table_name), str(Table_name) + "_temp")
        SQLitedb.CreatePermanentTable(Table_name, str(Table_name) + "_temp")
   SQLitedb.DropTable('MSysObjects')
   SQLitedb.DropTable('MSysObjectsShadow')
   SQLitedb.DropTable('MSysObjids')
   SQLitedb.DropTable('MSysLocales')
   SQLitedb.DropTable('ESEDB_Master_Table')
   SQLitedb.DropTable('ESEDB_Empty_Tables')
   CreateView = 'create view Application_Execution as select timestamp ExecutionTime, idBlob ApplicationName, "SRU Network Usage" TableName from network_Usage, SruDbIdMapTable ' + \
                ' where appid = idIndex union select timestamp, idBlob, "Sru Application Resource Usage" TableName from Application_Resource_Usage, SruDbIdMapTable ' + \
                ' where appid = idIndex;'
   SQLitedb.UpdateTable(CreateView)
   CreateView = "create view exe_to_app as select substr(ltrim(IdBlob, '\Device\HarddiskVolume'), instr(ltrim(IdBlob, '\Device\HarddiskVolume'), '\\')) " + \
                " application_name, idBlob source_name from SruDbIdMapTable where idType = 0 and idBlob not like '!!%';"
   SQLitedb.UpdateTable(CreateView)

def Populate_ESEDB_DB(File_To_Parse):
   idType = None
   file_object = open(File_To_Parse, "rb")
   esedb_file = pyesedb.file()
   esedb_file.open_file_object(file_object)
   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables);")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        print ("Inserting into table " + str(Table_name))
        EsedbTable = esedb_file.get_table_by_name(Table_Rev_Dict[Table_Name[0]])

        for i in range(0,EsedbTable.get_number_of_records()):
           SQL_Bind_Values = []
           SQL_Statement_Table = 'Insert into ' + Table_Name[0] + '_temp'
           EsedbTable_Record = EsedbTable.get_record(i)
           EsedbTable_Num_Columns = EsedbTable.get_number_of_columns()
           Column_Name = EsedbTable_Record.get_column_name(0)
           SQL_Statement_Columns = SQLitedb.Check_SQL_Reserved_Word(Column_Name)
           SQL_Bind_Variables = SQLitedb.create_question_bind_variables(EsedbTable.get_number_of_columns())
           Column_Type = EsedbTable_Record.get_column_type(0)
           Check_Column_Type(EsedbTable_Record, Column_Type, 0, SQL_Bind_Values, False)
           idType = 0
           if Column_Name == 'IdType':
               idType = SQL_Bind_Values[len(SQL_Bind_Values) - 1]
           for x in range(1,EsedbTable.get_number_of_columns()):
               Column_Name = EsedbTable_Record.get_column_name(x)
               SQL_Statement_Columns = SQL_Statement_Columns + ',' + SQLitedb.Check_SQL_Reserved_Word(Column_Name)
               Column_Type = EsedbTable_Record.get_column_type(x)
               if Column_Name == 'IdBlob':
                  if idType == 3:
                     Check_Column_Type(EsedbTable_Record, 10, x, SQL_Bind_Values, True)
                  else:
                     Check_Column_Type(EsedbTable_Record, 10, x, SQL_Bind_Values, False)   
               else:
                  Check_Column_Type(EsedbTable_Record, Column_Type, x, SQL_Bind_Values, False)
           try:
               SQLitedb.InsertBindValues(Table_Name[0] + '_temp', SQL_Statement_Columns, SQL_Bind_Variables, SQL_Bind_Values)
           except:
               print ("SQL_Statement_Columns ==> " + SQL_Statement_Columns)
               print ("SQL_Bind_Variables ==> " + SQL_Bind_Variables)
               print ("SQL_Bind_Values ==> " + str(SQL_Bind_Values))

   esedb_file.close()

def Add_Application_Userids():

    # Select_Stmt = "select name, tbl_name, type from sqlite_master;"
    # All_Rows = SQLitedb.SelectAllRows(Select_Stmt)
    # luId = {}
    # for all_row in All_Rows:
    #     print(all_row)
    #     print(all_row[0] + " <<>> " + all_row[1] + " <<>> " + all_row[2])

    createIndex = "create index sruid on srudbidmaptable_temp (idindex)"
    SQLitedb.UpdateTable(createIndex)

    CreateView = 'create table userNames as select username, idIndex from srudbidmaptable_temp LEFT OUTER JOIN sids ON idblob = sid where idType = 3'
    SQLitedb.UpdateTable(CreateView)
    createIndex = "create index uid on userNames (idindex)"
    SQLitedb.UpdateTable(createIndex)

    for Table_name in Application_Table_List:
        try:
            SQLitedb.AddColumn(Table_name + "_temp", 'Application_Name text')
            SQLitedb.AddColumn(Table_name  + "_temp", 'User_Name Text')
            SQL_Update_1 = "Update " + Table_name + "_temp SET application_name = (SELECT idblob from srudbidmaptable_temp where appid = idindex)"
            SQLitedb.UpdateTable(SQL_Update_1)
            SQL_Update_2 = "Update " + Table_name + "_temp SET user_name = (select username from usernames where userid = idIndex)"
            SQLitedb.UpdateTable(SQL_Update_2)
        except:
           print ("Table does not exist ==> " + Table_name)

    SQLitedb.AddColumn('Network_Connectivity_temp', 'LUID_Name text')
    SQLitedb.AddColumn('Network_Connectivity_temp', 'Profile_Name Text')
    SQLitedb.AddColumn('Network_Usage_temp', 'LUID_Name text')
    SQLitedb.AddColumn('Network_Usage_temp', 'Profile_Name Text')

    SQLitedb.CreateTable("luidinterfaces_xref", "LUID text, LUIDName text , interface_luid text")
    Select_Stmt = "Select distinct interfaceLuid from Network_Connectivity_temp union all Select distinct interfaceLuid from Network_usage_temp"
    All_Rows = SQLitedb.SelectAllRows(Select_Stmt)
    for all_row in All_Rows:
        luid = struct.unpack(">H6B", codecs.decode(format(int(all_row[0]),'016x'),'hex'))[0]
        SQLitedb.InsertValues("luidinterfaces_xref", "interface_luid, LUID", '"' + str(all_row[0]) + '", "' + str(luid) + '"')
        #print (str(all_row[0]) + " <<>> " + str(luid))

    Update_Stmt = "update luidinterfaces_xref set luidname = (select luidName from luidinterfaces where LUID = luidinterfaces_xref.LUID)"
    SQLitedb.UpdateTable(Update_Stmt)

    SQL_Update_1 = "Update Network_Connectivity_temp SET LUID_name = (SELECT LUIDName from LUIDInterfaces_xref where interface_luid = InterfaceLuid)"
    SQLitedb.UpdateTable(SQL_Update_1)
    SQL_Update_2 = "Update Network_Connectivity_temp SET Profile_Name = (select ProfileName from interfaces where interfaces.L2ProfileId = Network_Connectivity_temp.L2profileId)"
    SQLitedb.UpdateTable(SQL_Update_2)
    SQL_Update_1 = "Update Network_Usage_temp SET LUID_name = (SELECT LUIDName from LUIDInterfaces_xref where interface_luid = InterfaceLuid)"
    SQLitedb.UpdateTable(SQL_Update_1)
    SQL_Update_2 = "Update Network_Usage_temp SET profile_name = (select ProfileName from interfaces where interfaces.L2ProfileId = Network_usage_temp.L2profileId)"
    SQLitedb.UpdateTable(SQL_Update_2)


def Post_Database_Processing():

   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables) and tab_name not like 'MSys%' and Tab_name not like 'Sru%';")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Date text')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_time text')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Time_Hour integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_time_Minute integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_time_Day_Of_Week integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_epochtime integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Date_Month text')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Date_Day Integer')
        SQL_Statement = "update " + Table_name + "_temp set SRUM_Write_Date = date(timestamp), " \
                             "SRUM_Write_Time = time(timestamp), SRUM_Write_Time_Hour = strftime('%H', timestamp), " \
                             "srum_Write_Time_Minute = strftime('%M', timestamp), srum_Write_Time_Day_Of_Week = " \
					         "(case when strftime('%w', timestamp) = '0' then 'Sunday' " \
                             "when strftime('%w', timestamp) = '1' then 'Monday' when strftime('%w', timestamp) = '2' then 'Tuesday' " \
                             "when strftime('%w', timestamp) = '3' then 'Wednesday' when strftime('%w', timestamp) = '4' then 'Thursday' " \
                             "when strftime('%w', timestamp) = '5' then 'Friday' when strftime('%w', timestamp) = '6' then 'Saturday' " \
                             "end), srum_Write_epochtime = strftime('%s', timestamp), srum_write_Date_Day = strftime('%d', timestamp);"
        #print (SQL_Statement)
        SQLitedb.UpdateTable(SQL_Statement)
        SQL_Statement = "update " + Table_name + "_Temp set SRUM_Write_Date_Month  = " \
	                         "(case when strftime('%m', timestamp) = '01' then 'January' " \
                             "when strftime('%m', timestamp) = '02' then 'February' " \
                             "when strftime('%m', timestamp) = '03' then 'March' " \
                             "when strftime('%m', timestamp) = '04' then 'April' " \
                             "when strftime('%m', timestamp) = '05' then 'May' " \
                             "when strftime('%m', timestamp) = '06' then 'June' " \
                             "when strftime('%m', timestamp) = '07' then 'July' " \
                             "when strftime('%m', timestamp) = '08' then 'August' " \
                             "when strftime('%m', timestamp) = '09' then 'September' " \
                             "when strftime('%m', timestamp) = '10' then 'October' " \
                             "when strftime('%m', timestamp) = '11' then 'November' " \
                             "when strftime('%m', timestamp) = '07' then 'December' end);"
        #print (SQL_Statement)
        SQLitedb.UpdateTable(SQL_Statement)

def getUserSids(SoftwareHive):
    SQLitedb.CreateTable("sids", "sid text, username text")
    userSids = load_registry_sids(SoftwareHive)
    userSidIds = userSids.keys()
    for userSidId in userSidIds:
        SQLitedb.InsertValues("sids", "sid, username", '"' + userSidId + '", "' + userSids[userSidId] + '"')
    knownSidIds = knownSids.keys()
    for knownSidId in knownSidIds:
        SQLitedb.InsertValues("sids", "sid, username", '"' + knownSidId + '", "' + knownSids[knownSidId] + '"')

def getInterfaces(SoftwareHive):
    SQLitedb.CreateTable("interfaces", "L2ProfileId text, ProfileName text")
    SQLitedb.CreateTable("LUIDInterfaces", "LUID text, LUIDName text")

    interfaces = load_interfaces(SoftwareHive)
    interfaceIds = interfaces.keys()
    for interfaceId in interfaceIds:
        SQLitedb.InsertValues("interfaces", "L2ProfileId, ProfileName", '"'+ interfaceId + '", "' + interfaces[interfaceId] + '"')

    LUIDInterfacesIds = LUIDInterfaces.keys()
    for LUIDInterfacesId in LUIDInterfacesIds:
        SQLitedb.InsertValues("LUIDInterfaces", "LUID, LUIDName", '"'+ LUIDInterfacesId + '", "' + LUIDInterfaces[LUIDInterfacesId] + '"')

args = sys.argv[1:]
File_To_Parse = args[0]
SoftwareHive = args[1]
SQLite_DB_Name = args[2]

SQLitedb = SQLiteDb()
SQLitedb.RemoveDB_File(SQLite_DB_Name)
SQLitedb.Open(SQLite_DB_Name)

getUserSids(SoftwareHive)
getInterfaces(SoftwareHive)

#print ("sids => " + str(sids))
#print ("interfaces => " + str(interfaces))

Parse_ESEDB_File(File_To_Parse)
Populate_ESEDB_DB(File_To_Parse)
#Post_Database_Processing()
Add_Application_Userids()
Create_Permanent_Tables()

SQLitedb.Close()

	