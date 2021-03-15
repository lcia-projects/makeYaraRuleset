# Louisiana State Police / Louisiana Cyber Investigators Alliance
# makYaraRuleset.py : simple script that takes in a text file with one IoT per line and turns that into a Yara Rule
# makeYaraRuleSet:
# Usage: makeYaraRuleSet.py [-i inputfile] [-n rule name]
# Usage example:
#              python3 makeYaraRulesSet.py -i indicators.txt -n emotet-washington-county
# Output: MarchExchange0Day.yara
# rule MarchExchange0Day_rules:
# {
#
# 	 strings:
# 			$MarchExchange0Day_rules_1 = "8e90ed33c7ee82c0b64078ea36ec95f7420ba435c693b3b3dd728b494abf7dfc" fullword ascii
#             $MarchExchange0Day_rules_2 = "C:\\inetpub\\wwwroot\\aspnet_client\\Server.aspx" fullword ascii
#             $MarchExchange0Day_rules_3 = "123.12.11.153" fullword ascii
#     condition:
#  			any of them
#  }

import argparse
# --============================================--
# commandline arguments options
# --============================================--
parser = argparse.ArgumentParser(description='-- Simple Yara Rule Maker --', usage='makeYaraRuleSet.py [-i inputfile] [-n rule name] \n    Example: python makeYaraRulesSet.py -i indicators.txt -n emotet-washington-county ' , add_help=False)
parser.add_argument('-i','--input', help='input text filename, should be one entry per line with carrage return at end of each line', required=True )
parser.add_argument('-n','--name',  help='name of rule, will be used as the first part of each yarasearch term: example: Emotet-WashingtonCounty   : would be converted into $emotet-washintoncounty1', required=True)
parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
args = vars(parser.parse_args())
# --============================================--

# --============================================--
# Common Variables
# --============================================--
dataList=[]
strName=args['name']
counter=1
wordsToSkip=["MD5\n","svchost\n","Chrome\n","iexplore\n"]

fileReader=open(args['input'],"r")
writeFilename=strName + "_rules.yara"
fileWriter=open(writeFilename,"w")
data=fileReader.readlines()

for item in data:
    WriteFlag=True
    if item in dataList: #already in list, dont need a duplicate, so we skip and move on
        WriteFlag = False
        continue

    if item == "" or item =="\n": # if empty line
        WriteFlag = False
        continue

    for skipword in wordsToSkip: #catagory type lines, skip these
         if skipword in item:
             WriteFlag = False
             continue

    else: # item not in list, so we add it, we remove leading spaces and spaces at end
        if WriteFlag == True and (len(item)>1):
            item=item.lstrip() #remove spaces at beginning
            item=item.rstrip() #remove spaces at end

            if "HKCU" in item:  # remove anything before it
                testStrip = item
                stripresult = testStrip.find("HKCU")
                if stripresult != -1:
                    item = testStrip[stripresult:]
                    dataList.append(item)

            if "HKCR" in item:  # remove anything before it
                testStrip = item
                stripresult = testStrip.find("HKCR")
                if stripresult != -1:
                    item = testStrip[stripresult:]
                    dataList.append(item)

            else:
                item=item.replace("\\","\\\\")
                dataList.append(item)
# --============================================--
# Setting up to write output rules file
# --============================================--
strRuleName="rule " + strName + "\n" + "{" + "\n" + "\n" + "\t strings:" + "\n"
strRuleName.replace("$","")
fileWriter.write(strRuleName)

for item in dataList:
    if len(item) >1:
        line = '\t\t\t' + '$' + strName + '_' + str(counter) + ' = "' + item + '" fullword ascii \n'
        fileWriter.write(line)
        counter+=1

strClosingText = "\t condition: \n \t\t\tany of them \n }"
fileWriter.write(strClosingText)
fileWriter.close()
