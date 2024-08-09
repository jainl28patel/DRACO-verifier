from argparse import ArgumentParser
import os
import re


def parseArguments():
  parser = ArgumentParser()
  parser.add_argument("-fd", "--first-directory", dest="first",
                      help="Absolute path to first directory of klee output", required=True)
  
  parser.add_argument("-sd", "--second-directory", dest="second",
                      help="Absolute path to second directory of klee output", required=True)

  return parser.parse_args()


def readInFiles(path):
  result = []
  with open(path, 'r') as fp:
    lines = fp.readlines()
  
  for line in lines:
    if line.isspace():
      continue
    vars = line.split(', ')
    temp = []
    for var in vars:
      if '}' in var:
        var = var.split('}')[0]
      if '{' in var:
        var = var.split('{')[1]

      var = var.strip()

      if (var != ""):
        temp.append(var)
      
    result.append(temp)
  return result


def getMaps(set1):
  maps = {}
  for elem in set1:
    if elem.startswith("map:"):
      map = elem.split("map:", 1)[1]
      mapName = map.split('.')[0]
      key = map.split('.')[1]
      if mapName in maps:
        maps[mapName].append(key)
      else:
        maps[mapName] = [key]
  return maps


def getByteValues(key, lastByteNum):
  # concrete key values are all integer and don't contain byte numbers
  if "b0" not in key:
    return getConcreteBytes(key, lastByteNum)
  byteValues = []
  
  values = re.split(r'b[0-9]+\(', key)[1:]
  byteValues = [ v[:-2] for v in values ]

  return byteValues

def getConcreteBytes(key, lastByteNum):
  hexValue = hex(int(key))[2:]
  bytes = []
  byteNum = 0
  for b in range(len(hexValue)-2, -1, -2):
    byte = "0x" + hexValue[b:b+2]
    byteVal = int(byte, 0)
    bytes.append(f"{byteVal}")
    byteNum += 1

  for b in range(byteNum, lastByteNum + 1):
    bytes.append(f"{0}")
  return bytes

def getLastByteNum(key):
  pos = key.rfind('b')
  lastIndex = key.rfind('(')
  keySize = int(key[pos+1:lastIndex])
  return keySize


def determineOverlap(set1, set2):
  '''
    Given two sets, determine the overlap of the two sets
    This treats maps specially, considering each byte of the key to the map,
    which may be symbolic.
  '''
  set1 = set(set1)
  set2 = set(set2)
  intersection = set1 & set2
  maps1 = getMaps(set1.difference(intersection))
  maps2 = getMaps(set2.difference(intersection))
  intersectingMaps = set(maps1.keys()) & set(maps2.keys())
  if (len(intersectingMaps) == 0):
    # No map was accessed by both programs
    # Hence we can just return the intersection
    return intersection
  
  # There were maps accessed by both programs
  # determine the keys to the maps that were accessed by both and find any
  # overlap, taking into account some bytes may be symbolic
  for intersectingMap in intersectingMaps:
    keys1 = maps1[intersectingMap]
    keys2 = maps2[intersectingMap]
    # determine the size of key to the map in number of bytes
    symbolicKeys = [ key for key in keys1 + keys2 if "b0" in key ]

    # if all the bytes of keys are concrete in both maps we can directly return
    # since there was no match earlier
    if not symbolicKeys:
      return intersection
    
    # Get the last byte number (number of bytes - 1)
    lastByteNum = getLastByteNum(symbolicKeys[0])
    
    keys1InBytes = [ getByteValues(key, lastByteNum) for key in keys1 ]
    keys2InBytes = [ getByteValues(key, lastByteNum) for key in keys2 ]

    for i in range(len(keys1InBytes)):
      for j in range(len(keys2InBytes)):
        currKeys1 = keys1InBytes[i]
        currKeys2 = keys2InBytes[j]
        assert(len(currKeys1) == len(currKeys2))
        same = True

        for k in range(len(currKeys1)):
          # If both bytes are concrete and not equal, then the keys are different
          if (currKeys1[k] != "sym" and 
              currKeys2[k] != "sym" and 
              currKeys1[k] != currKeys2[k]):
            same = False
            break
          # If at least one of the bytes is symbolic, or the concrete values are the same
          # then they could be equivalent

        if (same):
          # these keys could be the same, since there are symbolic bytes
          intersection.add(intersectingMap + "." + keys1[i])
  return intersection        


def readWriteSetAnalysis(program1Sets, program2Sets):
  readSet1 = program1Sets[0]
  readSet2 = program2Sets[0]
  writeSet1 = program1Sets[1]
  writeSet2 = program2Sets[1]

  foundOverlap = False
  r1w2 = determineOverlap(readSet1, writeSet2)
  # print(f"readset of 1 {readSet1}, writeset of 2 {writeSet2}")
  if r1w2:
    foundOverlap = True
    print("The variables that the first program reads and the second program writes overlap")
    print(f"These elements overlap: {r1w2}")

  # print(f"writeset of 1 {writeSet1}, readset of 2 {readSet2}")
  r2w1 = determineOverlap(writeSet1, readSet2)
  if r2w1:
    foundOverlap = True
    print("The variables that the first program writes and the second program reads overlap")
    print(f"These elements overlap: {r2w1}")
  
  w1w2 = determineOverlap(writeSet1, writeSet2)
  if w1w2:
    foundOverlap = True
    print("The variables that the first program writes and the second program writes overlap")
    print(f"These elements overlap: {w1w2}")
  
  if not foundOverlap:
    print("No overlap was found in the read and write sets of both programs")


if __name__ == "__main__":
  args = parseArguments()
  path1 = os.path.join(args.first, 'verification')
  path2 = os.path.join(args.second, 'verification')

  program1Sets = readInFiles(path1)
  program2Sets = readInFiles(path2)

  print(f"Read/Write set analysis on {path1} and {path2}")
  readWriteSetAnalysis(program1Sets, program2Sets)