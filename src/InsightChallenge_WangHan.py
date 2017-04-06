#!/usr/bin/env python3
import re
from collections import Counter,defaultdict,deque
from datetime import datetime,timedelta
import os

OUTPUT_DIR = 'log_output'
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# a log object stores all information related to one single log
class Log(object):
	def __init__(self,key,host,time,httpMethod,resource,httpStatus,bandwidth,line):
		self.key = key
		self.host = host
		self.time = time
		self.httpMethod = httpMethod
		self.resource = resource
		self.httpStatus = httpStatus
		self.bandwidth = bandwidth
		self.line = line

class Node(object):
	def __init__(self,key,val):
		self.key = key
		self.val = val

class BEAnalytics(object):
	# import the input file. create a list of log objects.
	def importLog(self,fileName):
		with open(fileName,'r',encoding = 'iso-8859-15') as logObj:
			key = 0
			logList = []
			for s in logObj:
				key += 1
				host = s[0:s.find(' - - ')]
				time = datetime.strptime(s[s.find('[')+1:s.find(']')],'%d/%b/%Y:%H:%M:%S -0400')
				httpMethod = s[s.find('"')+1:s.find(' /')]
				resource = s[s.find(' /')+1:s.find('" ')].replace(' HTTP/1.0','')
				httpStatus = s[s.find('" ')+2:s.find('" ')+5]
				bandwidth = s[s.find('" ')+6:]
				try:
					bandwidth=int(bandwidth)
				except:
					bandwidth=0
				if len(host)!=0:
					logList.append(Log(key,host,time,httpMethod,resource,httpStatus,bandwidth,s))
			print('Total number of log:',len(logList))
			print('Import & extraction successful. Return logList to main()')
		return logList
	
	# get the top hosts. 	
	def getTopHost(self,logList):
		hostCnt = defaultdict(int)
		for log in logList:
			hostCnt[log.host]+=1
		topHost = self.topKFrequent(hostCnt,10)
		outputs = []
		for host in topHost:
			outputs.append('{},{}'.format(host[0], host[1]))
		with open(os.path.join(OUTPUT_DIR, 'hosts.txt'),'w+',encoding='iso-8859-15') as hostObj:
				hostObj.write('\n'.join(outputs))
		print('Get top 10 frequent host successfully. Saved in host.txt')
		
	# get the top resources that consume bandwidth the most
	def getTopResource(self,logList):
		resCnt = defaultdict(int)
		for log in logList:
			resCnt[log.resource] += log.bandwidth
		# print('Testing:',resCnt.most_common(10))
		topResource = self.topKFrequent(resCnt,10)
		outputs = []
		for res in topResource:
			outputs.append('{}'.format(res[0]))
		with open(os.path.join(OUTPUT_DIR, 'resources.txt'),'w+',encoding='iso-8859-15') as resObj:
				resObj.write('\n'.join(outputs))
		print('Get top 10 bandwidth-intensive resources successfully. Saved in resources.txt')
	
	# get the busiest 60 min window
	def getTopHour(self,logList):
		timeCnt = {}
		hourWdw = deque()
		timeFreq = defaultdict(int)
		for log in logList:
			timeFreq[log.time] += 1
			if hourWdw == deque():
				hourWdw.append(log)
			elif hourWdw[-1].time == log.time:
				continue
			elif hourWdw[-1].time < log.time < hourWdw[0].time+timedelta(minutes=60):
				hourWdw.append(log)
			elif log.time >= hourWdw[0].time+timedelta(minutes=60):
				# timeCnt[hourWdw[0].time] = log.key - hourWdw[0].keylist
				while hourWdw[0].time + timedelta(minutes=60) <= log.time:
					timeCnt[hourWdw[0].time] = log.key - hourWdw[0].key
					hourWdw.popleft()
				hourWdw.append(log)
		while hourWdw:
			timeCnt[hourWdw[0].time] = logList[-1].key - hourWdw[0].key + 1
			hourWdw.popleft()
		
		topHour = self.topKFrequent(timeCnt,10)
		topHourWin = set()
		
		for i in range(len(topHour)):
			curTime = topHour[i][0]
			topHourWin.add(topHour[i])
			tmp = curTime
			tmpWin = topHour[i][1]
			while tmp-timedelta(seconds=1)>logList[0].time and tmp-timedelta(seconds=1)not in topHourWin and (tmp - timedelta(seconds=1)) not in timeFreq:
				topHourWin.add((tmp - timedelta(seconds=1),tmpWin-timeFreq.get(tmp+timedelta(minutes=59,seconds=59),0)))
				tmp-=timedelta(seconds=1)
				tmpWin -= timeFreq.get(tmp+timedelta(minutes=59,seconds=59),0)
			tmp = curTime
			tmpWin = topHour[i][1]
			while tmp + timedelta(seconds=1)< logList[-1].time and tmp + timedelta(seconds=1) not in topHourWin and tmp + timedelta(seconds=1) not in timeFreq:
				topHourWin.add((tmp+timedelta(seconds=1),tmpWin-timeFreq.get(tmp,0)+timeFreq.get(tmp+timedelta(minutes=60),0)))
				tmpWin=tmpWin-timeFreq.get(tmp,0)+timeFreq.get(tmp+timedelta(minutes=60),0)
				tmp+=timedelta(seconds=1)

		topHourWin = sorted(topHourWin,key=lambda x:x[0])
		topHourWin = sorted(topHourWin,key=lambda x:x[1],reverse=True)

		outputs = []
		for i in range(10):
				outputs.append('{},{}'.format(topHourWin[i][0].strftime('%d/%b/%Y:%H:%M:%S -0400'),str(topHourWin[i][1])))
		with open(os.path.join(OUTPUT_DIR, 'hours.txt'),'w+',encoding='iso-8859-15') as hourObj:
			hourObj.write('\n'.join(outputs))
		print('Get top 10 busiest hour successfully. Saved in hours.txt')

	# get a list of blocked IP/hosts after 3 consecutive login failure
	def getBlocked(self,logList):
		blocked = []
		tmp = defaultdict(list)
		for log in logList:
			if log.host in tmp:
				if len(tmp[log.host])==3 and tmp[log.host][-1]<tmp[log.host][0]+timedelta(seconds=20) and log.time<=tmp[log.host][-1]+timedelta(minutes=5):
						blocked.append(log)
				elif log.httpStatus=='200' and 'login' in log.line:
					del tmp[log.host]
				elif log.httpStatus=='401' and 'login' in log.line:
					# print(tmp[log.host])
					while tmp[log.host] and log.time >= tmp[log.host][0] + timedelta(seconds=20):
						tmp[log.host].pop(0)
					tmp[log.host].append(log.time)
				else:
					continue
			else:
				if log.httpStatus=='401' and 'login' in log.line:
					tmp[log.host].append(log.time)
				else:
					continue

		outputs = [b.line for b in blocked]
		with open(os.path.join(OUTPUT_DIR, 'blocked.txt'),'w+',encoding='iso-8859-15') as blkObj:
			blkObj.write(''.join(outputs))
		print('Get blocked log successfully. Saved in blocked.txt')

	# get the top K frequent elements. return the sorted elements in descending order to the calling function
	def topKFrequent(self,cnt,k):
		heap = []
		indx = 0
		for key,val in cnt.items():
			node = Node(key,val)
			if indx != k:
				indx+=1
				self.heappush(heap,node)
			else:
				if heap[0].val<val:
					heap[0]=node
					self.heapify(heap,0,k)
		res = sorted([(node.key,node.val) for node in heap],reverse=True,key=lambda x:x[1])
		return res

	# a helper function for the topKFrequent. it pushes an element to a heap
	def heappush(self,heap,node):
		heap.append(node)
		nodeInd = len(heap)-1
		parentIndx = (nodeInd-1)//2
		while parentIndx >= 0 and heap[parentIndx].val>heap[nodeInd].val:
			self.swap(heap,parentIndx,nodeInd)
			nodeInd = parentIndx
			parentIndx = (parentIndx-1)//2

	# a helper function for the topKFrequent.
	def heapify(self,heap,indx,size):
		left = indx*2+1
		right = indx*2+2
		smallest = indx
		if left < size and heap[left].val < heap[smallest].val:
			smallest = left
		if right < size and heap[right].val < heap[smallest].val:
			smallest = right
		if smallest!=indx:
			self.swap(heap,indx,smallest)
			self.heapify(heap,smallest,size)
	
	# a helper function for the topKElement. it swap two elements on a heap.
	def swap(self,heap,indx1,indx2):
		heap[indx1],heap[indx2] = heap[indx2],heap[indx1]
	
	# main function
	def main(self):
		import sys
		fileName = sys.argv[1]
		logList = self.importLog(fileName)
		self.getTopHost(logList)
		self.getTopResource(logList)
		self.getTopHour(logList)
		self.getBlocked(logList)

if __name__ == '__main__':
	be = BEAnalytics()
	be.main()
