# this hashing table is based off of a YouTube tutorial that I found at https://youtu.be/zHi5v78W1f0.
import re
import time

class Node:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None

class HashTable:
	
	def __init__(self):
		self.capacity = 50
		self.size = 0
		self.buckets = [None] * self.capacity
	
	def hash(self, key):
		hashsum = 0
		try:
			splitKey = key.split('.')
			splitKey[3].strip("\"")
			hashsum += int(splitKey[3])
		except ValueError:
   			pass      # or whatever
					
		hashsum = hashsum % self.capacity
		return hashsum
		
	def insert(self, key, value):
		self.size += 1
		index = self.hash(key)
		node = self.buckets[index]
		if node is None:
			self.buckets[index] = Node(key, value)
			return
		prev = node
		while node is not None:
			prev = node
			node = node.next
		prev.next = Node(key, value)
	
	def find(self, key):
		index = self.hash(key)
		node = self.buckets[index]
		while node is not None and node.key != key:
			node = node.next
		if node is None:
			return None
		else:
			return node.value
	
	def removeOld(self, key):
		index = self.hash(key)
		node = self.buckets[index]
		prev = node
		while node is not None and node.key != key:
			prev = node
			node = node.next
		if node is None:
			return False
		elif time.time() - node.value > 301:
			self.size -= 1
			result = node.value
			if prev is None:
				node = None
			else:
				prev.next = None
			return True
