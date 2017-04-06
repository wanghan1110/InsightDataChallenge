# Implementation Summary
The following four features are implemented for Insight Data Science challenge 2017.

### Feature 1: 
Data Structure: Hash table, heap

Time Complexity: O(N+klog(N)), k = 10 in our case

List the top 10 most active host/IP addresses that have accessed the site.

If any two hosts have same frequency, the host that have earlier 'first-time' access to server will rank first.


### Feature 2: 
Data Structure: Hash table, heap

Time Complexity: O(N+klog(N)), k = 10 in our case

Identify the 10 resources that consume the most bandwidth on the site

If any two resources consume same bandwidth, the resources that have earlier 'first-time' access by host will rank first.

### Feature 3:
Data Structure: double-ended queue, hash table

Time Complexity: O(N)

List the top 10 busiest (or most frequently visited) 60-minute periods 

If any two windows have same number of visits, the window that starts earlier will rank first.

### Feature 4: 
Data Structure: Hash table

Time Complexity: O(N)

Detect patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be 
blocked for 5 minutes. Log those possible security breaches.


# Implementation details
### Lanuage:
Python 3.6
