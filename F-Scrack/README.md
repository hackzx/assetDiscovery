# F-Scrack

**F-Scrack** is a single file bruteforcer supports multi-protocol, no extra library requires except python standard library, which is ideal for a quick test.

Currently support protocol:
FTP, MySQL, MSSQL，MongoDB，Redis，Telnet，Elasticsearch，PostgreSQL.

Compatible with OSX, Linux, Windows, Python 2.6+.

## Usage ##
Options:

	python F-Scrack.py -h 192.168.1 [-p 21,80,3306] [-m 50] [-t 10]

	-h
	Supports ip(192.168.1.1), ip range (192.168.1) (192.168.1.1-192.168.1.254), ip list (ip.ini) , maximum 65535 ips per scan.
	-p
	Ports you want to scan, use comma to separate multi ports. Eg 1433,3306,5432. 
	Default scan ports(21,23,1433,3306,5432,6379,9200,11211,27017) if no ports specified.
	-m
	Number of threads. Default is 100.
	-t
	Seconds to wait before timeout.
	-d
	Dictionary file.
	-n
	Scan without ping scan(Live hosts detect).
	
Example:

	python F-Scrack.py -h 10.111.1
	python F-Scrack.py -h 192.168.1.1 -d pass.txt
	python F-Scrack.py -h 10.111.1.1-10.111.2.254 -p 3306,5432 -m 200 -t 6
	python F-Scrack.py -h ip.ini -n

**功能**  
	一款python编写的轻量级弱口令检测脚本，目前支持以下服务：FTP、MYSQL、MSSQL、MONGODB、REDIS、TELNET、ELASTICSEARCH、POSTGRESQL。  
**特点**  
	命令行、单文件，绿色方便各种情况下的使用。  
	无需任何外库以及外部程序支持，所有协议均采用socket与内置库进行检测。  
	兼容OSX、LINUX、WINDOWS，Python 2.6+(更低版本请自行测试，理论上均可运行)。  
**参数说明**  
	python F-Scrack.py -h 192.168.1 [-p 21,80,3306] [-m 50] [-t 10]  
	-h 必须输入的参数，支持ip(192.168.1.1)，ip段（192.168.1），ip范围指定（192.168.1.1-192.168.1.254）,ip列表文件（ip.ini），最多限制一次可扫描65535个IP。  
	-p 指定要扫描端口列表，多个端口使用,隔开 例如：1433,3306,5432。未指定即使用内置默认端口进行扫描(21,23,1433,3306,5432,6379,9200,11211,27017)  
	-m 指定线程数量 默认100线程  
	-t 指定请求超时时间。  
	-d 指定密码字典。  
	-n 不进行存活探测(ICMP)直接进行扫描。  
**使用例子**  
	python F-Scrack.py -h 10.111.1  
	python F-Scrack.py -h 192.168.1.1 -d pass.txt  
	python F-Scrack.py -h 10.111.1.1-10.111.2.254 -p 3306,5432 -m 200 -t 6  
	python F-Scrack.py -h ip.ini -n  
**特别声明**  
	此脚本仅可用于授权的渗透测试以及自身的安全检测中。  
	此脚本仅用于学习以及使用，可自由进行改进，禁止提取加入任何有商业行为的产品中。  
**效果图**  
![](https://sec-pic-ly.b0.upaiyun.com/img/161110/E87D5D68EC0B7E2AE3B813B4AC78740F1D1F2B4B.png)
