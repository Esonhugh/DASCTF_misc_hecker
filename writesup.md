# misc Hecker

[TOC]

## Main Route for CTFer

``` mermaid
flowchart TD;

	Status_Begin("
Wireshark dump file with traffic with ping transfer file and something with webshell interface in noise env")
	-->
	Status_1("find webshell interface and ping datas in file transfer")

	Status_1 
	-->
	Status_2("zip file extract ")
	-->
	Status_3("go bins (Strings conatin leaked compiled location in debug)") & Status_4("Jenkins Secrets")
	
	Status_3 --> Status_6("strings the bins file (No reverse it) and get git repo name and location about the web Sever")
	
	Status_4 --> Status_5("ssh key about git")
	
	Status_5 & Status_6 --> Status_7("Get file at Secrets github repo")
	--> Status_End("GET flag at source code commit")
	
	%% {{ Project on git contains source code SeverCode and flag }}

```

## 实战意义

出题目的过程其实是来源于我经历的一次渗透

日穿服务器之后信息收集 偷取源码或者go web binary

看到 Jenkins 和 CICD 之后 滥用它的 git 来获取源码与信息

strings 这步可能会有很多人没想到 

