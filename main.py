#!/usr/bin/env python
#-*- coding:utf-8 -*-
#  我真诚地保证：
#  我自己独立地完成了整个程序从分析、设计到编码的所有工作。
#  如果在上述过程中，我遇到了什么困难而求教于人，那么，我将在程序实习报告中
#  详细地列举我所遇到的问题，以及别人给我的提示。
#  在此，我感谢 XXX, …, XXX对我的启发和帮助。下面的报告中，我还会具体地提到
#  他们在各个方法对我的帮助。
#  我的程序里中凡是引用到其他程序或文档之处，
#  例如教材、课堂笔记、网上的源代码以及其他参考书上的代码段,
#  我都已经在程序的注释里很清楚地注明了引用的出处。

#  我从未没抄袭过别人的程序，也没有盗用别人的程序，
#  不管是修改式的抄袭还是原封不动的抄袭。
#  我编写这个程序，从来没有想过要去破坏或妨碍其他计算机系统的正常运转。
#  <马天波>

import scapy.all
import matplotlib.pyplot as plt
import numpy as np

#matplotlib显示中文
plt.rcParams['font.sans-serif']=['SimHei']
plt.rcParams['axes.unicode_minus']=False

#test2 ip
# client_ip = '60.176.45.15'
# server_ip = '115.239.134.25'

#test3 ip test4 ip
client_ip = '61.175.172.105'
server_ip = '115.239.134.25'

#打开pcapng文件
packets = scapy.all.rdpcap("test4.pcapng")
#tcp数据包列表
tcp_list = []
#三次握手列表
SYN = []
#四次挥手列表
FIN = []

#以IP地址为过滤条件 过滤出TCP包
for p in packets:
    if 'TCP' in p:
        if (p['IP'].src == client_ip and p['IP'].dst == server_ip) \
            or (p['IP'].dst == client_ip and p['IP'].src == server_ip):
            tcp_list.append(p)

#取出三次握手的包
for i in range(0,len(tcp_list)):
    if str(tcp_list[i]['TCP'].flags) == 'S':
        SYN.extend([tcp_list[i],tcp_list[i+1],tcp_list[i+2]])
        break

#取出四次挥手的包 （四次挥手有时会简化成三次挥手）
for i in range(0, len(tcp_list)):
    if str(tcp_list[i]['TCP'].flags) == 'FA':
        FIN.append(tcp_list[i])
        if str(tcp_list[i+1]['TCP'].flags) == 'FA':
            FIN.extend([tcp_list[i+1],tcp_list[i+2]])
        else:
            FIN.extend([tcp_list[i+1],tcp_list[i+2],tcp_list[i+3]])
        break

#获得端口号
client_port = SYN[0]['TCP'].sport
server_port = SYN[0]['TCP'].dport
SYN_CONTENT = []
FIN_CONTENT = []

#取出TCP中的seq、ack信息
for i in SYN:
    SYN_CONTENT.append({'seq':i['TCP'].seq,'ack':i['TCP'].ack})
for i in FIN:
    if str(i['TCP'].flags) == 'FA':
        FIN_CONTENT.append({'seq': i['TCP'].seq, 'ack': i['TCP'].ack, 'fin': 1})
    else:
        FIN_CONTENT.append({'seq': i['TCP'].seq, 'ack': i['TCP'].ack, 'fin': 0})

#画线
x = np.linspace(0, 2, 5)
y1 = x * (-1) + 6
_y1 = x + 4
y2 = x + 2
_y2 = x * (-1) + 4
y3 = x * (-1) + 2
_y3 = x + 2
y4 = x - 1
_y4 = x * (-1) + 1
y5 = x * (-1) - 1
_y5 = x - 3

plt.figure(figsize=(8,7.5))
plt.subplot(211)
plt.title("三次握手")
plt.plot(x, y1,color='#12CAFF')
plt.plot(x,y2,color='#1E58F2')
plt.plot(x,y3,color='#12CAFF')
plt.legend(['Client','Server'],loc = 'best')
#去掉横坐标值
plt.xticks([])
plt.ylim((-1, 7))
plt.yticks([2,6],['ACK','Connection\nrequest'])
plt.text(2.12,4,'Connection\ngranted')
plt.text(0,7,'Client\n'+client_ip+':'+str(client_port))
plt.text(1.5,7,'Server\n'+server_ip+':'+str(server_port))
plt.annotate('seq={} ack={} SYN=1'.format(SYN_CONTENT[0]['seq'],SYN_CONTENT[0]['ack']),xy=(0.8,5.2),xycoords='data')
plt.annotate('seq={} ack={} SYN=1'.format(SYN_CONTENT[1]['seq'],SYN_CONTENT[1]['ack']),xy=(0.2,3.2),xycoords='data')
plt.annotate('seq={} ack={} SYN=0'.format(SYN_CONTENT[2]['seq'],SYN_CONTENT[2]['ack']),xy=(0.8,1.2),xycoords='data')
#获取坐标轴
ax = plt.gca()
#隐藏上下坐标轴
ax.spines["top"].set_color('none')
ax.spines["bottom"].set_color('none')


plt.subplot(212)
plt.title("四次挥手")

#四次挥手可能会简化为三次挥手
if FIN[0]['IP'].src == client_ip and len(FIN) == 4:
    plt.plot(x,y1,color='#12CAFF')
    plt.plot(x,y2,color='#1E58F2')
    plt.plot(x,y4,color='#1E58F2')
    plt.plot(x,y5,color='#12CAFF')
    plt.yticks([6], ['Close'])
    plt.text(2.12, 1, 'Close')
    # 图例
    plt.legend(['Client', 'Server'], loc='best')
elif FIN[0]['IP'].src == server_ip and len(FIN) == 4:
    plt.plot(x, _y1, color='#1E58F2')
    plt.plot(x, _y2, color='#12CAFF')
    plt.plot(x, _y4, color='#12CAFF')
    plt.plot(x, _y5, color='#1E58F2')
    plt.yticks([1], ['Close'])
    plt.text(2.12, 6, 'Close')
    # 图例
    plt.legend(['Server', 'Client'], loc='best')
elif FIN[0]['IP'].src == client_ip and len(FIN) == 3:
    plt.plot(x, y1, color='#12CAFF')
    plt.plot(x, y2, color='#1E58F2')
    plt.plot(x, y3, color='#12CAFF')
    plt.yticks([6], ['Close'])
    plt.text(2.12, 4, 'Close')
    # 图例
    plt.legend(['Client', 'Server'], loc='best')
elif FIN[0]['IP'].src == server_ip and len(FIN) == 3:
    plt.plot(x, _y1, color='#1E58F2')
    plt.plot(x, _y2, color='#12CAFF')
    plt.plot(x, _y3, color='#1E58F2')
    plt.yticks([4], ['Close'])
    plt.text(2.12, 6, 'Close')
    # 图例
    plt.legend(['Server', 'Client'], loc='best')

#去掉横坐标值
plt.xticks([])
plt.ylim((-4, 7))
plt.text(0,7,'Client\n'+client_ip+':'+str(client_port))
plt.text(1.5,7,'Server\n'+server_ip+':'+str(server_port))
plt.annotate('seq={} ack={} FIN={}'.format(FIN_CONTENT[0]['seq'],FIN_CONTENT[0]['ack'],FIN_CONTENT[0]['fin']),xy=(0.6,5.4),xycoords='data')
plt.annotate('seq={} ack={} FIN={}'.format(FIN_CONTENT[1]['seq'],FIN_CONTENT[1]['ack'],FIN_CONTENT[1]['fin']),xy=(0.2,3.2),xycoords='data')
plt.annotate('seq={} ack={} FIN={}'.format(FIN_CONTENT[2]['seq'],FIN_CONTENT[2]['ack'],FIN_CONTENT[2]['fin']),xy=(0.2,0.2),xycoords='data')
try:
    plt.annotate('seq={} ack={} FIN={}'.format(FIN_CONTENT[3]['seq'],FIN_CONTENT[3]['ack'],FIN_CONTENT[3]['fin']),xy=(0.8,-1.8),xycoords='data')
except:
    pass

ax = plt.gca()
ax.spines["top"].set_color('none')
ax.spines["bottom"].set_color('none')

plt.subplots_adjust(hspace=0.5)
plt.show()