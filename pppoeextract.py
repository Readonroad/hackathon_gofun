import dpkt
import os
import time
from multiprocessing import Process,Queue
import socket

pcapfilepath = r'D:\dpi\downloadpcap'
rstflename = 'test011_flow.txt'
threadnumber = 14

#提取dpi解析后的rst文件
def extractflow(rstfile):
    dictIPtuple = {}
    #打开dpi分析的结果文件，将该文件读取出来生成字典文件
    with open(rstfile, 'r', encoding='gb18030', errors='ignore') as txtFile:
        lines = txtFile.readlines()

    for line in lines[1:]:
        ss = line.split('\t')
        if (len(ss) < 14):  #非法长度
            continue
        # if int(ss[5])<100:
        #     continue
        #获得五元组
        IPtuple = ss[7].split(' ')  # IP四元组里面的数据由空格隔开了

        # 按照PORT大小来生成4元组,port1取大值
        if (int(IPtuple[10]) >= int(IPtuple[15])):
            ip1 = IPtuple[2]
            ip2 = IPtuple[6]
            port1 = int(IPtuple[10])
            port2 = int(IPtuple[15])
        else:
            ip1 = IPtuple[6]
            ip2 = IPtuple[2]
            port1 = int(IPtuple[15])
            port2 = int(IPtuple[10])

        # 开始建立key
        IPkey = (ip1, ip2, port1, port2)

        # 如果已经建立了对应的key，那么跳过这一个条目，否则建立对应的key-
        if (IPkey in dictIPtuple.keys()):
            dictIPtuple[IPkey][1] = dictIPtuple[IPkey][1] + int(ss[5])
            dictIPtuple[IPkey][2] = dictIPtuple[IPkey][2] + 1
            #print('append.')
            continue
        else:
            dictIPtuple[IPkey] = [ss[14], int(ss[5]), 1, ss[8]]

    return dictIPtuple

    #for k, v in dictIPtuple.items():
    #    #dictFile.write(str(k[0])+' '+str(k[1])+' '+str(k[2]) +' '+ str(k[3])+ ' '+str(v[0])+'\n')
    #    print(str(k[0])+' '+str(k[1])+' '+str(k[2]) +' '+ str(k[3])+ ' '+str(v[0])+' '+str(v[1])+' '+str(v[2]))


#将dpi结果文件读取出来，并在原始报文信息里面搜索每个flow建立的时间，将连接的建立时间保存到每个dstfolder的flowStartTime.txt
def getflowInfo(dstfolder, threadId):
    global  pcapfilepath, rstflename
    rstfile = os.path.join(dstfolder, rstflename)
    flowdict = extractflow(rstfile)

    logfile = os.path.join(dstfolder, 'log.txt')
    logp = open(logfile, 'r')
    filedesc = logp.readlines()
    files = []
    for line in filedesc:
        files.append('udp_'+line.split(' ')[2]+'.txt')  #获得文件名，因为pcap文件被提取出来后放在udp_xxxx.pcap.txt里面
        files.append('tcp_' + line.split(' ')[2] + '.txt')

    pktdict = {}
    i = 0

    for filename in files:
        print("process file: ", filename)
        if 'udp' in filename:
            pro = 'udp'
        else:
            pro = 'tcp'

        pcapfile = os.path.join(r'F:\aihu', filename)
        srcf = open(pcapfile, 'r')
        pktlines = srcf.readlines()
        i = 0
        for pktline in pktlines:
            pktinfo = pktline.split('\t')
            src = pktinfo[0]
            dst = pktinfo[2]
            sport = int(pktinfo[1])
            dport = int(pktinfo[3])

            #获得四元组的值，跟前面一样，port1为比较大的端口
            if (sport >= dport):
                port1 = sport
                port2 = dport
                ip1 = src
                ip2 = dst
            else:
                port1 = dport
                port2 = sport
                ip1 = dst
                ip2 = src

            IPkey = (ip1, ip2, port1, port2)

            # 如果没有找到对应的key，则建立该k,v，如果已经有了，则continue下一个报文
            if (IPkey not in pktdict.keys()):
                pktdict[IPkey] = [str(pktinfo[4]), 0, pro, str(pktinfo[4])]  #把首包的时间记录下来
            pktdict[IPkey][1] = pktdict[IPkey][1] + 1
            pktdict[IPkey][3] = pktinfo[4]

        srcf.close()

    flowStartTime = os.path.join(dstfolder, 'flowStartTime.txt')
    datafp = open(flowStartTime, 'w')

    for k, v in pktdict.items():
        k2 = (k[1], k[0], k[3], k[2])
        if k in flowdict:
            name = flowdict[k][0]
        elif k2 in flowdict:
            name = flowdict[k2][0]
        else:
            name = 'XXXX'

        pro = v[2]
        datafp.write(v[2] + '\t'+str(k[0])+'\t'+str(k[1])+'\t'+str(k[2]) +'\t'+ str(k[3])+ '\t'+str(name)+'\t'+str(v[0])+'\t'+str(v[3])+'\t'+str(v[1])+'\n')
    datafp.close()

#将dst下的每个目录下的flowStartTime.txt合并成一个大的flowStartTime.txt存放到dstFile
def mergeDpiRst():
    allFolder = r'D:\dpi\dst'
    dstFile = r'F:\flowStartTime.txt'
    list = os.listdir(allFolder)
    text = ''
    i = 0

    allFolderList = os.listdir(allFolder)

    for subFolder in allFolderList:
        i += 1
        if i%100:
            print("complete: ", round(float(i/len(allFolderList)),4)*100, "%")
        flowInfoPath = os.path.join(allFolder, subFolder)
        flowInfoPath = os.path.join(flowInfoPath, 'flowStartTime.txt')
        fp = open(flowInfoPath, 'r')
        text = text+fp.read()
        fp.close()
    outfp = open(dstFile, 'w')
    outfp.write(text)
    outfp.close()


#将汇总后的应用识别标签(加上了起始时间)进行再次汇总，将四元组重复的行合并
def sortSetupTime():
    ifilename = r'F:\flowStartTime.txt'
    outfile = r'F:\flowStartTime_sort.txt'
    pktdict = {}
    i = 0

    with open(ifilename, 'r') as f:

        for line in f:
            info = line.split('\t')
            i = i + 1
            if (i % 100000 == 0):
                print('i = ', i)
            IPkey = (info[1], info[2], info[3], info[4])

            # 如果没有找到对应的key，则建立该k,v，如果已经有了，则continue下一行
            if (IPkey not in pktdict.keys()):
                pktdict[IPkey] = [info[0], info[5], float(info[6]), float(info[7]), 0]  #分别是tcp/udp，type，starttime，endtime，number
            pktdict[IPkey][4] = pktdict[IPkey][4] + int(info[8])
            if (float(info[6]) < pktdict[IPkey][2]):
                pktdict[IPkey][2] = float(info[6])
            if (float(info[7]) > pktdict[IPkey][3]):
                pktdict[IPkey][3] = float(info[7])


    with open(outfile, 'w') as outf:
        for k, v in pktdict.items():
            if v[1] != 'NULL':
                if k[0].startswith('10.11'):
                    outf.write(
                        v[0] + '\t' + k[0] + '\t' + k[2] + '\t' + k[1] + '\t' + k[3] + '\t' + str(v[1]) + '\t' + str(
                            v[2]) + '\t' + str(v[3]) + '\t' + str(v[4]) + '\n')
                else:
                    outf.write(
                        v[0] + '\t' + k[1] + '\t' + k[3] + '\t' + k[0] + '\t' + k[2] + '\t' + str(v[1]) + '\t' + str(
                            v[2]) + '\t' + str(v[3]) + '\t' + str(v[4]) + '\n')

    f.close()
    outf.close()

#将建立连接的信息按照应用类型进行切割
def splitSetupTime():
    ifilename = r'F:\flowStartTime_sort.txt'
    allFolder = r'F:\linksetup2'
    pktdict = {}
    i = 0

    with open(ifilename, 'r') as f:
        for line in f:
            info = line.split('\t')
            i = i + 1
            if (i % 100000 == 0):
                print('i = ', i)
            keys = (info[1], info[5])   #通过用户IP+应用类型建立key

            #将建链信息添加到key对应的list里面
            if (keys not in pktdict.keys()):
                pktdict[keys] = []
            pktdict[keys].append(line)
    f.close()

    #将报文key对应的list信息输出到文件
    for k, v in pktdict.items():
        typepath = os.path.join(allFolder, k[1])
        if not os.path.exists(typepath):   #如果没有对应的文件夹，则建立文件夹
            os.mkdir(typepath)
        filePath = os.path.join(typepath, k[0]+'.txt')
        filep = open(filePath, 'w')
        for kk in v:
            filep.write(kk)
        filep.close()

# 将建链时间按照用户进行划分
def splitSetupTimeWithUser():
    ifilename = r'F:\flowStartTime_sort.txt'
    allFolder = r'F:\linksetupByUser'
    pktdict = {}
    i = 0

    with open(ifilename, 'r') as f:
        for line in f:
            info = line.split('\t')
            i = i + 1
            if (i % 100000 == 0):
                print('i = ', i)
            keys = info[1]  # 通过用户IP建立key

            # 将建链信息添加到key对应的list里面
            if (keys not in pktdict.keys()):
                pktdict[keys] = []
            pktdict[keys].append(line)
    f.close()

    # 将报文key对应的list信息输出到文件
    for k, v in pktdict.items():
        userfile = os.path.join(allFolder, k+'.txt')

        filep = open(userfile, 'w')
        for kk in v:
            filep.write(kk)
        filep.close()


# 将建链时间按照用户进行划分，并且过滤掉DNS报文
def splitSetupTimeWithUser_NO_DNS():
    ifilename = r'F:\flowStartTime_sort.txt'
    allFolder = r'F:\linksetupByUser_NO_DNS'
    pktdict = {}
    i = 0

    with open(ifilename, 'r') as f:
        for line in f:
            info = line.split('\t')
            i = i + 1
            if (i % 100000 == 0):
                print('i = ', i)
            keys = info[1]  # 通过用户IP建立key
            if info[5] == 'DNS':
                continue
            # 将建链信息添加到key对应的list里面
            if (keys not in pktdict.keys()):
                pktdict[keys] = []
            pktdict[keys].append(line)
    f.close()

    # 将报文key对应的list信息输出到文件
    for k, v in pktdict.items():
        userfile = os.path.join(allFolder, k + '.txt')

        filep = open(userfile, 'w')
        for kk in v:
            filep.write(kk)
        filep.close()

#获取分类文件夹下的dpi结果文件及log文件，根据log文件找到pcap文件，将pcap文件的每个报文读取出来后根据dpi结果打标签。
def getpcap(dstfolder, threadId):
    global  pcapfilepath, rstflename
    rstfile = os.path.join(dstfolder, rstflename)
    flowdict = extractflow(rstfile)

    logfile = os.path.join(dstfolder, 'log.txt')
    logp = open(logfile, 'r')
    filedesc = logp.readlines()
    files = []
    for line in filedesc:
        files.append(line.split(' ')[2])

    pktdict = {}
    i = 0

    for filename in files:
        print("process file: ", filename)
        pcapfile = os.path.join(pcapfilepath, filename)
        srcf = open(pcapfile, 'rb')
        pcap = dpkt.pcap.Reader(srcf)
        i = 0
        for ts, buf in pcap:
            i+=1
            if (i>120000000):
                break
            if (i%800000)==0:
                print("threadId: ",threadId, " processed：", int(float(i/12000000)*100), '%', filename)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.pppoe.ppp.ip
                src = str(ip.src[0])+'.'+str(ip.src[1])+'.'+str(ip.src[2])+'.'+str(ip.src[3])
                dst = str(ip.dst[0])+'.'+str(ip.dst[1])+'.'+str(ip.dst[2])+'.'+str(ip.dst[3])
                if ip.p == 6:
                    sport = ip.tcp.sport
                    dport = ip.tcp.dport
                    type = 'tcp'
                elif ip.p == 17:
                    sport = ip.udp.sport
                    dport = ip.udp.dport
                    type = 'udp'
                else:
                    continue

                #获得四元组的值，跟前面一样，port1为比较大的端口
                if (sport >= dport):
                    port1 = sport
                    port2 = dport
                    ip1 = src
                    ip2 = dst
                else:
                    port1 = dport
                    port2 = sport
                    ip1 = dst
                    ip2 = src

                IPkey = (ip1, ip2, port1, port2)

                if src.startswith('10.11'):
                    dir = '1'
                elif dst.startswith('10.11'):
                    dir = '0'
                else:
                    continue

                # 如果已经建立了对应的key，建立对应的key-，否则将报文加入list进去
                if (IPkey not in pktdict.keys()):
                    pktdict[IPkey] = []

                pktdict[IPkey].append(dir+'\t'+str(ts)+'\t'+str(ip.len)+'\t'+type)
            except Exception as e:
                #print(e)
                continue
        srcf.close()

    #根据该五元组在dpi里面的结果打上标签
    for k, v in pktdict.items():
        if k not in flowdict:
            continue
        name = flowdict[k][0]
        type = v[0].split('\t')[-1]
        starttime = int(float(v[0].split('\t')[1]))
        endtime = int(float(v[-1].split('\t')[1]))
        if k[0].startswith('10.11'):
            fn = str(k[0])+'_'+str(k[2])+'_'+str(k[1])+'_'+str(k[3])
        else:
            fn = str(k[1])+'_' + str(k[3])+'_' + str(k[0]) +'_'+ str(k[2])
        filename = name+'_'+type+'_'+fn+'_'+str(starttime)+'_'+str(endtime)+'_'+str(len(v))+'.txt'
        typepath = os.path.join(dstfolder, name)
        if not os.path.exists(typepath):
            os.mkdir(typepath)
        dataf = os.path.join(typepath, filename)
        if os.path.exists(dataf):
            continue
        datafp = open(dataf, 'w')
        for ll in v:
            linfo = ll.split('\t')
            datafp.write(linfo[0]+'\t'+linfo[1]+'\t'+linfo[2]+'\n')
        datafp.close()

# 从aihu里面获取报文信息并归类后存储，dstfolder目录为存放dpi结果的目录，将dpi下的文件解析后存放到另外的目录；
def getPktInfo(dstfolder, threadId):
    global  pcapfilepath, rstflename
    dFolder = r'F:\dst4'
    rstfile = os.path.join(dstfolder, rstflename)
    flowdict = extractflow(rstfile)
    dpath = dstfolder.split('\\')[-1]
    dpath = os.path.join(dFolder, dpath)
    if not os.path.exists(dpath):
        os.mkdir(dpath)

    logfile = os.path.join(dstfolder, 'log.txt')
    logp = open(logfile, 'r')
    filedesc = logp.readlines()
    files = []
    for line in filedesc:
        files.append('udp_'+line.split(' ')[2]+'.txt')  #获得文件名，因为pcap文件被提取出来后放在udp_xxxx.pcap.txt里面
        files.append('tcp_' + line.split(' ')[2] + '.txt')

    pktdict = {}
    i = 0

    for filename in files:
        print("process file: ", filename)
        if 'udp' in filename:
            pro = 'udp'
        else:
            pro = 'tcp'

        pcapfile = os.path.join(r'F:\aihunext', filename)
        srcf = open(pcapfile, 'r')
        pktlines = srcf.readlines()
        i = 0
        for pktline in pktlines:
            pktinfo = pktline.split('\t')
            src = pktinfo[0]
            dst = pktinfo[2]
            sport = int(pktinfo[1])
            dport = int(pktinfo[3])
            ts = pktinfo[4]
            lenp = int(pktinfo[5])

            #获得四元组的值，跟前面一样，port1为比较大的端口
            if (sport >= dport):
                port1 = sport
                port2 = dport
                ip1 = src
                ip2 = dst
            else:
                port1 = dport
                port2 = sport
                ip1 = dst
                ip2 = src

            IPkey = (ip1, ip2, port1, port2)

            if src.startswith('10.11'):
                dir = '1'
            elif dst.startswith('10.11'):
                dir = '0'
            else:
                continue

            # 如果已经建立了对应的key，建立对应的key-，否则将报文加入list里面
            if (IPkey not in pktdict.keys()):
                pktdict[IPkey] = []

            if pro == 'udp':
                pktdict[IPkey].append(dir + '\t' + str(ts) + '\t' + str(lenp) + '\t' + pro)
            if pro == 'tcp':
                pktdict[IPkey].append(dir + '\t' + str(ts) + '\t' + str(lenp) + '\t'+ pktinfo[6] +'\t'+pktinfo[7] +'\t'+pktinfo[8] +'\t'+pktinfo[9]+'\t' + pro)

        srcf.close()

    # 根据该五元组在dpi里面的结果打上标签
    for k, v in pktdict.items():
        i = i + 1
        if k not in flowdict:
            continue
        name = flowdict[k][0]
        if name == 'DNS':
            continue
        if i % 10000 == 0:
            per = round((i/len(pktdict)) * 100, 4)
            print('threadid:', threadId, 'complete percent: ', per, '%')


        type = v[0].split('\t')[-1]
        starttime = int(float(v[0].split('\t')[1]))
        endtime = int(float(v[-1].split('\t')[1]))
        if k[0].startswith('10.11'):
            fn = str(k[0]) + '_' + str(k[2]) + '_' + str(k[1]) + '_' + str(k[3])
        else:
            fn = str(k[1]) + '_' + str(k[3]) + '_' + str(k[0]) + '_' + str(k[2])
        filename = name + '_' + type + '_' + fn + '_' + str(starttime) + '_' + str(endtime) + '_' + str(len(v)) + '.txt'
        # typepath = os.path.join(dstfolder, name)

        typepath = os.path.join(dpath, name)
        if not os.path.exists(typepath):
            os.mkdir(typepath)
        dataf = os.path.join(typepath, filename)
        if os.path.exists(dataf):
            continue

        datafp = open(dataf, 'w')

        for ll in v:
            linfo = ll.split('\t')
            if type == 'udp':
                datafp.write(linfo[0] + '\t' + linfo[1] + '\t' + linfo[2] + '\n')
            else:
                datafp.write(linfo[0] + '\t' + linfo[1] + '\t' + linfo[2] + '\t' + linfo[3] + '\t' + linfo[4] + '\t' + linfo[5] + '\t' + linfo[6])
        datafp.close()


#提取pcap文件中的dns报文，并将dns信息存储到指定的目标文件里面
def extractDNS(dstfolder, dnsInfo):
    global pcapfilepath, rstflename
    rstfile = os.path.join(dstfolder, rstflename)
    flowdict = extractflow(rstfile)


    dnsdata = os.path.join(dstfolder, 'dns.txt')
    datafp = open(dnsdata, 'w')

    logfile = os.path.join(dstfolder, 'log.txt')
    logp = open(logfile, 'r')
    filedesc = logp.readlines()
    files = []
    for line in filedesc:
        files.append(line.split(' ')[2])

    for filename in files:
        print("process file: ", filename)
        pcapfile = os.path.join(pcapfilepath, filename)
        srcf = open(pcapfile, 'rb')
        pcap = dpkt.pcap.Reader(srcf)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.pppoe.ppp.ip
                src = str(ip.src[0])+'.'+str(ip.src[1])+'.'+str(ip.src[2])+'.'+str(ip.src[3])
                dst = str(ip.dst[0])+'.'+str(ip.dst[1])+'.'+str(ip.dst[2])+'.'+str(ip.dst[3])
                dns = dpkt.dns.DNS(ip.udp.data)
                dns_data = []
                if dns.rcode is dpkt.dns.DNS_RCODE_NOERR:
                    if dns.qr == 1:
                        if not dns.an:
                            dns_data.append(u'DNS Response: No answer for ')
                            dns_data.append(dns.qd[0].name)
                        else:
                            # Type of DNS answer.
                            for answer in dns.an:
                                if answer.type == 1:
                                    dns_data.append(u'DNS-A request ')
                                    datafp.write(str(ts)+'\t'+dst+'\t'+answer.name+'\t'+socket.inet_ntoa(answer.rdata)+'\n')
                                    # print(str(ts)+'\t'+dst+'\t'+answer.name+'\t'+socket.inet_ntoa(answer.rdata)+'\n')
                                    # dns_data.append(u' response: ')
                                    # print(socket.inet_ntoa(answer.rdata))

            except Exception as e:
                # print(e)
                continue
    datafp.close()


#将dst下的每个目录下的dns.txt合并成一个大的dns.txt存放到dstFile
def mergeDNSRst():
    allFolder = r'D:\dpi\dst'
    dstFile = r'F:\DNS.txt'
    list = os.listdir(allFolder)
    text = ''
    i = 0

    allFolderList = os.listdir(allFolder)

    for subFolder in allFolderList:
        i += 1
        if i%100:
            print("complete: ", round(float(i/len(allFolderList)),4)*100, "%")
        flowInfoPath = os.path.join(allFolder, subFolder)
        flowInfoPath = os.path.join(flowInfoPath, 'flowStartTime.txt')
        fp = open(flowInfoPath, 'r')
        text = text+fp.read()
        fp.close()
    outfp = open(dstFile, 'w')
    outfp.write(text)
    outfp.close()


#将原始IP字符串转换到另外一串字符串，算法如下
def mapping(aa):
    cc = ''
    for i in range(len(aa)):
        cc = cc + chr(ord(aa[i])-ord('0')+ord('a')+i)
    return cc

#还原出IP字符串
def unmapping(cc):
    aa = ''
    for i in range(len(cc)):
        aa = aa + chr(ord(cc[i])-ord('a')+ord('0')-i)
    return aa

#将数据匿名化
def mappingData():
    src = r'F:\flowStartTime_sort.txt'
    dst = r'F:\flowStartTime_sort_mapping.txt'

    i = 0
    with open(dst, 'w') as ff:
        with open(src, 'r') as f:
            for line in f:
                i = i + 1
                if (i % 100000) == 0:
                    print(i)
                # print(line)
                info = line.split('\t')
                cc = mapping(info[1])
                # print(info[0]+'\t'+cc+'\t'+info[2]+'\t'+info[3]+'\t'+info[4]+'\t'+info[5]+'\t'+info[6]+'\t'+info[7]+'\n')
                ff.write(
                    info[0] + '\t' + cc + '\t' + info[2] + '\t' + info[3] + '\t' + info[4] + '\t' + info[5] + '\t' +
                    info[6] + '\t' + info[7] + '\t' + info[8] + '\n')


def pprocessFile(filelist, threadId):
    for tt in range(len(filelist)):
        try:
            #getpcap(filelist[tt], threadId)
            getPktInfo(filelist[tt], threadId)
            #getflowInfo(filelist[tt], threadId)
            #extractDNS(filelist[tt], threadId)
        except:
            print('error......')
            continue
        if (tt%100 == 0):
            print("thread ", threadId, ' complete percent: ', round(float(tt/len(filelist)), 4)*100, '%')

# 采用多进程进行文件处理
def processFile_start(fileNameList):
    p = []
    for i in range(threadnumber):
        print("start thread ", i)
        pt = Process(target=pprocessFile, args=(fileNameList[i], i))
        p.append(pt)
        p[i].start()
    for pt in p:
        pt.join()


def batchProcess():
    allsrcfolder = r'f:\dstnext\dst'

    fileNameList = []
    fileSplit = []
    for i in range(threadnumber):    #线程数
        fileSplit.append([])

    folderList = os.listdir(allsrcfolder)

    print("totol folders: ", len(folderList))

    #将文件名分配到每个线程对应的list
    for kk in range(len(folderList)):
        fileSplit[kk%threadnumber].append(os.path.join(allsrcfolder, folderList[kk]))    #每个线程存储对应的名称

    for nn in range(threadnumber):
        print("thread ", nn, " have ", len(fileSplit[nn]), " files! ")

    print("start process file!")
    time.sleep(1)
    processFile_start(fileSplit)

def main():
    rstfile = r'D:\dpi\dst\rst20181124022643'
    pcafile = r'D:\dpi\downloadpcap\wkby4.pcap1600.pcap'
    dst = r'D:\dpi\dst2\rst20181110111401\LOL'
    #delRepeatFile(dst, 1)
    tcpfile = r'H:\tcp.txt'
    udpfile = r'H:\udp.txt'
    dnspcap = r'H:\wwm\dns.pcap'
    dnsinfo = r'h:\dnsinfo.txt'

    #getpcap(rstfile, 0)
    #getPktInfo(rstfile, 0)
    #getflowInfo(rstfile, 1)
    batchProcess()
    #mergeDpiRst()
    #extractpcap(pcafile, tcpfile, udpfile, 1)
    #sortSetupTime()
    #splitSetupTime()
    #splitSetupTimeWithUser()
    #splitSetupTimeWithUser_NO_DNS()
    #extractDNS(pcafile, dnsinfo)
    #mergeDNSRst()

if __name__ == '__main__':
    main()
