#对数据进行提取，原始数据为每个流的每个报文的信息，呈现格式为dir, time, length...
#在此程序里面会将流信息按照cell(比如1秒钟)进行信息提取，提取出该cell里面平均数及方差

import os
import math
import numpy as np
import time
from multiprocessing import Process,Queue
import random


threadnumber = 14

# 提取报文的信息，按照1s为分辨率提取数据
def extractdata (srcfile, dstfile):
    setupLinkFolder = r'F:\linksetupByUser_NO_DNS'
    localIP = srcfile.split('_')[-7]
    setuptime = int(srcfile.split('_')[-3])   #建立连接的时间
    setupLink = os.path.join(setupLinkFolder, localIP+'.txt')
    setupp = open(setupLink, 'r')
    setupline = setupp.readlines()
    setupNumber = 0

    #轮询每一行，得出该flow建立时间所在秒内建立的连接数
    for line in setupline:
        starttime = int(float(line.split('\t')[6]))
        if starttime == setuptime and line.split('\t')[0] == 'udp':
            setupNumber = setupNumber + 1

    dstfile = dstfile[:-4] + '_' + str(setupNumber) + '.txt'
    filep = open(srcfile, 'r')
    ofilep = open(dstfile, 'w')

    lines = filep.readlines()

    maxtime = float(lines[-1].split('\t')[1])
    inittime = float(lines[0].split('\t')[1])
    cnumber = int(math.ceil(maxtime - inittime))  # 按照秒时间 作为分辨率的刻度

    data = []
    length_data = []
    odata = []
    for i in range(cnumber):
        data.append({0: [], 1: [], 2: [], 3: []})  # 每个秒里面0存放下行时间间隔，1存放上行时间间隔，2存放下行报文长度，3存放上行报文长度
        odata.append([])

    lasttime = [inittime, inittime]

    # 先将数据提取出来按照秒存放
    for i in range(len(lines)):
        line = lines[i].split('\t')
        sid = int(float(line[1]) - inittime)
        length = int(line[2])
        interval = float(line[1]) - lasttime[int(line[0])]
        lasttime[int(line[0])] = float(line[1])
        interval = round(interval, 6)
        try:
            data[sid][int(line[0])].append(interval)  # line[0]为0表示下行，为1表示上行
            data[sid][int(line[0]) + 2].append(length)
        except Exception as e:
            print(len(data), sid, int(line[0]))
            print(srcfile)
            print(e)
            # quit()

    # 将每个刻度()里面的数据提取出来
    for i in range(cnumber):
        down_number = len(data[i][0])
        if down_number > 0:
            down_interval_av = round(float(np.average(np.array(data[i][0]))), 6)
            down_interval_std = round(float(np.std(np.array(data[i][0]))), 6)
            down_length_av = round(float(np.average(np.array(data[i][2]))), 6)
            down_length_std = round(float(np.std(np.array(data[i][2]))), 6)
            down_length_bytes = np.sum(np.array(data[i][2]))
        else:
            down_interval_av = 0
            down_interval_std = 0
            down_length_av = 0
            down_length_std = 0
            down_length_bytes = 0

        up_number = len(data[i][1])
        if up_number > 0:
            up_interval_av = round(float(np.average(np.array(data[i][1]))), 6)
            up_interval_std = round(float(np.std(np.array(data[i][1]))), 6)
            up_length_av = round(float(np.average(np.array(data[i][3]))), 6)
            up_length_std = round(float(np.std(np.array(data[i][3]))), 6)
            up_length_bytes = np.sum(np.array(data[i][3]))
        else:
            up_interval_av = 0
            up_interval_std = 0
            up_length_av = 0
            up_length_std = 0
            up_length_bytes = 0

        if (down_number > 0) & (up_number > 0):
            length_radio = round(float(down_length_bytes / up_length_bytes), 4)
            number_radio = round(down_number / up_number, 2)
            interval_radio = round(down_interval_av / (up_interval_av + 0.000001), 2)

        else:
            length_radio = 0
            number_radio = 0
            interval_radio = 0

        clist = [i, down_number, down_interval_av, down_interval_std, down_length_av, down_length_std,
                 down_length_bytes,
                 up_number, up_interval_av, up_interval_std, up_length_av, up_length_std, up_length_bytes, length_radio,
                 number_radio, interval_radio]

        odata[i] = clist

        temp = ''

        for kk in clist:
            temp = temp + str(kk) + '\t'
        temp = temp[:-1]+'\n'
        ofilep.write(temp)

    filep.close()
    ofilep.close()

#将报文信息提取出来
maxFileInFolder = 3000
def batchExtractFileName(srcTypeFolder, dstTypeFolder):
    filelist = []
    list2 = os.listdir(srcTypeFolder)
    list = []
    id = []

    for v in list2:
        if 'udp' in v:
            if int(v.split('_')[-1].split('.')[0])>1000:
                list.append(v)

    #如果没有超过最大个数，则直接选顺序号，如果超过了最大个数，则随机选择指定的个数
    if len(list)<= maxFileInFolder:
        id = range(len(list))
    else:
        id = [random.randint(0, len(list)) for _ in range(maxFileInFolder)]

    for i in range(len(id)):
        try:
            ifilepath = os.path.join(srcTypeFolder, list[id[i]-1])
            ofilepath = os.path.join(dstTypeFolder, list[id[i]-1])
            filelist.append((ifilepath, ofilepath))
        except Exception as e:
            print("list length= ", len(list), "i= ", i, "id length=", len(id), "id[i]=", id[i])
            print(e)
            quit()

    return filelist


def pprocessFile(filelist, threadId):
    for tt in range(len(filelist)):
        # try:
        extractdata(filelist[tt][0], filelist[tt][1])
        # except Exception as e:
        #     print('error......')
        #     print(e)
        #     continue
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
    allsrcfolder = r'f:\result5'
    alldstfolder = r'H:\wwm\dataudp2'
    typelistFile = r'F:\udptypelist.txt'

    typep = open(typelistFile, 'r')
    typelist = typep.readlines()

    fileNameList = []
    fileSplit = []
    for i in range(threadnumber):
        fileSplit.append([])

    list = os.listdir(allsrcfolder)
    for j in range(len(list)):
        if list[j]+'\n' not in typelist:
            continue
        print("process ", list[j], "......")
        allsp = os.path.join(allsrcfolder, list[j])
        alldp = os.path.join(alldstfolder, list[j])
        if not os.path.exists(alldp):
            os.mkdir(alldp)

        tlist = batchExtractFileName(allsp, alldp)
        fileNameList.extend(tlist)

    print("totol files: ", len(fileNameList))

    #将文件名分配到每个线程对应的list
    for kk in range(len(fileNameList)):
        fileSplit[kk%threadnumber].append(fileNameList[kk])

    for nn in range(threadnumber):
        print("thread ", nn, " have ", len(fileSplit[nn]), " files! ")

    print("start process file!")
    time.sleep(1)
    processFile_start(fileSplit)

def singleFileProcess():
    srcfolder = r'f:\result5\BitTorrent_DHT_Control' + '\\'
    filename = 'BitTorrent_DHT_Control_udp_10.11.5.164_0_69.197.158.130_0_1542144083_1542331215_4049.txt'
    dstfolder = 'H:\\wwm' + '\\'

    srcfile = os.path.join(srcfolder+filename)
    dstfile = os.path.join(dstfolder+filename)
    extractdata(srcfile, dstfile)

def main():
    # singleFileProcess()
    #batchExtractFileName(r'F:\result4\BitTorrent_Data_UDP', r'H:\wwm\wangzherongyao')
    batchProcess()

if __name__ == '__main__':
    main()
