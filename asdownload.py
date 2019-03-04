#writed by 00239458

import requests
from bs4 import BeautifulSoup
import os
import sys
import time
from robobrowser import RoboBrowser


def getFileListPage(proxyFile, archive_url, fileListKeyWords):
    # 打开proxy文件获取proxy信息
    with open(proxyFile, 'r') as proxyFileHandle:
        line = proxyFileHandle.readline()
        proxyValue = line

    print(proxyValue)

    proxies = {
        "http": proxyValue,
    }
    try:
        browser = RoboBrowser(history=True, parser='html5lib')

        browser.open(archive_url, proxies=proxies)

        titles = browser.find_all('title')  # 获取head信息，跳到proxy确认的网页的title是'Huawei Proxy Notification'
                                            #文件list的title是'Directory Listing For /pkt2/'

        gotoWebPage = 'connectError'
        links = []
        successful = 0

        for title in titles:
            if 'Huawei Proxy Notification' in title.text:
                gotoWebPage = 'proxyPage'
            if 'Directory Listing' in title.text:
                gotoWebPage = 'fileList'
        print(title.text)

        if gotoWebPage == 'proxyPage':  #提交表单，类似在浏览器上点击按钮
            form = browser.get_form(action='/storePDStorage/')
            time.sleep(3)
            browser.open('http://www.internalrequests.org/showconfirmpage/?url='+archive_url,
                         proxies=proxies)

            form = browser.get_form(action='/storePDStorage/')

            time.sleep(3)
            browser.submit_form(form)
            time.sleep(3)
            browser.open(archive_url, proxies=proxies)
            links = browser.find_all('a')

        if gotoWebPage == 'fileList':
            links = browser.find_all('a')

        for link in links:
            if fileListKeyWords in link['href']:
                successful = 1
                break

        if 1 == successful:
            print("connect successful!\n")
            return 0
        else:
            print("connect failed!\n")
            return 1

    except:
        print("connect webpage failed!!")
        return 2



#下载文件到指定目录，并将下载结果写入到结果文件
#proxyFile: proxy文件
#dnfile_path: 下载后的文件存放的目录
#resultFile: 下载结果存放的目录，存储哪些文件已经下载了
#fileNumber: 一次最多下载的文件个数
#archive_url: 文件的网址
#fileList: 需要下载哪些文件
def asdnFile(proxyFile, dnfile_path, resultFile, fileNumber, archive_url, fileList, fileListKeyWords):

    downloadFileNumber = 0
    try:
        #打开proxy文件获取proxy信息
        with open(proxyFile, 'r') as proxyFileHandle:
            line = proxyFileHandle.readline()
            proxyValue = line

        proxies = {
            "http": proxyValue,
        }

        #打开下载结果文件
        resultFileHandle =  open(resultFile, 'r+')
        resultLines = resultFileHandle.readlines()

        #打开需要下载的文件列表
        fileListHandle =  open(fileList, 'r+')
        fileListLines = fileListHandle.readlines()

        for dstFile in fileListLines:
            if downloadFileNumber >= fileNumber:
                break

            fileAlreadyDn = 0
            # 判断该文件是否已经下载处理过了，result文件里面记录了已经被处理的文件
            for filett in resultLines:
                if filett == dstFile:
                    fileAlreadyDn = 1
                    break

            if fileAlreadyDn == 1:
                continue

            #开始获取网页信息，看网页是否可以连接成功
            getFileListPageResult = getFileListPage(proxyFile, archive_url, fileListKeyWords)
            if getFileListPageResult != 0:
                print("getFileListPage failed!!")
                return getFileListPageResult, downloadFileNumber

            #获取文件的url，准备开始下载文件
            file_url = archive_url + dstFile[:-1]
            print("fileurl: ", file_url)

            r = requests.get(archive_url, proxies=proxies)

            print("start download file: ", dstFile)
            # start: 开始下载文件
            r = requests.get(file_url, stream=True, proxies=proxies)  # 开始下载文件
            status = r.status_code
            total_size = 0
            if status == 200:
                total_size = int(r.headers['Content-Length'])

            if total_size < 100:
                print("download file failed!")
                return 3, downloadFileNumber   #文件下载大小不对

            file_name = dnfile_path + dstFile[:-1] + ".pcap"


            # 将文件写入本地
            with open(file_name, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024 * 100):
                    if chunk:
                        f.write(chunk)
            # end: 结束下载文件

            filesize = os.path.getsize(file_name)
            if (int(filesize / 1024 / 1024) < 900):
                print("mayby download error file!!", "file name: ", dstFile[:-1], "filesize: ", filesize)
                #time.sleep(2)
            else:
                print("download file successful, ", "file name: ", dstFile[:-1], "filesize: ", filesize)

            #time.sleep(90)

            downloadFileNumber = downloadFileNumber + 1
            # 将文件名写入result
            #resultFileHandle.write(dstFile)
            #resultFileHandle.flush()

        #resultFileHandle.flush()
        resultFileHandle.close()
        fileListHandle.close()

        return 0, downloadFileNumber
    except:
        print("download file failed!")
        return 4, 0

#只用于测试的代码
def main():
    rootPath = r"H:\wwm\dpi" + '\\'  # dpi的工作目录
    # 需要存放下载文件的目录
    pcap_base_dir = rootPath + r'file_proc\01_stream\test011' + '\\'
    dnfile_path = pcap_base_dir + 't001' + '\\'
    # 存放剥离PPPOE头部后的文件存储目录
    src_pcapfile_dir = pcap_base_dir + 't002' + '\\'
    pcap_temp_dir1 = pcap_base_dir + 'temp1' + '\\'
    pcap_temp_dir2 = pcap_base_dir + 'temp2' + '\\'

    dpiResultFile = rootPath + r'file_proc\04_msg_processed\Inspect_Flow_Report\test011_flow.txt'
    # dst_base_file_dir = r'D:\dpi\DPI_TEST\file_proc\01_stream\dst\rst'
    dst_base_file_dir = r'd:\dpi\dst\rst'
    downloadpcap_file_dir = r'd:\dpi\downloadpcap' + '\\'
    processFileNumberOneSchedule = 10
    fileListKeyWords = "wkby"

    archive_url = "http://183.233.91.188:8082/pkt/pkt4/"
    fileList = rootPath + r"file_proc\01_stream\filelist.txt"
    exefilePath = rootPath + r"file_proc\01_stream"

    proxyFile = rootPath + r"file_proc\01_stream\id.txt"
    resultFile = rootPath + r"file_proc\01_stream\result.txt"

    blacklistFile = rootPath + r'file_proc\01_stream\blacklist.txt'
    dstpcapile = rootPath + r'file_proc\01_stream\test011\t002' + '\\'
    testcaseFile = rootPath + r"file_proc\03_testcase.txt"

    #while 1:
    dnResult, downloadFileNumber = asdnFile(proxyFile, dnfile_path, resultFile, processFileNumberOneSchedule,
                                                       archive_url, fileList, fileListKeyWords)

    if dnResult != 0:
        print("download failed!")

if __name__ == '__main__':
    main()
