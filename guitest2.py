#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import *
import hashlib
import time
import rsa
import base64
# import pyperclip

LOG_LINE_NUM = 0
class MY_RSA():
    def __init__(self):
        pass
    def genkeypair(self):
        (pk,sk)=rsa.newkeys(1024)
        publickeybyte=pk.save_pkcs1()
        screcrtkeybyte=sk.save_pkcs1()
        self.pk=pk
        self.sk=sk
        #保存秘钥
        pfile=open('pkey','wb+')
        pfile.write(publickeybyte)

        pfile.close()

        sfile=open('skey','wb+')
        sfile.write(screcrtkeybyte)

        sfile.close()

    def loadkeypair(self):
        pfile=open('pkey','r')
        publickeybyte=pfile.read()
        pk=rsa.PublicKey.load_pkcs1(publickeybyte)

        pfile.close()

        sfile=open('skey','r')
        screcrtkeybyte=sfile.read()
        sk=rsa.PrivateKey.load_pkcs1(screcrtkeybyte)
        sfile.close()

        self.pk=pk
        self.sk=sk
    def loadrpk(self,rpk):
        self.rpk=rsa.PublicKey.load_pkcs1(rpk)
    def encryp(self,msg):
        msg_bytes=bytes(msg,"utf-8")
        msg_enc=rsa.encrypt(msg_bytes,self.rpk)
        msg_enc_b64=base64.b64encode(msg_enc)
        # print(msg_enc_b64)
        return msg_enc_b64
    def decrypt(self,msg_enc_b64):
        msg_enc=base64.b64decode(msg_enc_b64)
        print(msg_enc)
        msg_bytes=rsa.decrypt(msg_enc,self.sk)
        msg=str(msg_bytes,"utf-8")
        # print(msg)
        return msg
    def pkbyte(self):
        return self.pk.save_pkcs1()
    def skbyte(self):
        return self.sk.save_pkcs1()

class MY_GUI():
    def __init__(self, init_window_name):
        self.init_window_name = init_window_name
        self.rsa=MY_RSA()

    # 设置窗口

    def set_init_window(self):
        self.init_window_name.title("从runnoob上偷来的文本处理工具_v1.2")  # 窗口名
        # self.init_window_name.geometry('320x160+10+10')                         #290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name.geometry('1068x681+10+10')
        # self.init_window_name["bg"] = "pink"                                    #窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        # self.init_window_name.attributes("-alpha",0.9)                          #虚化，值越小虚化程度越高

        # 标签
        self.init_data_label = Label(self.init_window_name, text="你的公钥")
        self.init_data_label.grid(row=0, column=0)

        self.result_data_label = Label(self.init_window_name, text="显示私钥")
        self.result_data_label.grid(row=7, column=0)

        self.log_label = Label(self.init_window_name, text="接受公钥")
        self.log_label.grid(row=23, column=0)

        self.msg1_label = Label(self.init_window_name, text="待处理文本")
        self.msg1_label.grid(row=0, column=10)

        self.msg2_label = Label(self.init_window_name, text="处理后文本")
        self.msg2_label.grid(row=21, column=10)

        # 文本框
        # 你的公钥
        self.pk_Text = Text(self.init_window_name, width=65, height=6)
        self.pk_Text.grid(row=1, column=0, rowspan=6, columnspan=10)
        # 显示私钥

        self.sk_Text = Text(self.init_window_name, show='*',width=65, height=15)
        self.sk_Text.grid(row=8, column=0, rowspan=15, columnspan=10)
        # 接受的公钥
        self.rpk_Text = Text(self.init_window_name, width=65, height=6)
        self.rpk_Text.grid(row=24, column=0, columnspan=10)

        # 待处理文本
        self.msg1_Text = Text(self.init_window_name, width=65, height=20)
        self.msg1_Text.grid(row=1, column=10, columnspan=10, rowspan=20)
        # 处理后文本
        self.msg2_Text = Text(self.init_window_name, width=65, height=20)
        self.msg2_Text.grid(row=22, column=10, columnspan=10, rowspan=20)

        # 按钮
        self.genratekey = Button(self.init_window_name, text="生成公私钥",
                                 bg="lightblue", width=10, command=self.gen_keypair)
        self.genratekey.grid(row=31, column=0)

        self.loadkeypair = Button(self.init_window_name, text="加载公私钥",
                                 bg="lightblue", width=10, command=self.load_keypair)
        self.loadkeypair.grid(row=31, column=1)

        self.process = Button(self.init_window_name, text="处理!",
                                 bg="lightblue", width=16,height=2, command=self.process_text)
        self.process.grid(row=21, column=13)

        self.accpetpk = Button(self.init_window_name, text="接受公钥",
                                 bg="lightblue", width=16,height=2, command=self.accpet_pk)
        self.accpetpk.grid(row=23, column=1)


    # 功能函数
    def accpet_pk(self):
        rpk = self.rpk_Text.get(1.0,END)
        # print(rpk)

        self.rsa.loadrpk(rpk)
    def load_keypair(self):
        self.rsa.loadkeypair()
        self.pk_Text.delete(1.0, END)
        self.pk_Text.insert(1.0, self.rsa.pkbyte())
        self.sk_Text.delete(1.0, END)
        self.sk_Text.insert(1.0, self.rsa.skbyte())
        pass
    def gen_keypair(self):
        self.rsa.genkeypair()
        self.pk_Text.delete(1.0, END)
        self.pk_Text.insert(1.0, self.rsa.pkbyte())
        self.sk_Text.delete(1.0, END)
        self.sk_Text.insert(1.0, self.rsa.skbyte())
    def copypkto_clipboard(self):
        # pyperclip.copy("haha")
        pass
    def pasterskfrom_clipboard(self):
        # rpk=pyperclip.paste()
        rpk="asdf"
        pass
        self.rpk_Text.delete(1.0, END)
        self.rpk_Text.insert(1.0, rpk)
    def process_text(self):
        src = self.msg1_Text.get(1.0,END)
        print(src)
        if src:
            try:
                msg=self.rsa.decrypt(src)
                self.msg2_Text.delete(1.0, END)
                self.msg2_Text.insert(1.0, msg)
            except:
                msg=self.rsa.encryp(src)
                self.msg2_Text.delete(1.0, END)
                self.msg2_Text.insert(1.0, msg)


        pass
    def str_trans_to_md5(self):
        src = self.init_data_Text.get(
            1.0, END).strip().replace("\n", "").encode()
        #print("src =",src)
        if src:
            try:
                myMd5 = hashlib.md5()
                myMd5.update(src)
                myMd5_Digest = myMd5.hexdigest()
                # print(myMd5_Digest)
                # 输出到界面
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, myMd5_Digest)
                self.write_log_to_Text("INFO:str_trans_to_md5 success")
            except:
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, "字符串转MD5失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_md5 failed")

    def decrypt(self):
        src = self.init_data_Text.get(
            1.0, END).strip().replace("\n", "").encode()
        if src:
            try:
                myMd5 = hashlib.md5()
                myMd5.update(src)
                myMd5_Digest = b"asdf"
                # print(myMd5_Digest)
                # 输出到界面
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, myMd5_Digest)
                self.write_log_to_Text("INFO:str_trans_to_md5 success")
            except:
                self.result_data_Text.delete(1.0, END)
                self.result_data_Text.insert(1.0, "字符串转MD5失败")
        else:
            self.write_log_to_Text("ERROR:str_trans_to_md5 failed")
    # 获取当前时间

    def get_current_time(self):
        current_time = time.strftime(
            '%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        return current_time

    # 日志动态打印
    def write_log_to_Text(self, logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) + " " + str(logmsg) + "\n"  # 换行
        if LOG_LINE_NUM <= 7:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0, 2.0)
            self.log_data_Text.insert(END, logmsg_in)


def gui_start():
    init_window = Tk()  # 实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()  # 父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示


gui_start()
