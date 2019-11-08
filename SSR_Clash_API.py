# coding=utf-8
import sys
import flask_restful
import  base64
import  re
import  requests
import urllib3
import urllib
import urllib.parse
import json
import time
import api.qx
import api.loon
from flask import Flask,render_template,request
urllib3.disable_warnings()
aff = '获取失败 请检查订阅是否错误或者节点带特殊符号'

def safe_base64_decode(s): # 解码
    try:
        if len(s) % 4 != 0:
            s = s + '=' * (4 - len(s) % 4)
        base64_str = base64.urlsafe_b64decode(s)
        return bytes.decode(base64_str)
    except Exception as e:
        print('解码错误')   

def safe_base64_encode(s): # 加密
    try:
        return base64.urlsafe_b64encode(bytes(s, encoding='utf8'))
    except Exception as e:
        print('解码错误',e)

def Retry_request(url): #远程下载
    i = 0
    for i in range(3):
        try:
            header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36'}
            res = requests.get(url, headers=header, timeout=5, verify=False) # verify =false 防止请求时因为代理导致证书不安全
            if res.headers['Connection']!='close':
                flag=False
                return res.text
        except Exception as e:
            i = i+1
            print('重新下载：'+url)

def getnodeR(s):             #获取节点信息

    config = {
    "remark": "",
    "server": "0.0.0.0",
    "server_port": 8388,
    "password": "m",
    "method": "aes-128-ctr",
    "protocol": "auth_aes128_md5",
    "protocol_param": "",
    "obfs": "tls1.2_ticket_auth_compatible",
    "obfs_param": ""
    }

    #s = safe_base64_decode(ssr)
    spilted = re.split(':',s)  #将多个参数分离开来
    pass_param = spilted[5]
    pass_param_spilted = re.split('\/\?',pass_param)
    passwd = safe_base64_decode(pass_param_spilted[0]) #解码得到password
    try:
        obfs_param = re.search(r'obfsparam=([^&]+)',pass_param_spilted[1]).group(1)
    except:
        obfs_param=""
    try:
        protocol_param = re.search(r'protoparam=([^&]+)', pass_param_spilted[1]).group(1)
        protocol_param = safe_base64_decode(protocol_param)
    except:
        protocol_param = ''
    try:
        remarks = re.search(r'remarks=([^&]+)', pass_param_spilted[1]).group(1)
        remarks = safe_base64_decode(remarks)
    except:
        remarks = '' 

    config['remark'] = remarks
    config['server'] = spilted[0]
    config['server_port'] = int(spilted[1])
    config['password'] = passwd
    config['method'] = spilted[3]
    config['protocol'] = spilted[2]
    config['obfs'] = spilted[4]
    config['protocol_param'] = protocol_param
    config['obfs_param'] = obfs_param

    return config

def getrules():             # 自定义规则
    
    try:
        finalrules=[]
        
        with open("./root/SSRClash/config/general.yaml", "r",encoding = 'utf-8') as f:
            p_rule = f.read() + '\n'

        with open("./root/SSRClash/config/my.yaml", "r",encoding = 'utf-8') as f:
            l_rule = f.read()        
        
        Peoxies = 'Proxy:\n'
        finalrules.append(p_rule)
        finalrules.append(Peoxies)
        finalrules.append(l_rule)
        return finalrules
    except Exception as e:
        print(e)

def writeRules(sublink,selectfirst):    #策略组及规则
    try:
        other=[]           #节点名list
        tw=[]
        Peoxies = ''       #节点
        data = Retry_request(sublink)    #请求订阅        
        ssrdata=safe_base64_decode(data).strip().split('\n')              
        for i in range(len(ssrdata)):                                                   #遍历节点            
            ssrlink = safe_base64_decode(ssrdata[i].replace('ssr://','').replace('\r',''))
            nodeR = getnodeR(ssrlink)
            remark = nodeR['remark']                                
            if "30倍" in remark:  #用于剔除高倍率节点
                continue
            if nodeR['protocol_param'] == '' and  nodeR['obfs_param'] == '':    #判断是否为ssr
                if nodeR['method'] == 'none':
                    continue
                Json={ 'name': remark, 'type': 'ss', 'server': nodeR['server'], 'port': nodeR['server_port'], 'password':nodeR['password'] , \
                'cipher': nodeR['method'], 'protocol': nodeR['protocol'], 'obfs': nodeR['obfs'] }
            else:
                Json={ 'name': remark, 'type': 'ssr', 'server': nodeR['server'], 'port': nodeR['server_port'], 'password':nodeR['password'] , \
                  'cipher': nodeR['method'], 'protocol': nodeR['protocol'], 'protocolparam': nodeR['protocol_param'], 'obfs': nodeR['obfs'], 'obfsparam': nodeR['obfs_param'] }
            Peoxies +='- '+str(Json)+'\n'    #节点加加
            other.insert(0,remark)           #节点名list加加
            if "深台" in remark  or "彰化" in remark  or "新北" in remark or "台" in remark : tw.insert(0,remark)
        proxy = str(other)                   #节点名转化为字符串
        proxy1 = proxy[1:-1]                 #节点名字符串去掉中括号
        #'- { name: "延迟最低", type: "url-test", "proxies": ' + proxy + ', url: "http://www.gstatic.com/generate_204", interval: 600'+ '}\n'\
        if selectfirst == 'yes':             #是否修改代理模式默认顺序，默认为故障切换在前
            ProxyGroup='\n\nProxy Group:\n\n'\
                    '- { name: "PROXY", type: "select", "proxies": ' + proxy + '}\n'\
                    '- { name: "netflix", type: select, proxies: '+proxy+' }\n'\
                    '- { name: "line动画疯kk", type: select, proxies: ["PROXY", ' +str(tw)[1:]+' }\n'\
                    '- { name: "GlobalMedia", type: select, proxies: ["PROXY",'+proxy1+'] }\n'\
                    '- { name: "HKMTMedia", type: select, proxies: ["DIRECT","PROXY","PROXY"] }\n'\
                    '- { name: "Hijacking", type: select, proxies: ["REJECT", "DIRECT"] }\n'\
                    '- { name: "Apple", type: select, proxies: ["DIRECT", "PROXY"] }\n'\
                    '- { name: "白/黑名单", type: select, proxies: ["PROXY", "DIRECT"] }\n\n\n'\
                    'Rule:\n'
        else :
            ProxyGroup='\n\nProxy Group:\n\n'\
                    '- { name: "PROXY", type: "select", "proxies": ' + proxy + '}\n'\
                    '- { name: "netflix", type: select, proxies: '+proxy+' }\n'\
                    '- { name: "line动画疯kk", type: select, proxies: ["PROXY", ' +str(tw)[1:]+' }\n'\
                    '- { name: "GlobalMedia", type: select, proxies: ["PROXY",'+proxy1+'] }\n'\
                    '- { name: "HKMTMedia", type: select, proxies: ["DIRECT","PROXY","PROXY"] }\n'\
                    '- { name: "Hijacking", type: select, proxies: ["REJECT", "DIRECT"] }\n'\
                    '- { name: "Apple", type: select, proxies: ["DIRECT", "PROXY"] }\n'\
                    '- { name: "白/黑名单", type: select, proxies: ["PROXY", "DIRECT"] }\n\n\n'\
                    'Rule:\n'           
        rules = getrules()   #获取分流规则       
        currenttime = '# 更新时间为（看分钟就行，不知道哪个时区）：'+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+'\n' #获取更新时间
        content = currenttime+rules[0]+rules[1]+Peoxies+ProxyGroup+rules[2]
        return content

    except Exception as e:
            print (e)
            return aff

def getcustomssrlink(sublink, flagname):    #客制化ssr订阅
    try:   
        customssr = ''     #客制化节点组
        data = Retry_request(sublink)    #请求订阅        
        ssrdata=safe_base64_decode(data).strip().split('\n')  
        flags = flagname.split('@')     #拆分    
        for i in range(len(ssrdata)):    #遍历所有节点                                                 
            ssrlink = safe_base64_decode(ssrdata[i].replace('ssr://','').replace('\r',''))
            nodeR = getnodeR(ssrlink)
            remark = nodeR['remark']                                
            if "30倍" in remark:        #用于剔除高倍率节点
                continue
            for flag in flags:          #遍历节点匹配
                if flag == '' :         #滤掉无效匹配请求
                    continue
                if  flag.split('&')[0] in remark:   #节点是否匹配
                    if '&' in flag:                 #是否有与操作符
                        inremark = 1                #标志位，一组里有一个不匹配就为0，就不匹配
                        andflags = flag.split('&')  #拆分一组的多个匹配规则  @香港&1倍@美国     香港&1倍 为一组
                        for andflag in andflags:
                            if andflag == '':       #滤掉无效匹配请求
                                continue
                            else:
                                if andflag in remark:
                                    inremark = inremark * 1
                                else:
                                    inremark = 0  
                        if inremark == 1:           #标志位是否为1                      
                            customssr += ssrdata[i]+'\n'
                    else:                         #没有与操作符  
                        customssr += ssrdata[i]+'\n'
        customssr = safe_base64_encode(customssr)   #base64加密
        return customssr
    except Exception as e:
            return aff

def writeRulescustom(sublink,flagname,selectfirst):    #客制化策略组及规则
    try:
        #print(sublink + 'custom')
        other=[]
        tw=[]
        Peoxies = ''
        noderemark = ''      #用于剔除节点标准
        data = Retry_request(sublink)    #请求订阅        
        ssrdata=safe_base64_decode(data).strip().split('\n')  
        flags = flagname.split('@')
        #ssrdata = data.strip().replace('==','').split('\n')            
        for i in range(len(ssrdata)):          #遍历节点                                         #节点组            
            ssrlink = safe_base64_decode(ssrdata[i].replace('ssr://','').replace('\r',''))
            nodeR = getnodeR(ssrlink)
            remark = nodeR['remark']                                
            if "30倍" in remark:  #用于剔除高倍率节点
                continue
            for flag in flags:     #遍历分组匹配规则
                if flag == '':
                    continue
                if flag.split('&')[0] in remark:   #每组第一个匹配
                    if '&' in flag:                #每组是否有多个匹配要求   @香港&1倍@美国     适用 香港&1倍  
                        inremark = 1
                        andflags = flag.split('&')
                        for andflag in andflags:
                            if andflag == '':
                                continue
                            else:
                                if andflag in remark:
                                    inremark = inremark * 1
                                else:
                                    inremark = 0
                        if inremark == 1:
                            if remark in noderemark:
                                continue
                            else:
                                Json={ 'name': remark, 'type': 'ssr', 'server': nodeR['server'], 'port': nodeR['server_port'], 'password':nodeR['password'] , \
                                'cipher': nodeR['method'], 'protocol': nodeR['protocol'], 'protocolparam': nodeR['protocol_param'], 'obfs': nodeR['obfs'], 'obfsparam': nodeR['obfs_param'] }
                                noderemark += remark
                                Peoxies +='- '+str(Json)+'\n'
                                other.insert(0,remark)
                        else :
                            continue
                    else :                         #每组是否有多个匹配要求   @香港&1倍@美国     适用 美国这组
                        if nodeR['protocol_param'] == '' and  nodeR['obfs_param'] == '':
                            if nodeR['method'] == 'none':
                                continue
                            Json={ 'name': remark, 'type': 'ss', 'server': nodeR['server'], 'port': nodeR['server_port'], 'password':nodeR['password'] , \
                            'cipher': nodeR['method'], 'protocol': nodeR['protocol'], 'obfs': nodeR['obfs'] }
                            Peoxies +='- '+str(Json)+'\n'
                            other.insert(0,remark)
                        else:
                            if remark in noderemark:
                                continue
                            else:
                                Json={ 'name': remark, 'type': 'ssr', 'server': nodeR['server'], 'port': nodeR['server_port'], 'password':nodeR['password'] , \
                                'cipher': nodeR['method'], 'protocol': nodeR['protocol'], 'protocolparam': nodeR['protocol_param'], 'obfs': nodeR['obfs'], 'obfsparam': nodeR['obfs_param'] }
                                noderemark += remark
                                Peoxies +='- '+str(Json)+'\n'
                                other.insert(0,remark)
                                if "深台" in remark  or "彰化" in remark  or "新北" in remark or "台" in remark : tw.insert(0,remark)
                else:                              #每组第一个不匹配
                    continue

        proxy = str(other)
        proxy1 = proxy[1:-1]
        if selectfirst == 'yes':
            ProxyGroup='\n\nProxy Group:\n\n'\
                    '- { name: "PROXY", type: "select", "proxies": ' + proxy + '}\n'\
                    '- { name: "netflix", type: select, proxies: '+proxy+' }\n'\
                    '- { name: "line动画疯kk", type: select, proxies: ["PROXY", ' +str(tw)[1:]+' }\n'\
                    '- { name: "GlobalMedia", type: select, proxies: ["PROXY",'+proxy1+'] }\n'\
                    '- { name: "HKMTMedia", type: select, proxies: ["DIRECT","PROXY","PROXY"] }\n'\
                    '- { name: "Hijacking", type: select, proxies: ["REJECT", "DIRECT"] }\n'\
                    '- { name: "Apple", type: select, proxies: ["DIRECT", "PROXY"] }\n'\
                    '- { name: "白/黑名单", type: select, proxies: ["PROXY", "DIRECT"] }\n\n\n'\
                    'Rule:\n'
        else :
            ProxyGroup='\n\nProxy Group:\n\n'\
                    '- { name: "PROXY", type: "select", "proxies": ' + proxy + '}\n'\
                    '- { name: "netflix", type: select, proxies: '+proxy+' }\n'\
                    '- { name: "line动画疯kk", type: select, proxies: ["PROXY", ' +str(tw)[1:]+' }\n'\
                    '- { name: "GlobalMedia", type: select, proxies: ["PROXY",'+proxy1+'] }\n'\
                    '- { name: "HKMTMedia", type: select, proxies: ["DIRECT","PROXY","PROXY"] }\n'\
                    '- { name: "Hijacking", type: select, proxies: ["REJECT", "DIRECT"] }\n'\
                    '- { name: "Apple", type: select, proxies: ["DIRECT", "PROXY"] }\n'\
                    '- { name: "白/黑名单", type: select, proxies: ["PROXY", "DIRECT"] }\n\n\n'\
                    'Rule:\n'             
        rules = getrules()        
        currenttime = '# 更新时间为（看分钟就行，不知道哪个时区）：'+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+'\n'
        content = currenttime+rules[0]+rules[1]+Peoxies+ProxyGroup+rules[2]
        return content

    except Exception as e:
            return aff

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        sub = request.form['left']
        custom = urllib.parse.quote(request.form['custom'])
        Clash = 'http://127.0.0.1:10086/clashr/nameless?sublink='+str(sub)+'&selectfirst=no'
        if custom == '':
             CustomClash = '假设想要香港就@香港，假设想要香港的2倍节点就@香港&2倍。支持多个@即：@PCCW@CMHK@香港&2倍'
             CustomSSR =   '请填入想要的节点，同上'
        else:
            CustomClash = 'http://127.0.0.1:10086/clashr/nameless?sublink='+str(sub)+'&custom='+str(custom)+'&selectfirst=no'
            CustomSSR = 'http://127.0.0.1:10086/ssr/nameless?sublink='+str(sub)+'&custom='+str(custom)
        QX = 'http://127.0.0.1:10086/qx/nameless?sublink='+str(sub)+'&tag=stc'
        Loon = 'http://127.0.0.1:10086/loon/nameless?sublink='+str(sub)+'&tag=stc'
        return render_template('index.html', Clash = Clash,QX = QX,Loon=Loon,CustomClash = CustomClash,CustomSSR = CustomSSR,Custom =request.form['custom'] ,sub = sub)
    return render_template('index.html')

@app.route('/clashr/nameless', methods=['GET', 'POST'])
def clashapi():
    try:
        sub = request.args.get('sublink')
        #print(sub)
        try:
            arg = request.args.get('selectfirst')
        except Exception as e:
            arg = 'no'
        #print(arg)
        try:
            custom = request.args.get('custom')
        except Exception as e:
            custom = ''
        #print(custom)
        if custom == '' or custom == None :
            return writeRules(sub,arg)
        else :
            return  writeRulescustom(sub,custom,arg)
    except Exception as e:
        return '检测调用格式是否正确'+ aff

@app.route('/qx/nameless', methods=['GET', 'POST'])
def qxapi():
    try:
        sub = request.args.get('sublink')            
        #print(sub)
        tag=request.args.get('tag')
        #print(tag)
        return  api.qx.getqxrules(sub,tag)

    except Exception as e:
        return '请调用格式适合正确'

@app.route('/ssr/nameless', methods=['GET', 'POST'])
def ssrapi():
    try:
        sub = request.args.get('sublink')             
        #print(sub)
        custom=request.args.get('custom')
        #print(tag)
        return  getcustomssrlink(sub,custom)

    except Exception as e:
        return '检测调用格式是否正确'

@app.route('/loon/nameless', methods=['GET', 'POST'])
def loonapi():
    try:
        sub = request.args.get('sublink').replace('!','&')              
        #print(sub)
        tag=request.args.get('tag')
        #print(tag)
        return  api.loon.getrules(sub,tag)
    except Exception as e:
        return '请调用格式适合正确'
if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=False,port=10086)            #自定义端口
