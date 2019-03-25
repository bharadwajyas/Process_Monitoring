#!/usr/bin/env python

import sys
if sys.version_info[0] >= 3:
    import PySimpleGUI as sg
else:
    import PySimpleGUI27 as sg
import os
import signal
import psutil
import operator
import subprocess
import hashlib, requests
import webbrowser
import datetime
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
'''
def Form(processes_to_select):
    layout = [[sg.Text('To get a Verbose Output about the Process Select the Show Option!\nTo Submit the Hash to VirusTotal please Select the  Submit Option!')],
        [sg.RButton('Show',pad=(5,5)),sg.RButton('Submit',pad=(5,5))]]

    window = sg.Window('Form').Layout(layout)

    while (True):
        try:
            bu, val = window.Read()

            if 'Mouse' in bu or 'Control' in bu or 'Shift' in bu:
                    continue
                 #--------- Do Button Operations --------


            if bu == 'Show':
               for process in processes_to_select:
                    pid = "The Pid of the Selected Process : {0}".format(process.pid)
                    name = "The Name of the Selected Process : {0}".format(process.name())
                    cpu_percent = "The CPU Utilization of the Selected Process : {0}".format(process.cpu_percent(interval=None))
                    try :
                        abs_path = "The Absolute Path of the Selected Process : {0}".format(process.cwd())
                        path = "The Path of the Selected Process : {0}".format(process.exe())
                    except :
                        abs_path = "The Absolute Path of the Selected Process : ' ' "
                        path = "The Path of the Selected Process :  ' ' "

                    sg.Popup('The Process Detail of PID is : ', pid, name, cpu_percent, abs_path, path, '.................')

            elif bu == 'Submit':
                sg.Popup('Submitting the hash to virustotal API :','','Loading........','','Results are: .......')
            if val is None:
                break
        except:
            break

def submit_form(processes_to_select):
    layout = [[sg.Text('Submitting the Hash to the Virustotal(Only 4 Request is allowed in 1 min)')],
              [sg.Listbox(values=display_list, size=(150, 45), select_mode=sg.SELECT_MODE_EXTENDED, text_color = "darkblue", font=('Courier', 10))],
              [sg.RButton('Open Virustotal')]]
    window = sg.Window('Submit The File to Virustotal').Layout(layout)
    for proc in processes_to_select:
        pid = int(proc[0:5])
        p = psutil.Process(pid)
        name = p.name()
        status = p.status()
        username = p.username()
        try:
            path = p.exe()
            abs_path = p.cwd()
        except:
            path = ""
            abs_path = ""
        BUF_SIZE = 65536
        if len(path) == 0:
            pass
        else:
            md5 = hashlib.md5()
            file = path.encode("unicode_escape")
            try:
                with open(file, 'rb') as f:
                    while True:
                        data = f.read(BUF_SIZE)
                        if not data:
                            break
                        md5.update(data)
                    hash = md5.hexdigest()


            except:
                pass
            params = {
                'apikey': "b8acfc47cf0cd9d6bb515722f5c4dad6739f4e1a9669241e39d56d46e2675abb",
                'resource': hash
            }

            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            json_response = response.json()

'''

def uploadForm():

    window_rows = [[sg.Text('Upload the file')],
                   [sg.InputText(), sg.FileBrowse()],
                   [sg.Submit(), sg.RButton('Open Virustotal')]
                   ]

    window = sg.Window('Upload The File to Virustotal').Layout(window_rows)
    while (True):
        button, values = window.Read()

        # if event is None or event == 'Exit':
        #     return
        # print('Event = ', event)

        if 'Mouse' in button or 'Control' in button or 'Shift' in button:
            continue
        # --------- Do Button Operations --------
        if values is None or button == 'Exit':
            break
        elif button == "Submit":
            path = values[0]
            BUF_SIZE = 65536
            if len(path) == 0:
                pass
            else:
                md5 = hashlib.md5()
                file = path.encode("unicode_escape")
                try:
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                except:
                    pass
                params = {
                    'apikey': "YOUR_API_Key",
                    'resource': hash
                }

                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                j_response = response.json()
                if len(j_response) == 0:
                    total_scan = j_response['total']
                    positives = j_response['positives']
                    sha256 = j_response['sha256']
                else:
                    total_scan = ""
                    positives = ""
                    sha256 = ""
                # scan_date = j_response['scan_date']
            sg.Popup('File Path : {0}'.format(values[0]), \
                     'Hash(MD5) of the File : {0}'.format(hash), \
                     'Hash(SHA256) of the File : {0}'.format(sha256), \
                     'No. of Scans by Virustotal : {0}'.format(total_scan), \
                     'No. of Positives found : {0}'.format(positives)
                     )


def MapForm(latitude,longitude):

    layout = [[sg.Text('LATITUDE  ='+str(latitude)+'\n\nLONGITUDE = '+str(longitude)+'\t\t\t\t')],
              [sg.RButton('OK'),sg.RButton('BROWSE',pad=((25,3),3))]]

    #sg.Popup('LATITUDE  =  37.7913838 \n LONGITUDE = -79.44398934', sg.Window('Next Form').Layout(layout))

    window=sg.Window('Maps').Layout(layout)
    b, v = window.Read()

def FirstForm():

    layout = [sg.RButton('Ok'),sg.RButton('Result',pad=((25,3),3))]

    #sg.Popup('LATITUDE  =  37.7913838 \n LONGITUDE = -79.44398934', sg.Window('Next Form').Layout(layout))

    window=sg.Window('Submit').Layout(layout)
    b, v = window.Read()

def SecondForm():

    layout = [[sg.Text('wedfrghjkl')],
              [sg.Exit('OK')]]

    window = sg.Window('Second Form').Layout(layout)
    b, v = window.Read()
#    window.Reappear()

def kill_proc_tree(pid, sig=signal.SIGTERM, include_parent=True,
                   timeout=None, on_terminate=None):

    if pid == os.getpid():
        raise RuntimeError("I refuse to kill myself")

    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    if include_parent:
            children.append(parent)
    for p in children:
            p.send_signal(sig)
    gone, alive = psutil.wait_procs(children, timeout=timeout,
                                    callback=on_terminate)
    return (gone, alive)


def main():

    # ----------------  Create Form  ----------------
    # sg.ChangeLookAndFeel('Topanga')
    menu_def = [['&File', ['&Run', 'Run as Administrator', 'Run as Limted User','---', 'Show details for all processes','---', '&Save', 'Save As','---', 'Shutdown',['Logoff', 'Shutdown', 'Hibernate', 'StandBy', 'Lock', 'Restart',],'---', '&Exit' ]],
                ['Options', ['Run to Logon', 'Verify Image Signature', 'VirusTotal.com', ['Check VirusTotal.com', 'Submit Unknown Executables'], 'Always on Top', 'Replace Task Manager', 'Hide when Minimized', 'Allow only one Instance', 'Confirm Kill', 'Tray Icons',['CPU History', 'I/O History', 'GPU History', 'Commit History', 'Physical Memory History',], 'Configure Symbols', 'Configure Colors', 'Difference Highlight Duration', 'Font'],],
                ['View',['System Information', 'Refresh Now'],],
                ['Process',['Window', 'Set Affinity', 'Kill Process', 'Restart', 'Suspend', 'Check VirusTotal', 'Properties', 'Search Online',]],
                ['Find',['Find Handle or DLL',]],
                ['Users',['User',['Connect', 'Disconnect', 'Logoff', 'Remote Control', 'Send Message', 'Properties',],],],
                ['&Help', ['Help', '&About','Walkthrough','Mail'],],]

    sg.SetOptions(auto_size_buttons=True, margins=(0,0), button_color=sg.COLOR_SYSTEM_DEFAULT)

    toolbar_buttons = [[sg.Button('', image_data=save64[22:], button_color=('white', sg.COLOR_SYSTEM_DEFAULT), pad=(0, 0), key='_save_',tooltip=' Save ',),
                        sg.Button('', image_data=sep64[22:], button_color=('white', sg.COLOR_SYSTEM_DEFAULT), pad=(0, 0), key='_separator_', border_width=0,disabled=True),
                        sg.Button('', image_data=refresh64[22:], button_color=('white', sg.COLOR_SYSTEM_DEFAULT), pad=(0, 0), key='_refresh_',tooltip=' Refresh '),
                        sg.Button('', image_data=sep64[22:], button_color=('white', sg.COLOR_SYSTEM_DEFAULT), pad=(0, 0), key='_separator_', border_width=0,disabled=True),
                        sg.Button('', image_data=sysinfo64[22:], button_color=('white', sg.COLOR_SYSTEM_DEFAULT), pad=(0, 0), key='_systeminfo_',tooltip=' System Information '),
                        sg.Button('', image_data=kill64[22:], button_color=('white', sg.COLOR_SYSTEM_DEFAULT), pad=(6, 0), key='_killproc_',tooltip=' Kill Process '),
                        ]]


    layout = [[sg.Menu(menu_def, )],
                [sg.Frame('', toolbar_buttons,title_color='white', pad=(0,0) , border_width=0)],
              [sg.T('Filter by Typing Process name or Process ID', font='ANY 14', text_color='black',),
               sg.In(size=(15,1), font='any 14', key='_filter_'),sg.RButton('Show', button_color=('black', 'Light blue'),pad=(5,5)), sg.RButton('Submit', button_color=('black', 'Light blue'),pad=(5,5)),sg.RButton('Open VirusTotal Result', button_color=('black', 'Light blue'),pad=(5,5),key='VirusTotalWeb'),sg.RButton('Upload', button_color=('black', 'Light blue'),pad=(5,5),key='uploadfile'),sg.RButton('GEOLOCATION of Live Process', button_color=('black', 'Light blue'),pad=(5,5),key='_ipadd_'),sg.Button('', image_data=firewall64[22:], button_color=('black', sg.COLOR_SYSTEM_DEFAULT), pad=(6, 0), key='_firewall_',tooltip=' Firewall ')],
               #sg.RButton(' Upload ', button_color=('black', 'Light blue'),pad=(5,5),key='uploadfile'),
               #sg.RButton('Ok', button_color=('black', 'Light blue'),pad=(5,5)),
               #sg.RButton('Show', button_color=('black', 'Light blue'))],
               # [sg.RButton('Web GUI',button_color=('white', 'sea green'), pad=((1070,3),3)),
               # sg.RButton('Maps', button_color=('white', 'sea green'), pad=((10, 3), 3)),
               # sg.RButton('Suspend', button_color=('white', 'sea green'), pad=((10,3),3)),
               # sg.RButton('Kill', button_color=('white', 'red'), bind_return_key=True, pad=((10,3),3))],
              [sg.RButton(' PID ', pad=((3,3),3)) , sg.RButton('                      Name                      ', pad=((0,3),3)) , sg.RButton('Connections', pad=((0,3),3)) , sg.RButton('Status', pad=((0,3),3)) , sg.RButton('  M_usage  ', pad=((0,3),3)), sg.RButton('    Score    ', pad=((0,3),3)) ,sg.RButton('                                                                                         Path                                                                                ', pad=((0,3),3))],
              [sg.Listbox(values=[' '], size=(150, 50), select_mode=sg.SELECT_MODE_EXTENDED, text_color = "darkblue", font=('Courier', 10), key='_processes_')]]


    window = sg.Window('TERMINATOR',
                       keep_on_top=False,
                       auto_size_text=True,
                       auto_size_buttons=True,
                       default_button_element_size=(20,1),
                       return_keyboard_events=True,
                       resizable=True
                       ).Layout(layout)



    display_list = None
    # ----------------  main loop  ----------------
    while (True):
        # --------- Read and update window --------
        #event= window.Read()
        button, values = window.Read()  #

        # if event is None or event == 'Exit':
        #     return
        # print('Event = ', event)

        if 'Mouse' in button or 'Control' in button or 'Shift' in button:
            continue
        # --------- Do Button Operations --------
        if values is None or button == 'Exit':
            break

        if button == 'About':
            #window.Disappear()
            sg.Popup('About this program','Version 1.0', 'PySimpleGUI rocks...\n We are SIH 2019 Team.... :D', grab_anywhere=True,button_color=('white','blue'))
            #window.Reappear()
        elif button == 'Run':
            #window.Disappear()
            #sg.Popup('Run Dialog called')
            #window.Reappear()
            p = subprocess.Popen(' explorer.exe Shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}', shell=True)
        elif button == 'Run as Administrator':
            #subprocess.Popen('explorer.exe Shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}', shell=True)
            shell.run("cmd.exe")
            #shell.SendKeys("^{SHIFT}")
        elif button == '_systeminfo_':
            p = subprocess.Popen('msinfo32', shell=True)
        elif button == '_close_':
            sys.exit(0)
        elif button=='Show':
            processes_to_select = values['_processes_']
            dll_path = {}
            all_dll = []
            for proc in processes_to_select:
                pid = int(proc[0:5])
                p = psutil.Process(pid)
                name = p.name()
                cpu_percent = p.cpu_percent()
                status = p.status()
                #parent = p.parent()
                #parent_pid = parent.pid
                #parent_name = parent.name()
                username = p.username()
                proc_time = datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                vms = p.memory_info().vms/(1024*1024)
                try :
                    path = p.exe()
                    abs_path = p.cwd()
                except:
                    path= " "
                    abs_path = " "
                try:
                    for dll in p.memory_maps():
                         all_dll.append(dll.path)
                    dll_path[p.pid] = all_dll
                except :
                    dll_path[p.pid] = ""

                if sg.PopupYesNo('Showing the Verbose Output of the Process  {} {} \nPress Yes to get the Output'.format(pid, proc[13:]), keep_on_top=True) == 'Yes':
                        p = psutil.Process(pid)
                        sg.Popup('Verbose Information about the Process {0}!!'.format(pid), 'Name of the Process : {0}'.format(name), 'Status of the Process : {0}'.format(status), 'Owner of the Process : {0}'.format(username), 'Time at which the process was created :{0}'.format(proc_time), 'Path of the Process : {0}'.format(path), 'Memory  Usage by the Process : {0}%'.format(vms)) # "DLL's loaded with the Process : {0}".format(dll_path[p.pid])

            #sg.Popup('About this program', 'Version 1.0', 'PySimpleGUI rocks...\n We are SIH 2019 Team.... :D',
                     #grab_anywhere=True)
        elif button=='Submit':
            processes_to_select = values['_processes_']
            for proc in processes_to_select:
                pid = int(proc[0:5])
                p = psutil.Process(pid)
                name = p.name()
                status = p.status()
                username = p.username()
                try :
                    path = p.exe()
                    abs_path = p.cwd()
                except:
                    path= ""
                    abs_path = ""
                BUF_SIZE = 65536
                if len(path) == 0 :
                    pass
                else :
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    try:
                        with open(file, 'rb') as f:
                            while True:
                                data = f.read(BUF_SIZE)
                                if not data:
                                    break
                                md5.update(data)
                            hash = md5.hexdigest()


                    except:
                        pass
                    params = {
                        'apikey': "Your_API_Key",
                        'resource': hash
                    }

                    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                    json_response = response.json()
                send_addr = "<Sender_EmailAddress>"

                mail_addr = "Receiving_Email_Address"

                msg = MIMEMultipart('alternative')
                msg['Subject'] = "Alert By Bug_Hunter_Squad!! Team"
                msg['From'] = send_addr
                msg['To'] = mail_addr

                # Create the body of the message (a plain-text and an HTML version).
                text = "Respected Users!\n\t\t\tHere is the Alert By Bug_Hunter_Squad!!"
                html ="""\
                <html>
                  <head></head>
                  <title>Submitted the Process of the LAB Machine</title>
                  <body>
                    <p>Dear Sir/Ma'am <br>
                       Activity Detected by the Team<br>
                       Here is the Full Description about the Process Submitted to the Virustotal<a href="{0}">link</a> you wanted.
                    </p>
                  </body>
                </html>
                """.format(json_response['permalink'])

                # Record the MIME types of both parts - text/plain and text/html.
                part1 = MIMEText(text, 'plain')
                part2 = MIMEText(html, 'html')

                # Attach parts into message container.
                # According to RFC 2046, the last part of a multipart message, in this case
                # the HTML message, is best and preferred.
                msg.attach(part1)
                msg.attach(part2)

                # Send the message via local SMTP server.
                s = smtplib.SMTP('smtp.gmail.com: 587')
                s.starttls()
                s.login(msg['From'], 'Email_Password')
                # sendmail function takes 3 arguments: sender's address, recipient's address
                # and message to send - here it is sent as one string.
                s.sendmail(msg['From'], msg['To'], msg.as_string())
                s.quit()

                if sg.PopupYesNo('Submitting the hash to the Virustotal API {} {} \nPress Yes to get the Output'.format(pid, proc[13:]), keep_on_top=True) == 'Yes':
                    p = psutil.Process(pid)
                    try :
                        if json_response['positives'] == 0:

                            sg.Popup('Verbose Information about the Nature of the Process {0}!!'.format(pid),\
                                    'Name of the Process : {0}'.format(name),\
                                    'Hash of the Process : {0}'.format(hash),\
                                    'No. of Checks performed on the Process  HASH : {0}'.format(json_response['total']),\
                                    'No. of Positives Result found : {0}'.format(json_response['positives']),\
                                    'Severity Level is : {} '.format("NONE( SAFE )")
                                    )
                        elif json_response['positives'] < 10 :
                            sg.Popup('Verbose Information about the Nature of the Process {0}!!'.format(pid), \
                                     'Name of the Process : {0}'.format(name), \
                                     'Hash of the Process : {0}'.format(hash), \
                                     'No. of Checks performed on the Process  HASH : {0}'.format(
                                         json_response['total']), \
                                     'No. of Positives Result found : {0}'.format(json_response['positives']), \
                                     'Severity Level is : {} '.format("Very LOW")
                                     )
                        elif json_response['positives'] in range(10,20):
                            sg.Popup('Verbose Information about the Nature of the Process {0}!!'.format(pid), \
                                     'Name of the Process : {0}'.format(name), \
                                     'Hash of the Process : {0}'.format(hash), \
                                     'No. of Checks performed on the Process  HASH : {0}'.format(
                                         json_response['total']), \
                                     'No. of Positives Result found : {0}'.format(json_response['positives']), \
                                     'Severity Level is : {} '.format("Very LOW")
                                     )
                        elif json_response['positives'] in range(20,30):

                            sg.Popup('Verbose Information about the Nature of the Process {0}!!'.format(pid), \
                                     'Name of the Process : {0}'.format(name), \
                                     'Hash of the Process : {0}'.format(hash), \
                                     'No. of Checks performed on the Process  HASH : {0}'.format(
                                         json_response['total']), \
                                     'No. of Positives Result found : {0}'.format(json_response['positives']), \
                                     'Severity Level is : {} '.format("LOW")
                                     )
                        else :
                            sg.Popup('Verbose Information about the Nature of the Process {0}!!'.format(pid), \
                                     'Name of the Process : {0}'.format(name), \
                                     'Hash of the Process : {0}'.format(hash), \
                                     'No. of Checks performed on the Process  HASH : {0}'.format(
                                         json_response['total']), \
                                     'No. of Positives Result found : {0}'.format(json_response['positives']), \
                                     'Severity Level is :  {} '.format("HIGH")
                                     )
                    except :
                        sg.Popup('Please Check Your Internet Connection........','')
            #sg.Popup('About this program', 'Version 1.0', 'PySimpleGUI rocks...\n We are SIH 2019 Team.... :D',
                     #grab_anywhere=True)
        elif button == "_ipadd_":
            processes_to_select = values['_processes_']
            for proc in processes_to_select :
                pid = int(proc[0:5])
                p=psutil.Process(pid)
                rem_addr = []
                conns = p.connections()
                for conn in conns:
                        if len(conn[4]) == 0:
                            pass
                        else :
                            rem_addr.append(conn[4][0])
                if len(rem_addr) == 0:
                    pass
                else:
                  all_res = []
                  for readdr in rem_addr:
                     if readdr == "127.0.0.1":
                      pass
                     else:
                      try:
                        res = requests.get("https://geo.ipify.org/api/v1?apiKey=GENEREATE_APIKEY_FROM_IPIFY&ipAddress="+str(readdr))
                        j_res = res.json()
                        all_res.append(j_res)
                        sg.Popup('Getting the Location Detailing of the Following :', 'Country  : {0}'.format(j_res['location']['country']),
                                 'Latitude : {0}'.format(j_res['location']['lat']),
                                 'Longitude : {0}'.format(j_res['location']['lng']),
                                 'Region : {0}'.format(j_res['location']['region']),
                                 'City : {0}'.format(j_res['location']['city'])
                                                             )

                      except:
                        pass
                      webbrowser.open("https://maps.google.com/?q=" + str(j_res['location']['lat']) + "," + str(j_res['location']['lng']))




        elif button == 'VirusTotalWeb':
            processes_to_select = values['_processes_']
            for proc in processes_to_select :
                pid=int(proc[0:5])
                p=psutil.Process(pid)
                try:
                    path= p.exe()
                    md5= hashlib.md5()
                    file= path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        link= json_response['permalink']
                except:
                        link=""

            webbrowser.open(link)

        elif button == 'Firewall':
         os.system("netsh advfirewall set allprofiles state on")
         sg.Popup("Firewall is ON")

            #processes_to_select = values['_processes_']
            #Form(processes_to_select)
        elif button == 'uploadfile':
            uploadForm()

        elif button=='Ok':
            FirstForm()
        elif button=='Maps':
            NextForm(74,-74)
        else:
            print("Not Found")

        if button == ' PID ':
            #procs = psutil.process_iter()
            #all_procs = [[proc.cpu_percent(), proc.name(), proc.pid, proc.status()] for proc in procs]
            #sorted_by_cpu_procs = sorted(all_procs, key=operator.itemgetter(1), reverse=False)
            display_list = []
            all_procs =[]
            for proc in psutil.process_iter():
                try :
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives)+"/"+str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try :
                        all_procs.append([proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms/(1024*1024), score, proc.exe()])
                    except :
                        all_procs.append([proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms/(1024*1024), score, ""])
                else :
                    try :
                        all_procs.append([proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms/(1024*1024), score, proc.exe()])
                    except:
                        all_procs.append([proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms/(1024*1024), score ,""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(0), reverse=False)
            for process in sorted_procs:
                #display_list.append()
                 display_list.append('{:5d} {:27s} {:8s} {:6s} {:5.3f} {:5s} {}\n'.format(process[0], process[1], process[2], process[3], process[4], process[5], process[6]))
            #list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)

            #display_list.SetValue(list)
        elif button == 'Kill' or button == '_killproc_':
            processes_to_kill = values['_processes_']
            for proc in processes_to_kill:
                pid = int(proc[0:5])
                if sg.PopupYesNo('About to kill {} {}'.format(pid, proc[13:]), keep_on_top=True) == 'Yes':
                    if pid == os.getpid():
                        raise RuntimeError("I refuse to kill myself")
                    else :
                        p = psutil.Process(pid)
                        '''children = p.children(recursive=True)
                        for process1 in children:'''
                        p.kill()
                        sg.Popup('The Process Number {:5d} was killed!!'.format(pid))

        elif button == "Suspend":
            processes_to_suspend = values['_processes_']
            for proc in processes_to_suspend:
                pid = int(proc[0:5])
                if sg.PopupYesNo('About to suspend {} {}'.format(pid, proc[13:]), keep_on_top=True) == 'No':
                    if pid == os.getpid():
                        raise RuntimeError("I refuse to kill myself")
                    else :
                        p = psutil.Process(pid)
                        '''children  = p.children(recursive=True)
                        for process1 in children:'''
                        p.suspend()
                        sg.Popup('The Process Number {:5d} was suspendend!!'.format(pid))

        elif button == "_save_" or button == 'Save' :
            sg.PopupGetFile('Save File:', #Message to show in the window
            default_path='Desktop', #Path browsing should start from
            default_extension='.txt', #Which filetype is the default
            save_as=True, #Determines which dialog box stype to show
            file_types=(("Text Files", "*.TXT*"),), #Which filetypes are displayed
            no_window=False, #if True no window is displayed except the dialog box
            size=(None,None), #Size of window
            button_color=None, #Color of buttons
            background_color=None, #Color of window background
            text_color=None, #Color of text in window
            #icon=DEFAULT_WINDOW_ICON, Icon to show on taskbar
            font=None, #Font to use
            no_titlebar=False,# If True does not display a titlebar
            grab_anywhere=False,# if True can grab window anywhere to move it
            keep_on_top=False, #if True window will be on top of others
            location=(None,None)) #Location on screen to show window

        elif button == '               Name               ' or button == '_refresh_':
            display_list = []
            all_procs = []
            for proc in psutil.process_iter():
                try:
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives) + "/" + str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])
                else:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(1), reverse=False)
            for process in sorted_procs:
                # display_list.append()
                display_list.append(
                    '{:5d} {:27s} {:8s} {:6s} {:4.2f} {:20s} {}\n'.format(process[0], process[1], process[2],
                                                                           process[3], process[4], process[5],
                                                                           process[6]))
            # list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)


        elif button == 'Connections':
            display_list = []
            all_procs = []
            for proc in psutil.process_iter():
                try:
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives) + "/" + str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])
                else:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(2), reverse=False)
            for process in sorted_procs:
                # display_list.append()
                display_list.append(
                    '{:5d} {:27s} {:8s} {:6s} {:4.2f} {:20s} {}\n'.format(process[0], process[1], process[2],
                                                                          process[3], process[4], process[5],
                                                                           process[6]))
            # list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)


        elif button == 'Status':
            display_list = []
            all_procs = []
            for proc in psutil.process_iter():
                try:
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "b8acfc47cf0cd9d6bb515722f5c4dad6739f4e1a9669241e39d56d46e2675abb",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives) + "/" + str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])
                else:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(3), reverse=False)
            for process in sorted_procs:
                # display_list.append()
                display_list.append(
                    '{:5d} {:27s} {:8s} {:6s} {:4.2f} {:20s} {}\n'.format(process[0], process[1], process[2],
                                                                           process[3], process[4], process[5],
                                                                           process[6]))
            # list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)


        elif button == '                                                                                         Path                                                                                ' :
            display_list = []
            all_procs = []
            for proc in psutil.process_iter():
                try:
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives) + "/" + str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])
                else:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(6), reverse=False)
            for process in sorted_procs:
                # display_list.append()
                display_list.append(
                    '{:5d} {:27s} {:8s} {:6s} {:4.2f} {:20s} {}\n'.format(process[0], process[1], process[2],
                                                                           process[3], process[4], process[5],
                                                                           process[6]))
            # list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)

        elif button == "  M_usage  ":
            display_list = []
            all_procs = []
            for proc in psutil.process_iter():
                try:
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives) + "/" + str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])
                else:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(4), reverse=False)
            for process in sorted_procs:
                # display_list.append()
                display_list.append(
                    '{:5d} {:27s} {:8s} {:6s} {:4.2f} {:20s} {}\n'.format(process[0], process[1], process[2],
                                                                           process[3], process[4], process[5],
                                                                           process[6]))
            # list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)

        elif button == "    Score    ":
            display_list = []
            all_procs = []
            for proc in psutil.process_iter():
                try:
                    path = proc.exe()
                    md5 = hashlib.md5()
                    file = path.encode("unicode_escape")
                    with open(file, 'rb') as f:
                        while True:
                            data = f.read(BUF_SIZE)
                            if not data:
                                break
                            md5.update(data)
                        hash = md5.hexdigest()
                        params = {
                            'apikey': "API_KEY",
                            'resource': hash
                        }
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        json_response = response.json()
                        total = json_response['total']
                        positives = json_response['positives']
                        score = str(positives) + "/" + str(total)
                except:
                    score = "None"
                if len(proc.connections()) == 0:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Not Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])
                else:
                    try:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, proc.exe()])
                    except:
                        all_procs.append(
                            [proc.pid, proc.name(), "Live", proc.status(), proc.memory_info().vms / (1024 * 1024),
                             score, ""])

            sorted_procs = sorted(all_procs, key=operator.itemgetter(5), reverse=False)
            for process in sorted_procs:
                # display_list.append()
                display_list.append(
                    '{:5d} {:27s} {:8s} {:6s} {:4.2f} {:20s} {}\n'.format(process[0], process[1], process[2],
                                                                           process[3], process[4], process[5],
                                                                           process[6]))
            # list[2].append('safe')
            window.FindElement('_processes_').Update(display_list)

        elif button == "Web GUI":
            os.system("cmd.exe")
        elif button == "Maps" :
            print("Not found!")
        #elif button == "Suspend":



        else:
            if display_list is not None:
                new_output = []
                for line in display_list:
                    if values['_filter_'] in line.lower():
                        new_output.append(line)
                window.FindElement('_processes_').Update(new_output)





if __name__ == "__main__":

    save64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAFF0lEQVR42rWVe2xTVRzHf+fe23vb297edm23dXPj4QZkEAYbzwkJmxEG6kACgSgRM4goMAF5yWuJCvM95RVMFIhKELaYYAxRUZHEMBRG0k2Q6QZjr66PtV2723btbXs8HbC4bsH+w0lOzrnnnns+5/v9/c65CB5xQf83YceeSiotReRFUTRijDPIUBpp0+JtDGOzxR5k6joDacEIdHIq9ekbRzf9NiIgq2zjaFZnKkYUPbBIvPIMjJ6WzuXOG2/WaNQ8o1QqEalYpVIhjuNw/Jn04eyVFtxolVBIliNdvdLq398rPz0MYJq9eA3DC589t6IcUrQCeUOBqNEAYAxL8lSg16oHdxUMhcHm9kGPV4KC3Gz44mIjXG9zQygsgz8Ukp1BOd9Sva5pKGDmsy9QCvbU/qpDwNIMtns8SEFR0Of34xUFemTUCQPziD34h2u3UPV3f+BgMIB+2r8GTvzyJ65vdaJQOEwgYeyJoBkNH79SnwhYihjmm92VH4JSocDdPT0oFo1CX8CP187JQmajbhDw7eUG9HbNJRwK9aNrBzfDse/r8dXbDhRXEJLD2A/s1BuH1jckAJ5ZCBR9fsvOA8BzHLTbbUAWIAoCsG1hHmSY9IMW1V6qh72nLgBNvrYc3Q7V5y7DlRYb3FcAEU6YdOvwhr+GAIzTFxUjmrm4bnMlaEgg71i7UJ8kDVj01vKZaJTZOKjgzMWraN+pC1ipYND1I1vhwJlf8ZVm6z2LZBkzgmFc05GNLUMAhsIFs0kM6lat2wFansfNHR3I7XGDjwCqXypBuVnpwwAqAqgngH1f/ojr/u66B4jImNeZRjd/uqU9EVBAMWz90tUVoNOooamtDawOO/RJfjhesRjGZ5sHLbrb7QSrywtpOjWoiJ2vf34eWmzuAXtkEjdBNGS2ntzVnQjIoxjFzUUrX46nJ/6nvQO1dnZAJBbDe5fNRRkGHdh6Jeh2+XCHy4s6nb242yOhXn8Q+knmkIoikQhQFB0T9Ib01hO7nAmA+Y8jhm0uWfIi6ARhYDf9MtmRHIGwHIb7GXI/kPf6LEQhlagw6zSgYmmorbtJ8oSJaXWGlDsn3vANAejzSx6jOVVH0aKVIAoCJouisCwDxGQsKhlk0iohVVRDuk6NMw1aokiLU7QaRJGzEg9NsD+ECis+AkzREa3OKNw+vrM/EWAkAGfBk0tAK2hxrolHq+dNjJ9gzNAkIREaDDIi5UH7YEwKBFHha9VA4ihrBFHVenJ3NAFQLNAc75s4pxQEAnhqUiZaVTIV/rvQwwA+yY+mb/oEaJYLO2rf5YbdRfrJ8xS0Uh3KmV4MakELCyZnQ/n8aUlfyx6fBLO2HCQAZZ+j9h1xGEDMK2IUGr2UlV9Ebl0tLs0fhTaUPZG0gp5eHyraehgUnMplr6kyjgSgWCHFnTqhUGR5DS6dMgZtW1acNMDu9qK52wlAydvsZ6vMIwEQUWDT50w2Eatg4ZSxsOf5+Ulb1OlwQcmuY8Aq1Z22sweyhwHihVx47ersCVmYVREFY1FVeVnSCprarJHlH9TcpRXsz51fVa4fGTDj6WY2IycnQrO4dGoOqn512TBANBrF5GcTcPUFbjq8/gavFLTcsroabG7vja/3rvUmKktUcI4yZZfJNAelBbnw3prFuMvtszu9gUYp2G+5bfM02Dw+i8PpaqnZXyEnY91QwKwynssc9yYlpLjSRd4yJlXXGPM6umvf34GTDsbDAI+i/AvYPpc3fS5BmgAAAABJRU5ErkJggg==" alt=""'

    refresh64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAD90lEQVR42q1Wf2zTRRR/r/2uP6hdgcniUCIaJ84NtzFUBCUx8geJEcg2AQMSlSEh6ZwakpkYjBKJTCWI0UyFzR9TXIZrHQy3KSEi60aUzQ0cZWVjpdu6dtCutJSupb3nXZduw4DrGC9533t3efc+9z737u6LAJDOtQIlRRYAwpSFRYLEwt9xS8/1mojY+vDKzdkv5OeSJJfFEAjG0Mbb4/s39HG4PLR313a8aj1dyLufISpU7N7X9qBakXCzoHEBZLptqAn6oSkljRztzTh0eG8ZHy9AUE5jmrf2TZmZ0pZaSIUQLMvJhbD5LwhW7f6aD29EUGtI+tDwf6uOK4OEYBCRMQip1cTaTcj2bS+PAqg1d9DuA4euC4SA1wPg6Lj4EG8x2o4I72HUlglbJqOW47/jnm3FIwDaxER2qsM89eoZJ/V1dbDl1YIRinQ6Hdn6+qdM0Xj70MEaXL9uXfkowMVLl24rgNFoxDWrV48CMLd76LZSZDQaID8/f4wij8cDxCW6Y2IJN7HH90UbW3VsTLgJW2SQl5c3lsHQ0OQzEPHPXOyBxv7T4An4IEU5A5Ykp0NKUjI0NDQAB7j1DPquDOLHrd9TglzCjKT7YJqkpAG/C9sHu2EuJFHSOUK9Xl9+SwD9PidtNZVg1qxUipAM79bM5jtMZPfbUSUHsPuHqKnBhM3vHzZx96cmBcD4SS069jbJZRHMuHMhrZ+3Ck+5/gSLx8y95NjlcUIgfJmsXifWbjVQwOxdNak9OOfqgjebiiAneSG88/i78Iu1Akz2OnGogYkvyUGnmA/nvf9A468nwfJRZ3U0A5fLNeE5EDVTYzkA+3tKqSC9CJ++ZzltO7EClfKQuDiIMUS19BAU53xOn7SVYP2Zaji64e/zUQCH0ymiEMbK7ga2oMdw9huwhc1UmFmCKklBx/oq8eTgjihAmClw7YNVcH9iKrmHPVh4ZCX8uOL4ACbyu6jbeiGusjT11MIR3w54PasM5mjnw/7OZRBiAxyAU0QSp2cxrE39ASotxXDwRA1UvmRpQa1WS82tbRNSJAy7wwZ/oJ7m6KbjA9OzyXG1ilcOA/4OUiiCvKJ2wWN35dGn7U/iz19cgMav3B+gQqkMfPtTjUqSpAkBgsPD0HvNQDPS6nGmCijCnsAws3EAiVI0G3Hp7A3Q7HiDjnYYcOfzTn/gMksTE7/MyMzelP5IZlxv/hWvF+YuaoVn13hhlho4VbmgkR6FYMQLVp8B2ro74b1XvNB7NryJu5eJkAlcN3PNgvh/K+YtWCItfnmLHJ9ZymCmllFHlxyrDQgVpSG/z0NFIjhMIuB/Rcx7juuLXBdw5bmAeFR+41rKtTfm+C9pVSdiCXz5nwAAAABJRU5ErkJggg==" alt=""'

    sysinfo64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAGAUlEQVR42pVWfUxVZRh/nvN1vzATuGIpokCKpiCaDtEtMz8uQ0pdmpiYw3KtmJua01q56WqUmcxWuv5AXZpOZobG9PoV080KExGhFJAbaehFRITg3nPP19vzHpjLnKln57n33HPv+f3e53l+z++9CI94pKamumNiYrz8+vbt263V1dWhR3kO/+/LuXPnjl68eHE+gWcNGjQo2TAMkW4zURSt5ubmhpqaGv+uXbuK9+/fX/tYBJmZmQPWr19flJExcX5lbZ1Q/edNaLzZAV2axfHBIwswNPYJSEvwwoS0EVZFRcW+DRs2rDh9+nTLQwlyc3MzioqKvm+81jLgwLkrrDkiQlgz0EZGQDoZo0t+OiQBoyHM5mcMg5GJ8cHVq1fPpozOPpBg9uzZ47dv337y8JmqqKOBTuyMmEwQEAREpGA96ITfy2ZZDE36LFo6TI1340Lf5I5ly5ZNo5Kdu48gKSkpury8/MJPtYH4g/XtENJNkAQBJLEnBBQALAMmDR8IgZZ2aL4TBouoDMsCw7ToKwNmJrghOzP16owZM8bU1dW130NQXFy8bcz4iW9tKa9jHRqBiyIqksgoQJZElCiDJG8UrnppImu43gYbf6gAi2g102S6YQIFmmqYrZk5Cupqzm/Lz89/5y5BYmJi/MWLF68U7j2u1LabjK9YkSV0yhJzyBJQoCwKzCEwfDVzBKtuaoFf/7gJBtUpohuMAiK6ibphsP5WJ3z+9jxt7NixSQ0NDc02wdq1a9fMX7j4k83l9aQUkwBFcCoyuHg4ZCAikO0yUe15i3lp6IVASQC6HarGSQywdA3em54Cpfv3rS4sLNxkExw5cuT4Lcv94ne/30JRQObsAUaPQ2FuhwSKiBjrcbDYPi68fifEdCaATnUnYAxFNNYdIZKIjqqmM900wTfYhYOj4Gh2drYPBToCgcDVnT9WP13VplPdJeZSJPA4FaRgbiIbN8SLIwdGs+SnYvB84AY7dfkG6DQSIU3DLlVjITUCIVVHImQR6scIt4Zv+iZcS0lJGUICRPkOHR9+43ddVSWk8jBeFlo9elwORu/gJL1LZoSteHkSVjcF2en6oE3QTaBdqsq6VY0ItB4CKttAoRs/ys/pio2N7cdLJJO3tK3bfazPXxGZNxR6CcDjUiDK6SACEbxuAZZMTYfDlfXQeCsENCLAgbtp9fZ7RONlAo0ySJBC8MEiX0dcXJyXEwjkKZdLzjYm19w2UeEZUFncPAOnTD1wgEMEHJcQw2aMScZt/nNMBQkiBvUgoiERMA4esntgMI3mYXw04qxxSXXp6ekj7Sbv2LGjRPAmzjtwqZXUwhUk9SpIAd4PiRSfm5kC/ft64OsTF0CQncCB+IrDmg1uKylCCrQY/XZkNPx9I7Bv6dKlC2yCOXPmvP5Z0Rc7Vn57CiWHm1EWVCoZCZxxyQqmjhtyp7CapiCWVTUxlGQ+WKDqPatWuUx1g+bAZLIWgk2LXsDlywvySktLd9sEiqL0qadj+4mqAdU0aDwLmmBquMS4/uOiZFy/4AVW+nMtll9qZoIsA6mU17t30PgkG2hajGXGArzyfHqQFDRM07Suu1aRl5e3vHDjpi3v7jwGquS2/UfmNkHT9aRThE/zplP6DEhFUPJLHXSquj0Ltk2YPX7Uz+yCwiU+WLVyRcGePXu++q+bKiUlJWXxzzw7bbP/AmiSE0mdTCTDE4BhlCLw+cC27ghDQaSuIGVhIQEzOsFjhnClL51duVx7jCw/hyZev8+uPR5P/7KysiNRMQPSv/RXYge6uCv32PU9+wHY2VAgdw++8oKs57C9NViZk5OTFQqFWh+44bhcLu/WrVuLs2fl5Ow7WQFnAm2gO6LIlpm9C/Q8hECWAoraCZOHRsP86Zlw6NDBgwUFBW+Ew+Fbj7Iny1lZWa/RNvh+YmJScuVvDdjUeoe1d6m23fXzOGGIty+MGzUcGxuv1K9bt+5jv9+/l57TH2vT5wmR7U7x+Xwz09LSRtNkxvKbwWCQ/6uoJVB/VVXVKboVfhDAwwj+ffB/FELvNd/9zUd56B8pXBJ0vO1EmwAAAABJRU5ErkJggg==" alt=""'

    kill64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAADHklEQVR42rWVX0iTURjGn21sOl1KhtKIGiYIda033XmlFxpW9Mf+meSdddWdNyKRUREVTuzPyqTC20gpLWpFdaX3gTRtiWiahrY5t7nZcz7fzc/TRAt84eE75+zb8/vOe95zjgVbHBatv486Te3M8NtGsUxNUk+pL5kAZ4sBXy1g97CTk0FOeTFs0oJJY9QLID4KnGfziRngdgMBHz0OsJNNJddRQpN5LEp9pS4CkQmghM2JFKC+CXh8W/6wpJksrdPO9JvKEz8Uj4BzfHSnAE13AW+DvGg1JVVXcp3xGBWUWbykrgMX+OhIA+4TcEpyZvvPihmnRgVwUwd0mgDGDGw22FtbgcVFxNva+OnJtW5WK+zNzVywbMRbWjj1BH7IGryibumADgJOmkrLVlYG1+Cg0Y91dSHS2LgKobnT54OjocHohsrLkRgawpQABqg7OqCdgDrJpzHocMDV34+sigrjhSghIQVhuGieJeZRvx+hqip+RcwABKjXVLsOINF73AxQ7Zwc5Pf1wSmQCCEqnGIeoflcdTUsCwtGXwFGqDfKWQcwZ95jUiXm3ZfMzUVBby9yBZKKMM1na2pgDYfTY9Myg7dUpw7gqnuPCkCPhMuF3YEA7EVFRj8+NYWxkhLYQqE1703LDN5R93TADQKOYLXOU2HhghYy53mSllTMM13TXJNlU3X9lDL1Uw90wDUCDmNlo6UBNHfTPF/MZ/1+41kg6ZojZMJUXQrwjXpPPdQBVwk4hNXtrsx30Xy7mM/Q/DtzrmIP12SHQH4RMi4QBVC7+QPVpQOuEFCr8iuAPFbHXhoZuaX5KPsOqZYYq6uY1VUokBGC59lPAT5S3TrgMgEHBWBM2ONB6cAAfg8PI1hXB4epWgwIq8vT04NtpaUYrqykcxCzAvgE46xeC+Ch4FUJiJkqSdWIncpC5ojKB7mkP4OVO+Ez9UwD1F/icX1C/pBeB4nlDOb62JKYq3mqffBcO67dvB0CPMOdVmz+Lsg0tgjjJI1MaheOijP7WV28kO2F+Pu22kxbLTKPiXgww5WZitSl78a/x4aX/pbEH2Ceaij62q1HAAAAAElFTkSuQmCC" alt=""'

    sep64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZdEVYdFNvZnR3YXJlAEFkb2JlIEltYWdlUmVhZHlxyWU8AAAAJklEQVQ4T2P4//8/XszExFSBTRyGmRgoBKMGjBoAAqMGDLwBDAwAvmwtcB6DfX4AAAAASUVORK5CYII=" alt=""'

    firewall64='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAESElEQVR42qWVbUxbVRjHn9PetqyBFcxwVEY3YEUCdWOOgktccG7LJDAWEZjzAzNzQE0otig4qZEXYTC2CaMgxi4sBBYYan0piRtpFfGDc4WU0hBmW5CNODvrFpCXFmjv8bYJaG2BBv+fbu495/zu//885xwEfignJ4dVVFQk4XK5BxFCYLFYfmxtbW3s6OhY3Ggu2mhAfX09PzMz8waHw0mgFkeYkuv9zMxf+t5eVY5EIjFtCqBQKIioqChRbGzsedv9ySDmmAHYGVnub7fu3QA+OwF2cCJnjUZjmcFgaBWLxU6/AM3NzcF8Pv/VmJgYCZtBxCz0dAKrV4noOyMx/eLHbgfnR/Pgt7kJeCEkGx2PPI0di07j+Ph448jISHdxcfG0T4BSqTwkEAhKAgMDX2Rgkol/UCPy8+sYrH+AKxoI2IJpnV8jTCHeGkwFu3PB/T6YCMVpO07Dc9uOIeSkLc7Pz3+n1+svZmVlfe8BGB4e/jR8bjqP7FUC6AYBbAtedmkfXgZTBIZLY2KvbwF0NsRzkuFwWDZstW1XxMXF5a8CUlJSkFwuvxo2fOcMqZC7i/jvgq48O8K5qOrsErbaH8BaY07tkoKAdvCaSCQ6OzAwgN2A1NRUVF1d/UnEpCmfbKxdE7DIBCSRLuLVfH2MeWP3BxBFJiiothap1Wq8GlF/f39dPF5+lywvWbPl7AwM0uKlddu6OPYKsB6HXBAKhec8atDV1VV4JGGP3Jn/2v9yULfvC/hlaLwoIyOj2QNARXS4oKBATea+jPHc7KYAbHoQbtjfC52d149KpVKNByAvLy+4qqrqT9qFChoeur0pgIBzAL8ZXUPW1tZua2pqmvbaaGaz+c5Dw+9CjcrkmgGA8cpK7mcaYxmeOanwmb1roXCuCIKZh7TR0dFJXhuNqjqicjvH4++tef0aAU7S2wGbsKNvj2T7dACIQPORCjxmtsi6u7vrWlpasJeDwsLCCJlMNvGRmkUMmGhef7mFboObR3N8OlgOfB7mQoscDQ0NUdQBOeXlYEVarbaLFrTrZGEXgZwk+OcA0WGB14B+tZDdiYmJp/4bnYdKS0tjqV048pl+K0Opo7sDWBdAVWcp+AQ8Csh0tLe376msrLy7LsAllUp1ae+zwrdlXzHB+PCfqHxF5GTxYZZbAUM6w+W0tLR3fBXfS1SxA0pKSrTbeU/Hv/8lA+499u2AZO1EC+EV+K7ZMkqdZcKenh67XwCXysrK+Onp6T+FRex+olFNoNsTyAPgCEwC25NiND5pedTX13egvLzc58227pVJdUNyUlLSLT4/hqO9z4RvdEsgT34PlkJeAVvAfjCZzDM6ne4YdW3+vNYaG97JNTU1+yipeDzeU6Ghoe6orFYrTE1NPRgdHT1ORalbb/6GAJeorgqjjvQ2BoPxkqutHA7HTY1Gc4Y6DiwbzfULsKK2trZEgiAgNzd30N85fwP+DDM3FSSnBAAAAABJRU5ErkJggg==" alt=""'

    main()
