from io import BytesIO
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import BaseDocTemplate, SimpleDocTemplate, PageTemplate, Flowable, FrameBreak, KeepTogether, PageBreak, Spacer
from reportlab.platypus import Frame, PageTemplate, KeepInFrame
from reportlab.lib.units import cm
from reportlab.platypus import (Table, TableStyle, BaseDocTemplate)
from reportlab.lib import colors
from reportlab.lib.units import inch

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib import colors
from reportlab.pdfgen import canvas

styleSheet = getSampleStyleSheet()

########################################################################

"""


attack_description = {"DoS": {"defination":"A type of DoS attack in which an attacker sends a large number of HTTP requests to a target server to overwhelm it and make it unavailable to legitimate users.", 
"example":"In 2015, the UK National Crime Agency website was targeted with a DoS Hulk attack.", 
"reference": "https://blog.sucuri.net/2015/08/understanding-and-mitigating-http-dos-attacks.html",
"rmediation":"DoS Rmediation"},

"PortScan":{"defination":"A reconnaissance technique in which an attacker scans a target network for open ports to identify vulnerable systems.",
"example":"The Mirai botnet used port scanning to identify vulnerable IoT devices.",
"reference":"",
"rmediation":"PortScan Rmediation"},

"DDoS":{"defination":"A type of DoS attack in which multiple compromised systems are used to flood a target server with traffic to make it unavailable.",
"example":"The 2016 Dyn cyberattack was a large-scale DDoS attack that disrupted access to popular websites.",
"reference":"",
"rmediation":"DDoS Rmediation"},

"FTP-Patator":{"defination":"A brute-force attack in which an attacker uses a tool called FTP-Patator to guess usernames and passwords to gain unauthorized access to an FTP server.",
"example":"The FTP-Patator tool was used in the 2011 Sony Pictures hack.",
"reference":"",
"rmediation":"FTP-Patator Rmediation"},

"SSH-Patator":{"defination":"A brute-force attack in which an attacker uses a tool called SSH-Patator to guess usernames and passwords to gain unauthorized access to an SSH server.",
"example":"The Mirai botnet used SSH-Patator to infect IoT devices.",
"reference":"",
"rmediation":"SSH-Patator Rmediation"},

"Bot":{"defination":"A type of attack in which a computer program called a bot is used to perform automated tasks, such as spreading malware or carrying out DDoS attacks.",
"example":"The Mirai botnet was used to launch DDoS attacks on various websites.",
"reference":"",
"rmediation":"Bot Rmediation"},

"Infiltration":{"defination":"A type of attack in which an attacker gains unauthorized access to a target system to steal data, install malware, or carry out other malicious activities.",
"example":"The 2017 Equifax data breach was caused by an infiltration attack.",
"reference":"",
"rmediation":"Infiltration Rmediation"},
}

list= {attack_counts:{"bruteforce":10,"FTP-Patator":20},
"attack_description":attack_description,

"source-ip":{"192.168.1.1":1000, ...},
"source-port":{"234":1000, ...},
"destination-ip":{"192.168.1.1":1000, ...},
"destination-port":{"22":1000, ...},
"time_stamp":{"11:00:00":1000, ...},
}
"""

attack_description = {"Dos": {"defination":"A type of DoS attack in which an attacker sends a large number of HTTP requests to a target server to overwhelm it and make it unavailable to legitimate users.", 
"example":"In 2015, the UK National Crime Agency website was targeted with a DoS Hulk attack.", 
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference": "https://blog.sucuri.net/2015/08/understanding-and-mitigating-http-dos-attacks.html",
"remediation":"DoS Remediation"},

"Portscan":{"defination":"A reconnaissance technique in which an attacker scans a target network for open ports to identify vulnerable systems.",
"example":"The Mirai botnet used port scanning to identify vulnerable IoT devices.",
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference":"",
"remediation":"PortScan Remediation"},

"DDoS":{"defination":"A type of DoS attack in which multiple compromised systems are used to flood a target server with traffic to make it unavailable.",
"example":"The 2016 Dyn cyberattack was a large-scale DDoS attack that disrupted access to popular websites.",
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference":"",
"remediation":"DDoS Remediation"},

"FTP-Patator":{"defination":"A brute-force attack in which an attacker uses a tool called FTP-Patator to guess usernames and passwords to gain unauthorized access to an FTP server.",
"example":"The FTP-Patator tool was used in the 2011 Sony Pictures hack.",
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference":"",
"remediation":"FTP-Patator Remediation"},

"SSH-Patator":{"defination":"A brute-force attack in which an attacker uses a tool called SSH-Patator to guess usernames and passwords to gain unauthorized access to an SSH server.",
"example":"The Mirai botnet used SSH-Patator to infect IoT devices.",
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference":"",
"remediation":"SSH-Patator Remediation"},

"Bot":{"defination":"A type of attack in which a computer program called a bot is used to perform automated tasks, such as spreading malware or carrying out DDoS attacks.",
"example":"The Mirai botnet was used to launch DDoS attacks on various websites.",
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference":"",
"remediation":"Bot Remediation"},

"Infiltration":{"defination":"A type of attack in which an attacker gains unauthorized access to a target system to steal data, install malware, or carry out other malicious activities.",
"example":"The 2017 Equifax data breach was caused by an infiltration attack.",
"details":"Ip 192.168.1.1 try to ssh brute force on ip 192.168.1.2",
"reference":"",
"remediation":"Infiltration Remediation"},
}

list= {"report_time_peroid":"2023-02-23 to 2023-03-20",
       "targated_ip":["192.168.1.1", "192.168.1.2"],
        "attack_info":{"DoS":['DoS','2023-01-01', '192.168.1.1', '192.168.1.2',	'22', '1000'],
        "SSH-Patator":['SSH-Patator', '2023-01-01', '192.168.1.1', '192.168.1.2',	'22', '1000'],
        "FTP-Patator":['FTP-Patator', '2023-01-01', '192.168.1.1', '192.168.1.2',	'22', '1000'],
        "Infiltration":['SSH-Patator', '2023-01-01', '192.168.1.1', '192.168.1.2',	'22', '1000']},
        "time_stamp":{"11:00:00":1000,"12:00:00":400},
}

"""
On Date {2023-02-23 to 2023-03-20}, a network attack was carried out against the [Name] network. 
The attack targeted the IP's ({list of IP}).<br/> The purpose of this report is to document the 
incident and recommend measures to prevent similar attacks from occurring in the future. 
"""

def create_pdf(list):
    """
    Create a pdf
    """

    L = []

    # Define the style for the table
    styles = getSampleStyleSheet()
    style = styles['Normal']
    style.fontName = 'Helvetica'
    style.fontSize = 12
    style.leading=1.5*10
    style.textColor = colors.black
    style.alignment = 4 # 4 is for justify

    # Create a frame
    text_frame = Frame(
        x1=2.6 * cm,  # From left
        y1=2.5 * cm,  # From bottom
        height=23 * cm,
        width=17 * cm,
        leftPadding=0 * cm,
        bottomPadding=0 * cm,
        rightPadding=0 * cm,
        topPadding=0 * cm,
        showBoundary=0,
        id='text_frame')

    spacer = Spacer(1, 10)

    introduction_header = Paragraph(""" Introduction """, styleSheet['Heading2'])
    incident_info_header = Paragraph(""" Incident Information """, styleSheet['Heading2'])
    incident_desc_header = Paragraph(""" Incident Description """, styleSheet['Heading2'])
    remediation_header = Paragraph(""" Remediation """, styleSheet['Heading2'])
    Conclusion_header = Paragraph(""" Conclusion """, styleSheet['Heading2'])
    
    introduction_body = Paragraph(f"""
                        On Date {list['report_time_peroid']}, a network attack was carried out against some
                        of internal network devices. The attack targeted the IP's {list['targated_ip']}.
                        <br/> The purpose of this report is to document the incident and recommend measures 
                        to prevent similar attacks from occurring in the future.
                        """, style=style)
    
    conclusion_body = Paragraph("""
                        In conclusion, network attacks pose a serious threat to modern computer systems 
                        and networks. To defend against network attacks, security strategy that includes 
                        multiple layers of defense, such as firewalls, intrusion detection and prevention 
                        systems, antivirus software, strong authentication mechanisms, and employee 
                        training and awareness programs should be implemented.
                         """, style=style)

    # Define the data for the table
    incident_info_table_data = [
        ['Anomaly Type', 'Date', 'Source IP', 'Destination IP', 'Destination\n Port', 'Total Count'],
    ]

    for value in list["attack_info"]:
        incident_info_table_data.append(value)

    incident_desc_table_data = [
        ['Anomaly', 'Description'],
    ]

    remediation_table_data = [
        ['Anomaly', 'Remediation'],
    ]

    table_style = TableStyle([
    ('BACKGROUND', (0,0), (-1,0), colors.grey),
    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
    ('ALIGN', (0,0), (-1,0), 'CENTER'),
    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ('FONTSIZE', (0,0), (-1,0), 14),
    ('BOTTOMPADDING', (0,0), (-1,0), 12),
    ('BACKGROUND', (0,1), (-1,-1), colors.beige),
    ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
    ('ALIGN', (0,1), (-1,-1), 'CENTER'),
    ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
    ('FONTSIZE', (0,1), (-1,-1), 10),
    ('BOTTOMPADDING', (0,1), (-1,-1), 8),
    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ('GRID', (0,0), (-1,-1), 1, colors.black),
    ])
    
    caption_style = ParagraphStyle(name='Centered', alignment='center')
    caption_1 = Paragraph("""Table 1: Count for Source IP and Source Port""",caption_style)
    
    incident_info_table = Table(incident_info_table_data)
    incident_info_table.setStyle(table_style)
    style_body = styles['Normal']

    L = [introduction_header,
         spacer,
         introduction_body,
         spacer,
        incident_info_header,
        spacer,

        incident_info_table,
        spacer,

        incident_desc_header,
        spacer,
    ]

    remediation_dict={}
    each_anomaly_description_list = []

    attacks = []
    for attackss in list["attack_info"]:
        attacks.append(attackss[0])
    
    replacements = {'DoS Hulk':'Dos', 'DoS GoldenEye':'Dos', 'Dos Slowloris':'Dos', 'Slowhttptest':'Dos'}

    new_array = [replacements.get(item, item) for item in attacks]
    attacks = new_array
    for key, value in attack_description.items():

        if key in attacks:
            attack = key
            desc = ""
            for key, value in value.items():
                if key != "remediation":
                    desc += key + ": "+value + "\n"
                else:
                    remediation_dict[attack] = value
                    continue
            
            desc = desc.replace('\n', '<br/>')
            each_anomaly_description_list.append(attack)
            each_anomaly_description_list.append(desc)

        else:
            continue
        incident_desc_table_data.append(each_anomaly_description_list)
        each_anomaly_description_list=[]
        

    for key, value in remediation_dict.items():
        a = []
        a.append(key)
        a.append(value)
        remediation_table_data.append(a)

    col_widths = [1.2 * inch, 6 * inch]

    # Create an empty list to hold the table data
    table_data = []
    table_data1 = []

    # Add paragraphs to the table cells and wrap the contents
    for row in incident_desc_table_data:
        # Create an empty list to hold the row data
        row_data = []
        
        # Add a paragraph to each cell and wrap the contents
        for cell in row:
            p = Paragraph(cell, style_body)
            p.wrap(col_widths[len(row_data)], 1000)
            row_data.append(p)
        
        # Add the row data to the table data list
        table_data.append(row_data)

    # Add paragraphs to the table cells and wrap the contents
    for row in remediation_table_data:
        # Create an empty list to hold the row data
        row_data = []
        
        # Add a paragraph to each cell and wrap the contents
        for cell in row:
            p = Paragraph(cell, style_body)
            p.wrap(col_widths[len(row_data)], 1000)
            row_data.append(p)
        
        # Add the row data to the table data list
        table_data1.append(row_data)

    incident_desc_table = Table(table_data, colWidths=col_widths)
    incident_desc_table.setStyle(table_style)
    
    remediation_table = Table(table_data1, colWidths=col_widths)
    remediation_table.setStyle(table_style)
    
    L.append(incident_desc_table)
    L.append(spacer)
    L.append(remediation_header)
    L.append(spacer)
    L.append(remediation_table)
    L.append(spacer)
    L.append(Conclusion_header)
    L.append(spacer)
    L.append(conclusion_body)


    # Building the story
    story = L # (alternative, story.add(L))
    story.append(KeepTogether([]))
    
    buffer = BytesIO()

    # Establish a document
    doc = SimpleDocTemplate(buffer, pagesize=letter)


    # Creating a page template
    frontpage = PageTemplate(id='FrontPage',
                             frames=[text_frame]
                             )
    # Adding the story to the template and template to the document
    doc.addPageTemplates(frontpage)

    # Building doc
    doc.build(story)

    return buffer
