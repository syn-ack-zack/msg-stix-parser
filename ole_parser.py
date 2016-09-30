from __future__ import absolute_import

import datetime
import email as eml
from email.parser import Parser
from email.utils import parseaddr, getaddresses, mktime_tz, parsedate_tz
import hashlib
import json
import magic
import re
import yaml
import io
import sys
import olefile

from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.utils import set_id_namespace as set_stix_id_namespace
from cStringIO import StringIO
from cybox.common import Hash
from cybox.core import Observables
from cybox.core.observable import Observable, ObservableComposition
from cybox.objects.address_object import Address
from cybox.common import (DateTime, HexBinary, MeasureSource, String,
        StructuredText, ToolInformation, ToolInformationList)
from cybox.objects.email_message_object import (Attachments, EmailHeader,
        EmailMessage, EmailRecipients, LinkReference, Links, ReceivedLine,
        ReceivedLineList)
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.utils import Namespace, set_id_namespace
from dateutil.parser import parse as date_parser


def _get_received_from(received_header):
    """
    Helper function to grab the 'from' part of a Received email header.
    """

    received_header = received_header.replace('\r', '').replace('\n', '')
    info = received_header.split('by ')
    try:
        return info[0]
    except:
        ''
def _get_received_by(received_header):
    """
    Helper function to grab the 'by' part of a Received email header.
    """

    received_header = received_header.replace('\r', '').replace('\n', '')
    info = received_header.split('by ')
    try:
        return info[-1].split('for ')[0]
    except:
        return ''

def _get_received_for(received_header):
    """
    Helper function to grab the 'for' part of a Received email header
    WARNING: If 'for' is not there, the entire Received header is returned.
    """

    received_header = received_header.replace('\r', '').replace('\n', '')
    info = received_header.split('for ')
    try:
        return info[-1].split(';')[0]
    except:
        return ''

def _get_received_date(received_header):
    """
    Helper function to grab the date part of a Received email header.
    """

    received_header = received_header.replace('\r', '').replace('\n', '')
    date = received_header.split(';')
    try:
        return date[-1]
    except:
        ''
def _is_reserved_ip(ip):
    """
    Simple test to detect if an IP is private or loopback. Does not check
    validity of the address.
    """

    grp = re.match(r'127.\d{1,3}.\d{1,3}.\d{1,3}', ip) # 127.0.0.0/8
    if grp:
        return True
    grp = re.match(r'10.\d{1,3}.\d{1,3}.\d{1,3}', ip) # 10.0.0.0/8
    if grp:
        return True
    grp = re.match(r'192.168.\d{1,3}.\d{1,3}', ip) # 192.168.0.0/16
    if grp:
        return True
    grp = re.match(r'172.(1[6-9]|2[0-9]|3[0-1]).\d{1,3}.\d{1,3}', ip) # 172.16.0.0/12
    if grp:
        return True
    # No matches
    return False

def _create_cybox_headers(msg):

    headers = EmailHeader()

    if 'to' in msg:
        headers.to = msg['to']
        if 'delivered-to' in msg and not headers.to:
            headers.to = msg['delivered-to']
    if 'cc' in msg:
        headers.cc = msg['cc']
    if 'bcc' in msg:
        headers.bcc = msg['bcc']
    if 'from' in msg:
        headers.from_ = msg['from']
    if 'sender' in msg:
        headers.sender = msg['sender']
    if 'reply-to' in msg:
        headers.reply_to = msg['reply-to']
    if 'subject' in msg:
        headers.subject = String(msg['subject'])
    if 'in-reply-to' in msg:
        headers.in_reply_to = String(msg['in-reply-to'])
    if 'errors-to' in msg:
        headers.errors_to = String(msg['errors-to'])
    if 'date' in msg:
        headers.date = DateTime(msg['date'])
    if 'message-id' in msg:
        headers.message_id = String(msg['message-id'])
    if 'boundary' in msg:
        headers.boundary = String(msg['boundary'])
    if 'content-type' in msg:
        headers.content_type = String(msg['content-type'])
    if 'mime-version' in msg:
        headers.mime_version = String(msg['mime-version'])
    if 'precedence' in msg:
        headers.precedence = String(msg['precedence'])
    if 'user-agent' in msg:
        headers.user_agent = String(msg['user-agent'])
    if 'x-mailer' in msg:
        headers.x_mailer = String(msg['x-mailer'])
    if 'x-originating-ip' in msg:
        headers.x_originating_ip = Address(msg['x-originating-ip'],
                                           Address.CAT_IPV4)

    return headers


def _create_cybox_files(attachments):
        """Returns a list of CybOX File objects from the message.

        Attachments can be identified within multipart messages by their
        Content-Disposition header.
        Ex: Content-Disposition: attachment; filename="foobar.jpg"
        """

        files = []

        for attachment in attachments:

            file_name = ""
            if 'name' in attachment:
                file_name = attachment['name']
            file_data = ""
            if 'data' in attachment:
                file_data = attachment['data']
            file_type = ""
            if 'type' in attachment:
                file_type = attachment['type']

            #PGP Encrypted could come back as None and ''
            if file_name or file_data:
                f = File()

                #Do what we can with what came back from the payload parsing
                if file_name and file_type:
                    f.file_name = file_name
                    f.file_type = attachment['type']

                if file_data:
                    f.size = len(file_data)
                    hashes = []
                    hashes.append(hashlib.md5(file_data).hexdigest())
                    hashes.append(hashlib.sha1(file_data).hexdigest())
                    hashes.append(hashlib.sha256(file_data).hexdigest())

                    for hash in hashes:
                        f.add_hash(hash)

                files.append(f)

        return files

def _parse_email_message(msg,attachments):
        
        files       = []
        message     = EmailMessage()

        # Headers are required (for now)
        message.header = _create_cybox_headers(msg)

        files = _create_cybox_files(attachments)
        message.attachments = Attachments()
        for f in files:
            message.attachments.append(f.parent.id_)
            f.add_related(message, "Contained_Within", inline=False)

        raw_headers_str = msg['raw_header']
        if raw_headers_str:
            message.raw_header = String(raw_headers_str)

        raw_body = msg['raw_body']

        message.raw_body = String(raw_body)


        # Return a list of all objects we've built
        return [message] + files



def email_observables_to_stix(email,attachments):
    '''takes a dict of observables, returns stix'''
    xmlns_url = 'https://cardinalhealth.com'
    xmlns_name = 'cardinal_health'
    set_stix_id_namespace({xmlns_url: xmlns_name})

    NS = Namespace(xmlns_url,xmlns_name)
    set_id_namespace(NS)

    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_package.stix_header = stix_header

    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "//node() | //@*"

    tlp = TLPMarkingStructure()
    tlp.color = email['tlp']
    marking_specification.marking_structures.append(tlp)

    handling = Marking()
    handling.add_marking(marking_specification)
   
    indicator_ = Indicator()
    indicator_.title = email['subject']

    d = u""
    for k,v in email.iteritems():
        if k and (k != 'raw_header' and k != 'raw_body') and (v != None or v != ""):
            d += u"%s: %s\n\n" % (k,v)
            #Clean up headers to remove brackets, STIX parser doesn't like it
            d = re.sub(r'\<|\>',"",d)
    d.encode("latin-1","replace")

    indicator_.description = d
        

    indicator_.confidence = 'Unknown'
    indicator_.add_indicator_type('Malicious E-mail')
    observable_composition_ = ObservableComposition()
    observable_composition_.operator = 'OR'
    results = (_parse_email_message(email,attachments))

    for obj in results:
        observable_ = Observable(obj)

        title = ""
        #print(str(observable_.to_dict()) + "\n\n\n---------------------------\n")
        if 'xsi:type' in observable_.to_dict()['object']['properties']:
            title = observable_.to_dict()['object']['properties']['xsi:type']
        else:
            title = "Unknown"

        od = u""
        if 'properties' in observable_.to_dict()['object']:
            for k,v in observable_.to_dict()['object']['properties'].iteritems():
                od += u"%s: %s\n\n" % (k,v)
                #Clean up headers to remove brackets, STIX parser doesn't like it
                od = re.sub(r'\<|\>',"",od)
            od.encode("latin-1","replace")
        observable_.description = od

        observable_.title = title
        observable_composition_.add(observable_)
    
    indicator_.observable = Observable()
    indicator_.observable.observable_composition = observable_composition_
    stix_package.add_indicator(indicator_)
    stix_package.stix_header.handling = handling

    return stix_package.to_xml()


def parse_ole_file(file):
    """
    Parse an OLE2.0 file to obtain data inside an email including attachments.

    References:
    http://www.fileformat.info/format/outlookmsg/
    http://www.decalage.info/en/python/olefileio
    https://code.google.com/p/pyflag/source/browse/src/FileFormats/OLE2.py
    http://cpansearch.perl.org/src/MVZ/Email-Outlook-Message-0.912/lib/Email/Outlook/Message.pm
    """

    header = file.read(len(olefile.MAGIC))

    # Verify the file is in OLE2 format first
    #if header != olefile.MAGIC:
        #return {'error': 'The upload file is not a valid Outlook file. It must be in OLE2 format (.msg)'}

    msg = {'subject': '_0037',
           'body': '_1000',
           'header': '_007D',
           'message_class': '_001A',
           'recipient_email': '_39FE',
           'attachment_name': '_3707',
           'attachment_data': '_3701',
           'attachment_type': '_370E',
    }

    file.seek(0)
    data = file.read()
    msg_file = io.BytesIO(data)
    ole = olefile.OleFileIO(msg_file)

    # Helper function to grab data out of stream objects
    def get_stream_data(entry):
        stream = ole.openstream(entry)
        data = stream.read()
        stream.close()
        return data

    # Parse the OLE streams and get attachments, subject, body, headers, and class
    # The email dict is what will be put into MongoDB for CRITs
    attachments = {}
    email = {}
    email['to'] = []
    for entry in ole.listdir():
        if 'attach' in entry[0]:
            # Attachments are keyed by directory entry in the stream
            # e.g. '__attach_version1.0_#00000000'
            if entry[0] not in attachments:
                attachments[entry[0]] = {}
            if msg['attachment_name'] in entry[-1]:
                attachments[entry[0]].update({'name': get_stream_data(entry).decode('utf-16')})
            if msg['attachment_data'] in entry[-1]:
                attachments[entry[0]].update({'data': get_stream_data(entry)})
            if msg['attachment_type'] in entry[-1]:
                attachments[entry[0]].update({'type': get_stream_data(entry).decode('utf-16')})
        else:
            if msg['subject'] in entry[-1]:
                email['subject'] = get_stream_data(entry).decode('utf-16')
            if msg['body'] in entry[-1]:
                email['raw_body'] = get_stream_data(entry).decode('utf-16')
            if msg['header'] in entry[-1]:
                email['raw_header'] = get_stream_data(entry).decode('utf-16')
            if msg['recipient_email'] in entry[-1]:
                email['to'].append(get_stream_data(entry).decode('utf-16').lower())
            if msg['message_class'] in entry[-1]:
                message_class = get_stream_data(entry).decode('utf-16').lower()
    ole.close()

    # Process headers to extract data
    raw_header = u'%s'%(email.get('raw_header',''))
    print(raw_header)
    headers = Parser().parse(io.StringIO(raw_header), headersonly=True)
    email['from_address'] = headers.get('From', '')
    email['reply_to'] = headers.get('Reply-To', '')
    email['date'] = headers.get('Date', '')
    email['message_id'] = headers.get('Message-ID', '')
    email['x_mailer'] = headers.get('X-Mailer', '')
    email['x_originating_ip'] = headers.get('X-Originating-IP', '')
    email['sender'] = getaddresses(headers.get_all('Sender', '')) # getaddresses returns list [(name, email)]

    # If no sender, set the email address found in From:
    if not email['sender']:
        email['sender'] = getaddresses(headers.get_all('From', ''))
    if len(email['sender']) > 0:
        email['sender'] = email['sender'][0][1]
    else:
        email['sender'] = ''

    # Get list of recipients and add to email['to'] if not already there
    # Some emails do not have a stream for recipients (_39FE)
    to = headers.get_all('To', [])
    cc = headers.get_all('CC', [])
    resent_to = headers.get_all('Resent-To', [])
    resent_cc = headers.get_all('Resent-CC', [])
    recipients = getaddresses(to + cc + resent_to + resent_cc)
    for r in recipients:
        addr = r[1].lower()
        # If BCC then addr could be blank or set to undisclosed-recipients:
        if addr and addr not in email['to'] and not re.match(r'^undisclosed-recipients[:;]?(?::;)?$', addr):
            email['to'].append(addr)

    # Check for encrypted and signed messages. The body will be empty in this case
    # Message classes: http://msdn.microsoft.com/en-us/library/ee200767%28v=exchg.80%29.aspx
    if message_class == 'ipm.note.smime' and not email.has_key('raw_body'):
        email['raw_body'] = '<ENCRYPTED>'
    if message_class == 'ipm.note.smime.multipartsigned' and not email.has_key('raw_body'):
        email['raw_body'] = '<DIGITALLY SIGNED: body in smime.p7m>'

    # Parse Received headers to get Helo and X-Originating-IP
    # This can be unreliable since Received headers can be reordered by gateways
    # and the date may not be in sync between systems. This is best effort based
    # on the date as it appears in the Received header. In some cases there is no
    # Received header present
    #
    # Received: from __ by __ with __ id __ for __ ; date
    #
    # See helper functions _get_received_from, _get_received_by, _get_received_date
    current_datetime = datetime.datetime.now()
    earliest_helo_date = current_datetime
    earliest_ip_date = current_datetime
    email['helo'] = ''
    originating_ip = ''
    last_from = ''
    helo_for = ''
    all_received = headers.get_all('Received')
    email_domain = ''

    if all_received:
        for received in all_received:
            received_from = _get_received_from(received).lower() # from __
            received_by = _get_received_by(received).lower() # by __ with __ id __
            received_for = _get_received_for(received).lower() # for <email>
            date = _get_received_date(received) # date
            try:
                current_date = datetime.datetime.fromtimestamp(mktime_tz(parsedate_tz(date))) # rfc2822 -> Time -> Datetime
            except:
                # Exception will occur if the date is not in the Received header. This could be
                # where the originating IP is. e.g. Received: from 11.12.13.14 by rms-us019 with HTTP
                current_date = datetime.datetime.min

            grp = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', received_from)
            if grp and not _is_reserved_ip(grp.group()) and ' localhost ' not in received_from:
                if email_domain not in received_from and email_domain in received_by:
                    if(current_date < earliest_helo_date):
                        helo_for = parseaddr(received_for.strip())[1]
                        earliest_helo_date = current_date
                        email['helo'] = received_from
                else:
                    last_from = received_from


            if grp and not email['x_originating_ip'] and not _is_reserved_ip(grp.group()):
                if current_date < earliest_ip_date:
                    earliest_ip_date = current_date
                    originating_ip = grp.group()

    # If no proper Helo found, just use the last received_from without a reserved IP
    if not email['helo']:
        email['helo'] = last_from

    # Set the extracted originating ip. If not found, then just use the IP from Helo
    if not email['x_originating_ip']:
        if originating_ip:
            email['x_originating_ip'] = originating_ip
        else:
            grp = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', email['helo'])
            if grp:
                email['x_originating_ip'] = grp.group()

    # Add the email address found in Helo
    if helo_for and '@' in helo_for:
        if helo_for not in email['to']:
            email['to'].append(helo_for)

    # If no Helo date found, then try to use the Date field
    if earliest_helo_date == current_datetime and email['date']:
        earliest_helo_date = datetime.datetime.fromtimestamp(mktime_tz(parsedate_tz(email['date'])))

    return {'email': email, 'attachments': attachments.values(), 'received_date': earliest_helo_date}


def email_to_stix(email_file):

    results = parse_ole_file(email_file)

    email_meta = {}
    if 'email' in results:
        email_meta = results['email']
        email_meta['tlp'] = 'GREEN'


    attachments = {}
    if 'attachments' in results:
        attachments = results['attachments']
    
    return (email_meta,attachments)


def main():
    fp = open(sys.argv[1],'r')
    if fp:
        email_meta,attachments = email_to_stix(fp)
        stix_xml = email_observables_to_stix(email_meta,attachments)
        fp = open("%s.xml"%(sys.argv[1]),'w')
        fp.write(stix_xml)
        fp.close()
    else:
        print("Invalid email file")

if __name__ == '__main__':
    main()