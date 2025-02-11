'''
     _                 _     _      _       _      
    | |   ___  __ __ _| |   /_\  __| |_ __ (_)_ _  
    | |__/ _ \/ _/ _` | |  / _ \/ _` | '  \| | ' \ 
    |____\___/\__\__,_|_| /_/ \_\__,_|_|_|_|_|_||_|
                                                
    Lists all local admins
    Bad programming by JL Dupont
    Version: 20250211

'''
# ----------------------------------------------------------------------------
# (Imports)
# ----------------------------------------------------------------------------
from    datetime        import datetime
from    io              import StringIO
import  os
import  csv
import  re
import  requests
import  time
import  json
import  urllib.parse
import  urllib.request
import  urllib3
import  sys

# ----------------------------------------------------------------------------
# (Global variables)
# ----------------------------------------------------------------------------
G_AADTOKEN      = None
G_HEADERS       = None

# ----------------------------------------------------------------------------
# (Constants)
# ----------------------------------------------------------------------------
C_APPID         = 'xxxxxxx'                                     # App name is 'xxxx'
C_APPSECRET     = 'xxxxx'                                       # Hard coded secret. (Lame).
C_CHECKSSL      = True                                          # Set to False if going through a transparent proxy with SSL inspection
C_TENANTID      = 'xxxxxxx'                                     # Azure tenant ID
C_TXTGREEN      = "\033[92m"
C_TXTRED        = "\033[91m"
C_TXTRST        = "\033[0m"
C_TXTYELLOW     = "\033[93m"
C_NEVER         = '9999-12-31'
C_UNSET         = '1601-01-01'
C_INFILE        = 'hostlist.txt'
C_OUTFILE       = 'localadmin.csv'
C_MAXFAIL       = 5
C_MAXWAIT       = 62

# ----------------------------------------------------------------------------
# (Functions)
# ----------------------------------------------------------------------------
def f_todate(mydate):
    '''
    Convert a date string to a more human-readable format.


    Parameters:
    - mydate (str): The date string to be converted.

    Returns:
    str: A human-readable date representation, or 'Never' if the input is empty or contains specific placeholders.
    '''
    string = str(mydate)
    if len(string) == 0:
        return "Never"
    delimiter = 'T' if 'T' in string else ' '
    nstring = string.split(delimiter, maxsplit=1)[0]
    if nstring in (C_NEVER, C_UNSET):
        nstring = "Never"
    return nstring

def f_givetoken():
    '''
    Get an MS Security Center access token

    Returns:
    - str: The access token.
    '''
    url         = "https://login.microsoftonline.com/%s/oauth2/token" % (C_TENANTID)
    resource_url= 'https://api-us.securitycenter.microsoft.com'
    body        = {
                        'resource'      : resource_url,
                        'client_id'     : C_APPID,
                        'client_secret' : C_APPSECRET,
                        'grant_type'    : 'client_credentials'
                }
    data        = urllib.parse.urlencode(body).encode("utf-8")
    req         = urllib.request.Request(url, data)
    response    = urllib.request.urlopen(req)
    jresponse   = json.loads(response.read())
    aad_token   = jresponse["access_token"]
    return aad_token


def f_giveheader(token):
    '''
    Return API headers to prepare an API call

    Parameters:
    - token (str): The API token.

    Returns:
    - str: The API header.
    '''
    header      = {
                        'Content-Type'  : 'application/json',
                        'Accept'        : 'application/json',
                        'Authorization' : "Bearer " + token
                }
    return header


def f_apicall(url):
    '''
    Makes an API call to the provided URL with global headers, handling rate limits.

    Parameters:
    - url (str): The endpoint URL to make the API request to.

    Returns:
    - dict: A JSON response from the API call.
    '''
    global G_HEADERS

    try:
        response        = requests.get(url, verify=C_CHECKSSL, headers=G_HEADERS)
    except Exception as e:
        print(f"{C_TXTRED} Fatal! {url}: {e}{C_TXTRST}")
        return None
    failcount = 1
    while failcount < C_MAXFAIL:
        failcount += 1
        try:
            jresponse = response.json()
        except:
            continue
        if 'ResourceNotFound' in str(jresponse):
            return None
        if 'error' in jresponse:
            print(f"{C_TXTYELLOW} Warning! Too many requests. Waiting for a few seconds.{C_TXTRST}")
            f_countdown(jresponse)
            G_AADTOKEN      = f_givetoken()                                 # Get a new Azure Active Directory Token
            G_HEADERS       = f_giveheader(G_AADTOKEN)                      # API http headers
            response = requests.get(url,  verify=C_CHECKSSL, headers=G_HEADERS)
        else:
            break
    if failcount > C_MAXFAIL + 1:
        return None
    return jresponse


def f_countdown(jsondata):
    '''
    Displays a countdown timer for the given number of seconds.

    Parameters:
    - n (int): The number of seconds for the countdown.

    Returns: Nothing
    '''

    seconds = re.search(r"\b(\d+)\b seconds", str(jsondata))
    waittime = int(seconds.group(1)) if seconds else C_MAXWAIT
    waittime += 1
    if waittime == 1:
        waittime = C_MAXWAIT
    if waittime > 300:
        waittime = 2 * C_MAXWAIT
    while waittime > 0:
        mins, secs = divmod(waittime, C_MAXWAIT)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        waittime -= 1


# ----------------------------------------------------------------------------
# (Main)
# ----------------------------------------------------------------------------
print(f"{C_TXTGREEN}LocalAdmin{C_TXTRST}")
try:
    os.remove(C_OUTFILE)
except Exception as e:
    print(e)    
if C_CHECKSSL == True:                         # Put the value to False if you go through a transparent proxy
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
G_AADTOKEN              = f_givetoken()                                 
G_HEADERS               = f_giveheader(G_AADTOKEN)
keywords                = ["default", "administrator"]
with open(C_INFILE, 'r') as file:
    for line in file:
        print(f"  {line}", end='')
        users               = f_apicall(f'https://api.securitycenter.microsoft.com/api/machines/{mid}/logonusers')
        oneprint            = False
        if users != None:
            for user in users['value']:
                uid         = user['id']
                lastseen    = user['lastSeen']
                lastseen    = f_todate(lastseen)
                admin       = user['isDomainAdmin']    # isDomainAdmin flag is not limited to DomainAdmin. It's any high privilege
                if admin == True:
                    if not any(keyword in uid for keyword in keywords):
                        with open(C_OUTFILE, 'a') as file:
                            file.write(f'{machine},{mid},{uid},{os},{ver},{lastseen}\n')
                            print(f"{C_TXTRED} {uid}{C_TXTRST}")
                            oneprint = True
                    else:
                        print(f"{C_TXTYELLOW} {uid} {C_TXTRST}")
                        oneprint = True
        if oneprint == False:
            print(f'{C_TXTGREEN} None{C_TXTRST}')
print(f"{C_TXTGREEN}Done.{C_TXTRST}")

# ----------------------------------------------------------------------------
# (End of file)
# ----------------------------------------------------------------------------