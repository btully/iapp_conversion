# Big-IP iApp Converstion Utility

Set of python scripts that will assist in the conversion of iApps


### Prerequisites


Python - https://www.python.org/

Git CLI Client (not required if downloading from Git website via browser)


### Installing

```
# cd <working directory>
# git clone https://github.com/btully/iapp_conversion.git
# cd ./iapp_conversion
# pip install -r requirements.txt
```
---
## Script:  convert_iapp_as3.py

This script converts iApp deployed Big-IP configurations to AS3 declarations.  Each iApp will result in an AS3 tenant declaration  
> :warning: **Please be aware that this script will only convert a specific set of F5 customer templates and will not work for generalized iApp implementations**

### Script Usage
```
# python convert_iapp_as3.py -h
usage: convert_iapp_ni.py [-h] --host HOST --username USERNAME
                          [--password PASSWORD] [--iapp IAPP]
                          [--from-file FROM_FILE] [--all]

F5 Big-IP iApp conversion utility

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           BIG-IP IP or Hostname
  --username USERNAME   BIG-IP Username
  --password PASSWORD   BIG-IP Password (optional)
  --iapp IAPP           iApp Name. When specified this will be the only
                        converted iApp (optional)
  --from-file FROM_FILE Source file containing an iApp name per line (optional)
  --all                 Convert all iApps (optional)
```

Enter password at prompt
```
# User: admin, enter your password:
```

Example Source file (used with --from-file option).  Make sure to place one iApp name per line.
``` 
# cat iapps.txt 
iapp-example1
iapp-example2
iapp-example3
```
---
## Script:  convert_iapp_ni.py

This script converts iApp deployed Big-IP configurations to conventional conventional configuration objects.  
> :warning: **Please be aware that this script will only convert a specific set of F5 customer templates and will not work for generalized iApp implementations**

### Script Usage
```
# python convert_iapp_ni.py -h
usage: convert_iapp_ni.py [-h] --host HOST --username USERNAME
                          [--password PASSWORD] [--iapp IAPP]
                          [--from-file FROM_FILE] [--all]

F5 Big-IP iApp conversion utility

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           BIG-IP IP or Hostname
  --username USERNAME   BIG-IP Username
  --password PASSWORD   BIG-IP Password (optional)
  --iapp IAPP           iApp Name. When specified this will be the only
                        converted iApp (optional)
  --from-file FROM_FILE Source file containing an iApp name per line (optional)
  --all                 Convert all iApps (optional)
```

Enter password at prompt
```
# User: admin, enter your password:
```

Example Source file (used with --from-file option).  Make sure to place one iApp name per line.
``` 
# cat iapps.txt 
iapp-example1
iapp-example2
iapp-example3
```
---
## Script:  get_all_iapps.py
This script will retrieve a full list of iApps from a Big-IP and outputs the list to a file.  One iApp name per line.
### Script Usage
```
# python get_all_iapps.py -h
usage: get_all_iapps.py [-h] --host HOST --username USERNAME
                        [--password PASSWORD]

F5 Big-IP iApp conversion utility

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          BIG-IP IP or Hostname
  --username USERNAME  BIG-IP Username
  --password PASSWORD  BIG-IP Password (optional)
```
---
## Script:  export_iapp.py
This script will retrieve an iApp configuration from a Big-IP and outputs the information to a json file.
### Script Usage
```
# python export_iapp.py -h
usage: export_iapp.py [-h] --host HOST --username USERNAME --iapp IAPP
                      [--password PASSWORD]

F5 Big-IP iApp conversion utility

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          BIG-IP IP or Hostname
  --username USERNAME  BIG-IP Username
  --password PASSWORD  BIG-IP Password (optional)
  --iapp IAPP          iApp Name to be exported

```
---
