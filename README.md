# Auth_user.py
essentially this is just a simple raw socket connection attempt that tries to create a user and password setting user to uid 0. My goal is that if I am acting on the system level i can bypass aspects of the OS in user creation to escalate privileges without having to pivot to much.I understand that unless there is a vulnerability this would likely never work however it is a project that i initially started as a script to run off of a USB and wantedto try using sockets, ctypes, and other imports I had not used.


#Usage
python auth_usr.py --add --username gbeardfist --password 12345 --servers <target IP 1> <target IP 2> --ports <port> <port>
