# Not just usbpcap

**Flag:** `hitcon{secret-flags-unveiled-with-bluetooth-radio}`

The first thing I noticed in the pcapng were a bunch of USB interrupts. Using a USB packet parser like [this](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) I was able to decrypt a message.

```
rraaddiioo..cchhaall..hhiittccoonnccttff..ccoomm
Sssoorrrryy,,  nnoo  ffllaagg  hheerree..  Tttrryy  hhaarrddeerr..
Buutt  ii  ccaann  tteellll  yyoouu  tthhaatt  tthhee  ffllaagg  ffoorrmmaatt  iiss  hhiittccoonn{lloowweerr--ccaassee--eenngglliisshh--sseeppaarraatteedd--wwiitthh--ddaasshh}
Aggaaiinn,,  tthhiiss  iiss  nnoott  tthhee  ffllaagg  :(
C88776633!
```

There is also an audio stream in the file, which I selected and extracted to its own file `audio.pcapng`. I then tried to connect the payloads together, but kept getting errors.

After hours of trying, I was eventually forced to consult a [writeup](https://github.com/t510599/My-CTF-Challenges/tree/master/HITCON%20CTF/2023/Not%20Just%20usbpcap) of this challenge, which explained that:

1. The audio file is in an LATM stream
2. The stream must be converted to one with a LOAS header for `ffmpeg` to recognize it.

I made a modified version of the solve script I saw and got an audio transcript from the LOAS output. That gave me the flag, a sequence of words which I put in the format that I had found earlier in the text.

```py
import scapy.utils

LOAS_SYNC = 0x2b7
LATM_HEADER = b"\x47\xfc\x00\x00"

capture = scapy.utils.rdpcap('./audio.pcapng')

with open('out.loas', "wb") as f:
    for p in capture:
        data = bytes(p)
        payload = data[data.index(LATM_HEADER):]

        loas_header = (LOAS_SYNC << 13) + (len(payload) & 0x1fff)
        f.write(loas_header.to_bytes(3, 'big'))
        f.write(payload)
```

```
Welcome back to "Secret Flags Unveiled" on HITCON Radio! I'm John, your host for this intriguing journey into the world of secret flags.

Today, we'll explore the secret flag, where flag served as vital information for scoring in CTFs.

The secret flags are crucial to the success of HITCON CTF, and one of them is going to be revealed. Listen carefully, you get only one chance.

Flag start.
secret flags unveiled with bluetooth radio.
Flag end.

Just simply wrap the text you heard with the flag format. If you find some information missing, just dig deeper in the packet.

Stay tuned for more secret flags. This is John, signing off from "Secret Flags Unveiled" on HITCON Radio. Keep those flags flying high!
```

