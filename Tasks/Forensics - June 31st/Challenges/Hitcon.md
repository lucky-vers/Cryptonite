# Not just usbpcap

The first thing I noticed in the pcapng were a bunch of USB interrupts. Using a USB packet parser like [this](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) I was able to decrypt a message.

```
rraaddiioo..cchhaall..hhiittccoonnccttff..ccoomm
Sssoorrrryy,,  nnoo  ffllaagg  hheerree..  Tttrryy  hhaarrddeerr..
Buutt  ii  ccaann  tteellll  yyoouu  tthhaatt  tthhee  ffllaagg  ffoorrmmaatt  iiss  hhiittccoonn{lloowweerr--ccaassee--eenngglliisshh--sseeppaarraatteedd--wwiitthh--ddaasshh}
Aggaaiinn,,  tthhiiss  iiss  nnoott  tthhee  ffllaagg  :(
C88776633!
```
