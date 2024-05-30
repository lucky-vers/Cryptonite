# Access Granted

**Flag:** `BITSCTF{adolfhitlerrulesallthepeople}`

We're told to extract a password from the memdump first. I first tried to use vol2 on the dump, but it failed and I was forced to use vol3.

I looked around for how to dump passwords in vol3 and found out we use the `windows.hashdump` command. Using it, we successfully get the hashes of MogamBro.

```
~/Downloads $ python3 volatility3/vol.py -f ~/Projects/Cryptonite/T*/F*\ -\ June\ */C*/F*/m*/memdump.mem windows.hashdump
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        8a320467c7c22e321c3173e757194bb3
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount  503     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount      504     aad3b435b51404eeaad3b435b51404ee        74d0db3c3f38778476a44ff9ce0aefe2
MogamBro        1000    aad3b435b51404eeaad3b435b51404ee        8a320467c7c22e321c3173e757194bb3
```

We have the nthash and the lmhash. Dumping them both into a hash decryption website like CrackStation, we get the password as `adolfhitlerrulesallthepeople`.

![password](../../../Images/1717068448663540153.png)

