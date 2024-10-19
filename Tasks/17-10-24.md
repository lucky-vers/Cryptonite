# TCP1P - Lost Progress

```
My friend Andi just crashed his computer and all the progress he made are gone. It was 2 of his secret passwords with each of them being inside an image and a text file. Luckily he has an automatic RAM capture program incase something like this happen, but no idea on how to use it...
```

Memdump challenge. I threw everything I had at it

- `filescan`, `netscan`, `pslist` analysis.
- dumping all files, then dumping by PIDs of programs like `code.exe` and `notepad.exe`.
- running the usual `strings`, `binwalk`, stego stuff on file dumps.
- running `strings` on the dump itself out of desperation.

I found a file `Temp\hmm.txt` and tried dumping it but to no avail. It was the last chal I tried before the CTF ended and I spent a good bit of time both in NLH and in my room trying to figure something out.

When the CTF ended, I found a writeup for it, containing something I entirely overlooked — dumping the contents of `gimp.exe` and opening it in Gimp. I had never even thought of that, since I've never seen Gimp used like this in a chal before.

**New thing I learned:**

1. More knowledge of volatility3 plugins generally
2. Greater situational knowledge of memory forensics — namely that when you see a `gimp.exe` being run, dump it.

Writeup (more of a short comment) of the chal I read: https://discord.com/channels/1127235720629723176/1293109191912718376/1295048228718514257

# TCP1P - Serial

Was supposed to be a simple crackme, but all of us couldn't solve it despite it having 70+ solves.

We're given a .NET exe with 2 inputs. Decompiling using dnSpy we get a `checkSerial` function.

One problem we were facing was that the `checkSerial` function wasn't decompiling correctly. Here's the full function I found after much effort from a writeup:

```c
// Serial, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// <Module>
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using std;

[return: MarshalAs(UnmanagedType.U1)]
internal unsafe static bool checkSerial(basic_string<char,std::char_traits<char>,std::allocator<char> >* szName, basic_string<char,std::char_traits<char>,std::allocator<char> >* szSerial)
{
	//IL_00a2: Expected I, but got I8
	//IL_02af: Expected I, but got I8
	//IL_02cb: Expected I, but got I8
	//IL_02e2: Expected I, but got I8
	//IL_0318: Expected I, but got I8
	//IL_0328: Expected I, but got I8
	//IL_017e: Expected I, but got I8
	//IL_0190: Expected I, but got I8
	//IL_019f: Expected I, but got I8
	//IL_00f6: Expected I, but got I8
	//IL_0108: Expected I, but got I8
	//IL_0117: Expected I, but got I8
	//IL_0338: Expected I, but got I8
	//IL_0348: Expected I, but got I8
	//IL_0358: Expected I, but got I8
	//IL_0368: Expected I, but got I8
	//IL_0378: Expected I, but got I8
	//IL_0388: Expected I, but got I8
	//IL_00ae->IL00b1: Incompatible stack types: I vs I8
	System.Runtime.CompilerServices.Unsafe.SkipInit(out vector<int,std::allocator<int> > obj);
	try
	{
		try
		{
			int num = 0;
			int num2 = 0;
			int num3 = 0;
			do
			{
				int num4 = (((num3 ^ 0x7892) + 19760) ^ 0x3421) % 65536;
				if (num4 % 11 == 0)
				{
					num4 /= 11;
					if (num4 <= 1000)
					{
						num = num3;
						num2 = num4;
					}
				}
				num3++;
			}
			while (num3 < 65536);
			num3 = 0;
			int num5 = (int)(*(long*)((ulong)(nint)szName + 16uL));
			int num6 = 0;
			if (num5 <= 0)
			{
				num6 = 0;
			}
			else
			{
				int num7 = 0;
				int num8 = 0;
				int num9 = num * 15 % 256;
				int num10 = num2 * 17 % 256;
				int num11 = 0;
				long num12 = 0L;
				long num13 = num5;
				if (0 < num13)
				{
					basic_string<char,std::char_traits<char>,std::allocator<char> >* ptr = (basic_string<char,std::char_traits<char>,std::allocator<char> >*)((ulong)(nint)szName + 24uL);
					do
					{
						long num14 = (nint)szName;
						if ((ulong)(*(long*)ptr) > 15uL)
						{
							num14 = *(long*)szName;
						}
						sbyte b = (sbyte)toupper(*(sbyte*)(num14 + num12));
						int num15 = (int)((long)(uint)(*(int*)((long)(byte)b * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE)) + num3) % 4294967296L);
						if (num11 % 2 == 0)
						{
							uint* ptr2 = (uint*)((long)(b + 13) * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE));
							uint* ptr3 = (uint*)((long)(b + 47) * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE));
							uint* ptr4 = (uint*)((long)num10 * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE));
							num15 = (int)((long)(uint)(*(int*)((long)num9 * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE)) + (int)((*ptr2 ^ (uint)num15) * *ptr3) + (int)(*ptr4)) % 4294967296L);
							int num16 = (int)((long)(uint)(*(int*)((long)num8 * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE)) + num15) % 4294967296L);
							num6 = num16;
							num3 = num16;
						}
						else
						{
							uint* ptr4 = (uint*)((long)(b + 63) * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE));
							uint* ptr5 = (uint*)((long)(b + 23) * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE));
							uint* ptr6 = (uint*)((long)num10 * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE));
							int num17 = (int)((long)(uint)(*(int*)((long)num9 * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE)) + (int)((*ptr4 ^ (uint)num15) * *ptr5) + (int)(*ptr6)) % 4294967296L);
							int num18 = (int)((long)(uint)(*(int*)((long)num7 * 4L + System.Runtime.CompilerServices.Unsafe.As<vector<unsigned int,std::allocator<unsigned int> >, long>(ref TABLE)) + num17) % 4294967296L);
							num6 = num18;
							num3 = num18;
						}
						num8 = (num8 + 19) % 256;
						num10 = (num10 + 9) % 256;
						num9 = (num9 + 13) % 256;
						num7 = (num7 + 7) % 256;
						num11++;
						num12++;
					}
					while (num12 < num13);
				}
			}
			*(long*)(&obj) = 0L;
			System.Runtime.CompilerServices.Unsafe.As<vector<int,std::allocator<int> >, long>(ref System.Runtime.CompilerServices.Unsafe.AddByteOffset(ref obj, 8)) = 0L;
			System.Runtime.CompilerServices.Unsafe.As<vector<int,std::allocator<int> >, long>(ref System.Runtime.CompilerServices.Unsafe.AddByteOffset(ref obj, 16)) = 0L;
			std.vector<int,std::allocator<int> >._Construct_n<>(&obj, 8uL);
			try
			{
				*(int*)(*(long*)(&obj) + 16) = num6 % 256;
				*(int*)(*(long*)(&obj) + 20) = (num6 >> 8) % 256;
				*(int*)(*(long*)(&obj) + 24) = (num6 >> 16) % 256;
				*(int*)(*(long*)(&obj) + 28) = (num6 >> 24) % 256;
				*(int*)(*(long*)(&obj) + 12) = 156;
				int* ptr7 = (int*)(*(long*)(&obj) + 20);
				*(int*)(*(long*)(&obj) + 8) = (num % 256) ^ *ptr7;
				ptr7 = (int*)(*(long*)(&obj) + 28);
				*(int*)(*(long*)(&obj) + 4) = (num >> 8) ^ *ptr7;
				ptr7 = (int*)(*(long*)(&obj) + 4);
				*(int*)(*(ulong*)(&obj)) = ((*(int*)(*(long*)(&obj) + 24) ^ *ptr7 ^ 0x55) % 256) ^ 0xA7;
				sbyte* ptr8 = (sbyte*)szSerial;
				ulong num19 = *(ulong*)((ulong)(nint)szSerial + 24uL);
				if (num19 > 15)
				{
					ptr8 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr9 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr9 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr10 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr10 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr11 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr11 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr12 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr12 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr13 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr13 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr14 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr14 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte* ptr15 = (sbyte*)szSerial;
				if (num19 > 15)
				{
					ptr15 = (sbyte*)(*(ulong*)szSerial);
				}
				sbyte b2 = *ptr8;
				int num20 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
				b2 = *(sbyte*)((ulong)(nint)ptr8 + 1uL);
				int num21 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
				if (((num20 << 4) | num21) == (*(int*)(*(ulong*)(&obj)) & 0xFF))
				{
					b2 = *(sbyte*)((ulong)(nint)ptr9 + 2uL);
					num20 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
					b2 = *(sbyte*)((long)(nint)ptr9 + 2L + 1);
					int num22 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
					if (((num20 << 4) | num22) == (*(int*)(*(long*)(&obj) + 4) & 0xFF))
					{
						b2 = *(sbyte*)((ulong)(nint)ptr10 + 5uL);
						int num23 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
						b2 = *(sbyte*)((long)(nint)ptr10 + 5L + 1);
						int num24 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
						if (((num23 << 4) | num24) == (*(int*)(*(long*)(&obj) + 8) & 0xFF))
						{
							b2 = *(sbyte*)((ulong)(nint)ptr11 + 7uL);
							int num25 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
							b2 = *(sbyte*)((long)(nint)ptr11 + 7L + 1);
							int num26 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
							if (((num25 << 4) | num26) == (*(int*)(*(long*)(&obj) + 12) & 0xFF))
							{
								b2 = *(sbyte*)((ulong)(nint)ptr12 + 10uL);
								int num27 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
								b2 = *(sbyte*)((long)(nint)ptr12 + 10L + 1);
								int num28 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
								if (((num27 << 4) | num28) == (*(int*)(*(long*)(&obj) + 16) & 0xFF))
								{
									b2 = *(sbyte*)((ulong)(nint)ptr13 + 12uL);
									int num29 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
									b2 = *(sbyte*)((long)(nint)ptr13 + 12L + 1);
									int num30 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
									if (((num29 << 4) | num30) == (*(int*)(*(long*)(&obj) + 20) & 0xFF))
									{
										b2 = *(sbyte*)((ulong)(nint)ptr14 + 15uL);
										int num31 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
										b2 = *(sbyte*)((long)(nint)ptr14 + 15L + 1);
										int num32 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
										if (((num31 << 4) | num32) == (*(int*)(*(long*)(&obj) + 24) & 0xFF))
										{
											b2 = *(sbyte*)((ulong)(nint)ptr15 + 17uL);
											int num33 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
											b2 = *(sbyte*)((long)(nint)ptr15 + 17L + 1);
											int num34 = ((b2 < 48 || b2 > 57) ? ((b2 & -33) - 55) : (b2 - 48));
											if (((num33 << 4) | num34) == (*(int*)(*(long*)(&obj) + 28) & 0xFF))
											{
												goto IL_06a9;
											}
										}
									}
								}
							}
						}
					}
				}
			}
			catch
			{
				//try-fault
				___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<vector<int,std::allocator<int> >*, void>)(&std.vector<int,std::allocator<int> >.{dtor}), &obj);
				throw;
			}
			goto end_IL_0000;
			IL_06a9:
			std.vector<int,std::allocator<int> >._Tidy(&obj);
			goto IL_06c0;
			end_IL_0000:;
		}
		catch
		{
			//try-fault
			___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<basic_string<char,std::char_traits<char>,std::allocator<char> >*, void>)(&std.basic_string<char,std::char_traits<char>,std::allocator<char> >.{dtor}), szName);
			throw;
		}
		goto end_IL_0000_2;
		IL_06c0:
		try
		{
			std.basic_string<char,std::char_traits<char>,std::allocator<char> >._Tidy_deallocate(szName);
		}
		catch
		{
			//try-fault
			___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<_Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>*, void>)(&std._Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>.{dtor}), szName);
			throw;
		}
		goto IL_06e5;
		end_IL_0000_2:;
	}
	catch
	{
		//try-fault
		___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<basic_string<char,std::char_traits<char>,std::allocator<char> >*, void>)(&std.basic_string<char,std::char_traits<char>,std::allocator<char> >.{dtor}), szSerial);
		throw;
	}
	try
	{
		try
		{
			std.vector<int,std::allocator<int> >._Tidy(&obj);
		}
		catch
		{
			//try-fault
			___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<basic_string<char,std::char_traits<char>,std::allocator<char> >*, void>)(&std.basic_string<char,std::char_traits<char>,std::allocator<char> >.{dtor}), szName);
			throw;
		}
		try
		{
			std.basic_string<char,std::char_traits<char>,std::allocator<char> >._Tidy_deallocate(szName);
		}
		catch
		{
			//try-fault
			___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<_Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>*, void>)(&std._Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>.{dtor}), szName);
			throw;
		}
	}
	catch
	{
		//try-fault
		___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<basic_string<char,std::char_traits<char>,std::allocator<char> >*, void>)(&std.basic_string<char,std::char_traits<char>,std::allocator<char> >.{dtor}), szSerial);
		throw;
	}
	try
	{
		std.basic_string<char,std::char_traits<char>,std::allocator<char> >._Tidy_deallocate(szSerial);
	}
	catch
	{
		//try-fault
		___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<_Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>*, void>)(&std._Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>.{dtor}), szSerial);
		throw;
	}
	return false;
	IL_06e5:
	try
	{
		std.basic_string<char,std::char_traits<char>,std::allocator<char> >._Tidy_deallocate(szSerial);
	}
	catch
	{
		//try-fault
		___CxxCallUnwindDtor((delegate*<void*, void>)(delegate*<_Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>*, void>)(&std._Compressed_pair<std::allocator<char>,std::_String_val<std::_Simple_types<char> >,1>.{dtor}), szSerial);
		throw;
	}
	return true;
```

I searched on their Discord after the CTF ended for writeups and this is what I ended up finding — a Python reconstruction of the entire binary and `checkSerial`.

```py
import tkinter as tk
from tkinter import messagebox
import hashlib
from Crypto.Cipher import AES
import binascii

def checkSerial(szName, szSerial):
    # Compute num and num2 based on initial loop
    num = 0
    num2 = 0
    num3 = 0
    while num3 < 65536:
        num4 = (((num3 ^ 0x7892) + 19760) ^ 0x3421) % 65536
        if num4 % 11 == 0:
            num4 //= 11
            if num4 <= 1000:
                num = num3
                num2 = num4
        num3 += 1

    # Initialize variables
    num3 = 0
    num5 = len(szName)
    num6 = 0

    # Initialize TABLE with actual values
    TABLE = [
        969622713, 594890599, 1593930257, 1052452058, 890701766, 1677293387, 394424968, 266815521,
        1532978959, 1211194088, 2019260265, 729421127, 953225874, 1117854514, 892543556, 2000911200,
        514538256, 1400963072, 486675118, 1862498216, 1136668818, 758909582, 1653935295, 821063674,
        888606944, 687085563, 890056597, 1513495898, 365692427, 184357836, 677395407, 863045227,
        818746596, 391985767, 1842768403, 758385145, 1478392706, 1985112985, 1552765320, 746944881,
        368385984, 1758203153, 1240817244, 660489060, 756944316, 1290697955, 844453952, 288239112,
        1769473626, 1922176006, 826636519, 391520695, 1081548223, 1069693142, 1244729994, 766313326,
        1101031894, 624951698, 14501479, 1794907983, 1460682958, 1660839647, 1104890686, 897721119,
        1442187162, 480708164, 454443986, 1064446153, 1595150448, 1041527979, 1145775470, 1399869657,
        255985995, 802693350, 2005610078, 1897360642, 2146073193, 1538606632, 431647857, 964049561,
        395138253, 19164808, 856904574, 730737943, 708645054, 1506870658, 933323739, 819349658,
        1780571206, 236747382, 533160167, 2042104933, 670325172, 2040165158, 1354372994, 705785180,
        1669754395, 1066536508, 1426207888, 1437950089, 741941201, 796931522, 1694313338, 1290302874,
        1367672048, 2039808424, 1062939821, 954597728, 1668694488, 859122242, 1369582617, 140269649,
        53024683, 729221831, 816609203, 736893191, 55706320, 262747091, 1629838835, 581764799,
        1488480625, 1607077349, 1879925846, 1453945819, 1521965565, 856558562, 1530662365, 1230847072,
        1404918182, 1281256849, 1238970765, 272453753, 1640907491, 2127893021, 350314733, 556617458,
        654390256, 1648581270, 531062411, 1862873022, 1241517385, 1471028336, 5121143, 1444839026,
        1183580211, 1573659650, 2018540230, 1487873223, 234237236, 898254600, 1023090193, 728843548,
        2007454357, 1451820833, 267351539, 302982385, 26807015, 865879122, 664886158, 195503981,
        1625037691, 1330347906, 1742434311, 1330272217, 1645368040, 542321916, 1782121222, 411042851,
        435386250, 1176704752, 1454246199, 1136813916, 1707755005, 224415730, 201138891, 989750331,
        1006010278, 1147286905, 406860280, 840388503, 1282017578, 1605698145, 23396724, 862145265,
        1898780916, 1855549801, 1571519230, 2083204840, 1859876276, 1602449334, 1009413590, 690816450,
        86131931, 345661263, 1565025600, 857544170, 1329948960, 1211787679, 994381573, 991984748,
        1956475134, 1098146294, 1655714289, 659576699, 689116467, 1485584392, 451884118, 255590636,
        2108114754, 1266252396, 1589326471, 2019907768, 15552498, 1651075358, 614606175, 1656823678,
        797605325, 1681594366, 2005080248, 624648446, 884695971, 1526931791, 1595240948, 439447199,
        2060396292, 680093752, 409028215, 469068267, 195583689, 1791650630, 507724330, 1364025102,
        1094582668, 813049577, 32316922, 1240756058, 1176200235, 2104494066, 325396055, 1796606917,
        1709197385, 525495836, 1510101430, 735526761, 767523533, 1374043776, 1559389967, 567085571,
        1560216161, 867042846, 1001796703, 1568754293, 628841972, 173812827, 379868455, 384973125
    ]

    if num5 > 0:
        num7 = 0
        num8 = 0
        num9 = num * 15 % 256
        num10 = num2 * 17 % 256
        num11 = 0
        num12 = 0
        num13 = num5

        while num12 < num13:
            b = ord(szName[num12].upper())
            num15 = (TABLE[b % 256] + num3) % (2**32)
            if num11 % 2 == 0:
                index1 = (b + 13) % 256
                index2 = (b + 47) % 256
                num15 = (TABLE[num9 % 256] + ((TABLE[index1] ^ num15) * TABLE[index2]) + TABLE[num10 % 256]) % (2**32)
                num6 = (TABLE[num8 % 256] + num15) % (2**32)
                num3 = num6
            else:
                index1 = (b + 63) % 256
                index2 = (b + 23) % 256
                num15 = (TABLE[num9 % 256] + ((TABLE[index1] ^ num15) * TABLE[index2]) + TABLE[num10 % 256]) % (2**32)
                num6 = (TABLE[num7 % 256] + num15) % (2**32)
                num3 = num6
            num8 = (num8 + 19) % 256
            num10 = (num10 + 9) % 256
            num9 = (num9 + 13) % 256
            num7 = (num7 + 7) % 256
            num11 += 1
            num12 += 1

    # Create vector of integers based on computed values
    vec = [0] * 8
    vec[4] = num6 % 256
    vec[5] = (num6 >> 8) % 256
    vec[6] = (num6 >> 16) % 256
    vec[7] = (num6 >> 24) % 256
    vec[3] = 156
    vec[2] = (num % 256) ^ vec[5]
    vec[1] = (num >> 8) ^ vec[7]
    vec[0] = ((vec[6] ^ vec[1] ^ 0x55) % 256) ^ 0xA7

    # Extract hexadecimal pairs from the serial number
    try:
        serial_parts = szSerial.split('-')
        if len(serial_parts) != 4 or any(len(part) != 4 for part in serial_parts):
            return False  # Invalid serial format

        serial_pairs = [
            serial_parts[0][0:2],
            serial_parts[0][2:4],
            serial_parts[1][0:2],
            serial_parts[1][2:4],
            serial_parts[2][0:2],
            serial_parts[2][2:4],
            serial_parts[3][0:2],
            serial_parts[3][2:4]
        ]

        for i in range(8):
            # Convert each pair to an integer
            s = serial_pairs[i]
            b = int(s, 16)
            if b != (vec[i] & 0xFF):
                return False
        return True
    except:
        # If any error occurs during processing, return False
        return False

def generateSerial(szName):
    # Compute num and num2 based on initial loop
    num = 0
    num2 = 0
    num3 = 0
    while num3 < 65536:
        num4 = (((num3 ^ 0x7892) + 19760) ^ 0x3421) % 65536
        if num4 % 11 == 0:
            num4 //= 11
            if num4 <= 1000:
                num = num3
                num2 = num4
        num3 += 1

    # Initialize variables
    num3 = 0
    num5 = len(szName)
    num6 = 0

    # Initialize TABLE with actual values
    TABLE = [
        969622713, 594890599, 1593930257, 1052452058, 890701766, 1677293387, 394424968, 266815521,
        1532978959, 1211194088, 2019260265, 729421127, 953225874, 1117854514, 892543556, 2000911200,
        514538256, 1400963072, 486675118, 1862498216, 1136668818, 758909582, 1653935295, 821063674,
        888606944, 687085563, 890056597, 1513495898, 365692427, 184357836, 677395407, 863045227,
        818746596, 391985767, 1842768403, 758385145, 1478392706, 1985112985, 1552765320, 746944881,
        368385984, 1758203153, 1240817244, 660489060, 756944316, 1290697955, 844453952, 288239112,
        1769473626, 1922176006, 826636519, 391520695, 1081548223, 1069693142, 1244729994, 766313326,
        1101031894, 624951698, 14501479, 1794907983, 1460682958, 1660839647, 1104890686, 897721119,
        1442187162, 480708164, 454443986, 1064446153, 1595150448, 1041527979, 1145775470, 1399869657,
        255985995, 802693350, 2005610078, 1897360642, 2146073193, 1538606632, 431647857, 964049561,
        395138253, 19164808, 856904574, 730737943, 708645054, 1506870658, 933323739, 819349658,
        1780571206, 236747382, 533160167, 2042104933, 670325172, 2040165158, 1354372994, 705785180,
        1669754395, 1066536508, 1426207888, 1437950089, 741941201, 796931522, 1694313338, 1290302874,
        1367672048, 2039808424, 1062939821, 954597728, 1668694488, 859122242, 1369582617, 140269649,
        53024683, 729221831, 816609203, 736893191, 55706320, 262747091, 1629838835, 581764799,
        1488480625, 1607077349, 1879925846, 1453945819, 1521965565, 856558562, 1530662365, 1230847072,
        1404918182, 1281256849, 1238970765, 272453753, 1640907491, 2127893021, 350314733, 556617458,
        654390256, 1648581270, 531062411, 1862873022, 1241517385, 1471028336, 5121143, 1444839026,
        1183580211, 1573659650, 2018540230, 1487873223, 234237236, 898254600, 1023090193, 728843548,
        2007454357, 1451820833, 267351539, 302982385, 26807015, 865879122, 664886158, 195503981,
        1625037691, 1330347906, 1742434311, 1330272217, 1645368040, 542321916, 1782121222, 411042851,
        435386250, 1176704752, 1454246199, 1136813916, 1707755005, 224415730, 201138891, 989750331,
        1006010278, 1147286905, 406860280, 840388503, 1282017578, 1605698145, 23396724, 862145265,
        1898780916, 1855549801, 1571519230, 2083204840, 1859876276, 1602449334, 1009413590, 690816450,
        86131931, 345661263, 1565025600, 857544170, 1329948960, 1211787679, 994381573, 991984748,
        1956475134, 1098146294, 1655714289, 659576699, 689116467, 1485584392, 451884118, 255590636,
        2108114754, 1266252396, 1589326471, 2019907768, 15552498, 1651075358, 614606175, 1656823678,
        797605325, 1681594366, 2005080248, 624648446, 884695971, 1526931791, 1595240948, 439447199,
        2060396292, 680093752, 409028215, 469068267, 195583689, 1791650630, 507724330, 1364025102,
        1094582668, 813049577, 32316922, 1240756058, 1176200235, 2104494066, 325396055, 1796606917,
        1709197385, 525495836, 1510101430, 735526761, 767523533, 1374043776, 1559389967, 567085571,
        1560216161, 867042846, 1001796703, 1568754293, 628841972, 173812827, 379868455, 384973125
    ]

    if num5 > 0:
        num7 = 0
        num8 = 0
        num9 = num * 15 % 256
        num10 = num2 * 17 % 256
        num11 = 0
        num12 = 0
        num13 = num5

        while num12 < num13:
            b = ord(szName[num12].upper())
            num15 = (TABLE[b % 256] + num3) % (2**32)
            if num11 % 2 == 0:
                index1 = (b + 13) % 256
                index2 = (b + 47) % 256
                num15 = (TABLE[num9 % 256] + ((TABLE[index1] ^ num15) * TABLE[index2]) + TABLE[num10 % 256]) % (2**32)
                num6 = (TABLE[num8 % 256] + num15) % (2**32)
                num3 = num6
            else:
                index1 = (b + 63) % 256
                index2 = (b + 23) % 256
                num15 = (TABLE[num9 % 256] + ((TABLE[index1] ^ num15) * TABLE[index2]) + TABLE[num10 % 256]) % (2**32)
                num6 = (TABLE[num7 % 256] + num15) % (2**32)
                num3 = num6
            num8 = (num8 + 19) % 256
            num10 = (num10 + 9) % 256
            num9 = (num9 + 13) % 256
            num7 = (num7 + 7) % 256
            num11 += 1
            num12 += 1

    # Create vector of integers based on computed values
    vec = [0] * 8
    vec[4] = num6 % 256
    vec[5] = (num6 >> 8) % 256
    vec[6] = (num6 >> 16) % 256
    vec[7] = (num6 >> 24) % 256
    vec[3] = 156
    vec[2] = (num % 256) ^ vec[5]
    vec[1] = (num >> 8) ^ vec[7]
    vec[0] = ((vec[6] ^ vec[1] ^ 0x55) % 256) ^ 0xA7

    # Generate the serial number from the vector with hyphens
    serial_parts = [
        "{:02X}".format(vec[0]),
        "{:02X}".format(vec[1]),
        "{:02X}".format(vec[2]),
        "{:02X}".format(vec[3]),
        "{:02X}".format(vec[4]),
        "{:02X}".format(vec[5]),
        "{:02X}".format(vec[6]),
        "{:02X}".format(vec[7])
    ]

    # Construct the serial string with hyphens
    serial = ''.join(serial_parts[0:2]) + '-' + ''.join(serial_parts[2:4]) + '-' + ''.join(serial_parts[4:6]) + '-' + ''.join(serial_parts[6:8])

    return serial

def decrypt_flag(serial, flag):
    try:
        # Prepare the IV (serial without hyphens, as bytes)
        bytes_iv = serial.replace("-", "").encode('ascii')

        # Prepare the key (MD5 hash of serial with hyphens)
        key = hashlib.md5(serial.encode('ascii')).digest()

        # Convert the flag hex string to bytes
        array2 = binascii.unhexlify(flag)

        # Set up AES cipher with no padding
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes_iv)

        # Decrypt the data
        decrypted_data = cipher.decrypt(array2)

        # Find the last occurrence of '}' (ASCII 125) in decrypted_data
        num3 = len(decrypted_data)
        num4 = num3 - 1
        while num4 >= 0:
            if decrypted_data[num4] == 125:  # ord('}')
                break
            num3 -= 1
            num4 -= 1

        # Get the message up to num3
        message = decrypted_data[:num3+1].decode('utf-8', errors='ignore')

        # Show the message
        messagebox.showinfo("Flag", message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt flag: {str(e)}")

def check_license():
    name = name_entry.get()
    serial = serial_entry.get()
    if len(name) != 0:
        generated_serial = generateSerial(name)
        print(f"Generated Serial: {generated_serial}")  # Debug print to console
        if serial.upper() == generated_serial:
            messagebox.showinfo("Good!", "That is a valid serial!")
            if name == "Administrator":
                decrypt_flag(serial, "6a2b68f955d492a677f3bd5d22a078a39ca10936ef89cb12823617a1e1bc4d1c")
        else:
            messagebox.showerror("Error", "Invalid serial information!")
    else:
        messagebox.showerror("Error", "Invalid serial information!")

def generate_serial_action():
    name = name_entry.get()
    if len(name) != 0:
        generated_serial = generateSerial(name)
        serial_entry.delete(0, tk.END)
        serial_entry.insert(0, generated_serial)
        print(f"Generated Serial: {generated_serial}")  # Debug print to console
    else:
        messagebox.showerror("Error", "Please enter a name to generate the serial.")

# Create the GUI
root = tk.Tk()
root.title("Serial Checker")
root.geometry("300x220")
root.resizable(False, False)

# Name label and entry
name_label = tk.Label(root, text="Name:")
name_label.place(x=20, y=20)
name_entry = tk.Entry(root, width=20)
name_entry.place(x=100, y=20)

# Serial label and entry
serial_label = tk.Label(root, text="Serial:")
serial_label.place(x=20, y=50)
serial_entry = tk.Entry(root, width=20)
serial_entry.place(x=100, y=50)

# Check Serial button
check_button = tk.Button(root, text="Check Serial", command=check_license)
check_button.place(x=100, y=90)

# Generate Serial button
generate_button = tk.Button(root, text="Generate Serial", command=generate_serial_action)
generate_button.place(x=100, y=130)

# Start the GUI loop
root.mainloop()
```

Someone also solved it by just setting the right breakpoints in `checkSerial`.

**New thing I learned:**

 - dnSpy reversing, I've not done it much surprisingly despite my summer specialization being in Windows rev.
 - Set breakpoints if possible, debugging can often reveal the flag much more easily.

