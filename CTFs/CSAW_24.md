# OSINT -  Literally 1984

```
An artist by the name of ‌ made a cover of a song I liked, but I don't remember the original composer of that song. Could you help me find the original composer?
```

**Flag:** `csawctf{Susumu_Hirasawa}`

I first noticed the \u200c character in the description and searched all across the web for artists with that name. Eventually I remembered the artist `x0o0x` with an empty YouTube username who posted vocaloid songs without any title too.

I checked the Vocaloid wiki for all their songs, and which ones they made were covers. I eventually landed on their cover of "Big Brother" by Susumu Hirasawa. And sure enough, the flag was `csawctf{Susumu_Hirasawa}`

## References

- https://vocaloid.fandom.com/wiki/XYXYZ
- https://www.reddit.com/r/x0o0x/comments/s97rfe/unofficial_complete_x0o0x_video_playlist/
- https://www.youtube.com/watch?v=5lrseDtxX_E
- https://www.youtube.com/watch?v=mI8KKipWEp4

## OSINT - Mystery

```
Remember the composer from Literally 1984? Well, they made a song when they were part of a band in 1992, and it turns out that ‌ also made a cover of this song, collabing with another artist. What is the name of that artist?
```

**Flag:** `csawctf{Chogakusei}`

Similar to the challenge `Literally 1984`, I went through all the songs of `x0o0x` and found the correct collab to be their one with Chogakusei titled "LAB=01", giving the flag `csawctf{Chogakusei`.

## References

- https://www.reddit.com/r/x0o0x/comments/s97rfe/unofficial_complete_x0o0x_video_playlist/
- https://www.youtube.com/watch?v=mI8KKipWEp4

## Forensics -  Is there an echo

```
Maybe next time you should record your music in an acoustically treated space.
```

I attempted this but did not get to solve it before the CTF ended.

I did a lot of research on echo hiding techniques. I found a MatLab script and tried it on the wave file, but it gave nothing.

Then I looked closer at the wave file. The audio was 89.6 seconds. I noticed a repeating pattern of around 9 peaks. This repeated, albiet slightly modified each time, 14 times, 6.4 seconds per instance.

I tried using a frequency domain analysis of the audio as well, but that returned nothing too.

## References

- https://github.com/ktekeli/audio-steganography-algorithms/tree/master/02-Echo-Hiding
- https://ietresearch.onlinelibrary.wiley.com/doi/full/10.1049/iet-spr.2019.0376
- https://medium.com/@evarostiana22/implementation-of-steganography-in-audio-files-with-the-echo-hiding-method-12086218fb6b
- https://link.springer.com/chapter/10.1007/3-540-61996-8_48
- https://www.researchgate.net/publication/257879537_Comparative_Study_of_Digital_Audio_Steganography_Techniques

