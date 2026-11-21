/* Source for thin-arm64-header.bin. Only the 32-byte header and sizeofcmds
 * bytes of load commands are retained. Built on Linux with:
 * clang -target arm64-apple-macos11 -nostdlib -fuse-ld=lld -Wl,-e,_main main.c -o thin
 * LLVM clang 22.1.8 with LLD. No code, paths or credentials are included in the fixture.
 */
int main(void) { return 0; }
